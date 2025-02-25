// Copyright (C) 2025-present The NetGauze Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use rdkafka::{
    config::ClientConfig,
    error::KafkaError,
    producer::{FutureProducer, FutureRecord, Producer},
    util::Timeout,
};
use schema_registry_converter::{
    async_impl::{avro::AvroEncoder, schema_registry::SrSettings},
    error::SRCError,
    schema_registry_common::{SchemaType, SubjectNameStrategy, SuppliedSchema},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, marker::PhantomData, time::Duration};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{error, info, warn};

pub trait AvroConverter<T, E: std::error::Error> {
    fn get_avro_schema(&self) -> String;
    fn get_avro_value(&self, input: T) -> Result<apache_avro::types::Value, E>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KafkaConfig<C> {
    /// Output topic
    pub topic: String,
    /// Key/Value producer configs a defined in librdkafka
    pub producer_config: HashMap<String, String>,
    pub schema_registry_url: String,
    pub writer_id: String,
    pub avro_converter: C,
}

#[derive(Debug)]
pub enum KafkaAvroPublisherActorError {
    KafkaError(KafkaError),
    AvroError(apache_avro::Error),
    SrcError(SRCError),
    TransformationError(String),
    ReceiveErr,
}

impl std::fmt::Display for KafkaAvroPublisherActorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KafkaError(e) => write!(f, "Kafka error: {e}"),
            Self::AvroError(e) => write!(f, "Avro error: {e}"),
            Self::SrcError(e) => write!(f, "Source error: {e}"),
            Self::TransformationError(e) => write!(f, "Transformation error: {e}"),
            Self::ReceiveErr => write!(f, "Error receiving messages from upstream producer"),
        }
    }
}

impl std::error::Error for KafkaAvroPublisherActorError {}

impl From<KafkaError> for KafkaAvroPublisherActorError {
    fn from(e: KafkaError) -> Self {
        Self::KafkaError(e)
    }
}

impl From<apache_avro::Error> for KafkaAvroPublisherActorError {
    fn from(e: apache_avro::Error) -> Self {
        Self::AvroError(e)
    }
}

impl From<SRCError> for KafkaAvroPublisherActorError {
    fn from(e: SRCError) -> Self {
        Self::SrcError(e)
    }
}

pub struct KafkaAvroPublisherActor<'a, T, E: std::error::Error, C: AvroConverter<T, E>> {
    cmd_rx: mpsc::Receiver<KafkaAvroPublisherActorCommand>,

    /// Configured kafka options
    config: KafkaConfig<C>,

    /// Schema used for AVRO records by this producer
    supplied_schema: SuppliedSchema,

    //// librdkafka producer
    producer: FutureProducer,

    /// Encoding to avro
    avro_encoder: AvroEncoder<'a>,

    msg_recv: async_channel::Receiver<T>,

    /// Rust magic for holding types and T, E
    pub _phantom: PhantomData<(T, E)>,
}

impl<T, E, C> KafkaAvroPublisherActor<'_, T, E, C>
where
    E: std::error::Error,
    C: AvroConverter<T, E>,
    KafkaAvroPublisherActorError: From<E>,
{
    pub fn from_config(
        cmd_rx: mpsc::Receiver<KafkaAvroPublisherActorCommand>,
        config: KafkaConfig<C>,
        msg_recv: async_channel::Receiver<T>,
    ) -> Result<Self, KafkaAvroPublisherActorError> {
        let mut producer_config = ClientConfig::new();
        for (k, v) in &config.producer_config {
            producer_config.set(k.as_str(), v.as_str());
        }
        let producer: FutureProducer = match producer_config.create() {
            Ok(p) => p,
            Err(err) => {
                error!("Failed to create Kafka producer: {err}");
                return Err(err)?;
            }
        };
        let sr_settings = SrSettings::new(config.schema_registry_url.clone());
        let avro_encoder = AvroEncoder::new(sr_settings.clone());
        let schema_str = config.avro_converter.get_avro_schema();
        let parse_schema = match apache_avro::schema::Schema::parse_str(&schema_str) {
            Ok(schema) => schema,
            Err(err) => {
                error!("Error parsing schema `{err}`, schema string is: `{schema_str}`");
                return Err(err)?;
            }
        };
        let supplied_schema = SuppliedSchema {
            name: parse_schema.name().map(|x| x.to_string()),
            schema_type: SchemaType::Avro,
            schema: schema_str,
            references: vec![],
        };

        info!(
            "Starting Kafka AVRO publisher to topic: `{}` with schema: `{}`",
            config.topic,
            parse_schema.canonical_form()
        );
        Ok(Self {
            cmd_rx,
            config,
            supplied_schema,
            producer,
            avro_encoder,
            msg_recv,
            _phantom: PhantomData,
        })
    }

    pub async fn send(&mut self, input: T) -> Result<(), KafkaAvroPublisherActorError> {
        let avro_value = match self.config.avro_converter.get_avro_value(input) {
            Ok(avro_value) => avro_value,
            Err(err) => {
                error!("Error getting avro value: {err}");
                return Err(err)?;
            }
        };
        // TODO: make subject name strategy configurable
        let encoded = match self
            .avro_encoder
            .encode_value(
                avro_value,
                &SubjectNameStrategy::TopicRecordNameStrategyWithSchema(
                    self.config.topic.clone(),
                    self.supplied_schema.clone(),
                ),
            )
            .await
        {
            Ok(result) => result,
            Err(err) => {
                error!("Error encoding avro value: {err}");
                return Err(err)?;
            }
        };

        let fr: FutureRecord<'_, Vec<u8>, Vec<u8>> = FutureRecord {
            topic: self.config.topic.as_str(),
            partition: None,
            payload: Some(&encoded),
            key: None,
            timestamp: None,
            headers: None,
        };
        if let Err((err, _)) = self
            .producer
            .send(fr, Timeout::After(Duration::from_secs(1)))
            .await
        {
            error!("Error sending avro value: {err}");
            return Err(KafkaAvroPublisherActorError::KafkaError(err));
        };
        Ok(())
    }

    async fn run(mut self) -> anyhow::Result<String> {
        loop {
            tokio::select! {
                biased;
                cmd = self.cmd_rx.recv() => {
                    return match cmd {
                        Some(KafkaAvroPublisherActorCommand::Shutdown) => {
                            info!("Received shutdown signal");
                            if let Err(err) = self.producer.flush(Duration::from_millis(1000)) {
                                error!("Failed flush messages before shutting down: {err}");
                            }
                            Ok("Shutting down".to_string())
                        }
                        None => {
                            warn!("KafkaAvroPublisher terminated due to command channel closing");
                            Ok("KafkaAvroPublisher shutdown successfully".to_string())
                        }
                    }
                }
                msg = self.msg_recv.recv() =>{
                    match msg{
                        Ok(msg) => {
                            if let Err(err) = self.send(msg).await {
                                error!("Error sending message to Kafka: {err}");
                            }
                        }
                        Err(_) => {
                            Err(KafkaAvroPublisherActorError::ReceiveErr)?
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum KafkaAvroPublisherActorHandleError {
    SendError,
}

#[derive(Debug, Clone, Copy)]
pub enum KafkaAvroPublisherActorCommand {
    Shutdown,
}

#[derive(Debug)]
pub struct KafkaAvroPublisherActorHandle<T, E, C>
where
    E: std::error::Error,
    C: AvroConverter<T, E>,
{
    cmd_tx: mpsc::Sender<KafkaAvroPublisherActorCommand>,
    _phantom: PhantomData<(T, E, C)>,
}

impl<T, E, C> KafkaAvroPublisherActorHandle<T, E, C>
where
    T: Send + 'static,
    E: std::error::Error + Send + 'static,
    C: AvroConverter<T, E> + Send + 'static,
    KafkaAvroPublisherActorError: From<E>,
{
    pub fn from_config(
        config: KafkaConfig<C>,
        msg_recv: async_channel::Receiver<T>,
    ) -> Result<(JoinHandle<anyhow::Result<String>>, Self), KafkaAvroPublisherActorError> {
        let (cmd_tx, cmd_rx) = mpsc::channel(10);
        let actor = KafkaAvroPublisherActor::from_config(cmd_rx, config, msg_recv)?;
        let join_handle = tokio::spawn(actor.run());
        let handle = Self {
            cmd_tx,
            _phantom: PhantomData,
        };
        Ok((join_handle, handle))
    }

    pub async fn shutdown(self) -> Result<(), KafkaAvroPublisherActorHandleError> {
        self.cmd_tx
            .send(KafkaAvroPublisherActorCommand::Shutdown)
            .await
            .map_err(|_| KafkaAvroPublisherActorHandleError::SendError)
    }
}
