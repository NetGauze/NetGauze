// Copyright (C) 2024-present The NetGauze Authors.
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

use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, error, info};

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct HttpPublisherEndpoint {
    pub url: String,
    pub writer_id: String,

    // Min number of messages to send in each HTTP request
    pub batch_size: usize,

    /// See [reqwest::ClientBuilder::tcp_keepalive]
    #[serde(skip_serializing_if = "::std::option::Option::is_none")]
    pub tcp_keepalive: Option<Duration>,

    /// See [reqwest::ClientBuilder::pool_idle_timeout]
    #[serde(skip_serializing_if = "::std::option::Option::is_none")]
    pub pool_idle_timeout: Option<Duration>,

    /// See [reqwest::ClientBuilder::pool_max_idle_per_host]
    #[serde(skip_serializing_if = "::std::option::Option::is_none")]
    pub pool_max_idle_per_host: Option<usize>,

    /// See [reqwest::ClientBuilder::timeout]
    #[serde(skip_serializing_if = "::std::option::Option::is_none")]
    pub timeout: Option<Duration>,

    /// See [reqwest::ClientBuilder::connect_timeout]
    #[serde(skip_serializing_if = "::std::option::Option::is_none")]
    pub connect_timeout: Option<Duration>,
}

#[derive(Debug, Clone, strum_macros::Display)]
pub(crate) enum HttpPublisherActorCommand {
    /// Command to shut down the actor.
    Shutdown(mpsc::Sender<String>),
}

/// Message representation to be sent to Feldera
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message<T: Clone> {
    insert {
        ts: String,
        peer_src: String,
        writer_id: String,
        payload: T,
    },
}

struct HttpPublisherActor<T, M: Serialize, F: Fn(Arc<T>, String) -> Vec<M>> {
    /// Human friendly name for logging purposes
    name: String,
    /// Writer ID used to annotate the messages
    writer_id: String,
    /// HTTP client -> if configured correctly it will use HTTP2 keep-alive
    /// method to avoid opening new TCP connection for each message
    client: reqwest::Client,
    /// URL to post messages to
    url: String,
    /// Min number of messages to send in each HTTP request
    batch_size: usize,
    /// Function pointer to a function that converts the collected messages of
    /// type `T` to a Feldera message `Message<O>`
    converter: F,
    msg_recv: async_channel::Receiver<Arc<T>>,
    cmd_recv: mpsc::Receiver<HttpPublisherActorCommand>,
    buf: Vec<M>,
}

impl<T, M: Serialize, F: Fn(Arc<T>, String) -> Vec<M>> HttpPublisherActor<T, M, F> {
    fn new(
        name: String,
        client: reqwest::Client,
        config: HttpPublisherEndpoint,
        converter: F,
        msg_recv: async_channel::Receiver<Arc<T>>,
        cmd_recv: mpsc::Receiver<HttpPublisherActorCommand>,
    ) -> Self {
        Self {
            name,
            writer_id: config.writer_id,
            client,
            url: config.url,
            batch_size: config.batch_size,
            converter,
            msg_recv,
            cmd_recv,
            buf: Vec::new(),
        }
    }

    async fn send<O: Serialize>(
        client: &'_ reqwest::Client,
        url: String,
        value: &'_ O,
    ) -> reqwest::Result<()> {
        debug!("Sending new batch");
        client
            .post(url.as_str())
            .json(&value)
            .send()
            .await
            .map(|response| debug!("Batch sent: {response:?}"))
    }

    async fn run(mut self) -> Result<String, reqwest::Error> {
        loop {
            tokio::select! {
                biased;
                 cmd = self.cmd_recv.recv() => {
                    return match cmd {
                        None => {
                            debug!("[{}] Shutting down due to close command stream", self.name);
                            Ok(self.name.clone())
                        }
                        Some(cmd) => {
                            match cmd {
                                HttpPublisherActorCommand::Shutdown(tx) => {
                                    info!("[{}] Received shutdown command, shutting down", self.name);
                                    let _ = tx.send(self.name.clone()).await;
                                    Ok(self.name.clone())
                                }
                            }
                        }
                    }
                }
                msg = self.msg_recv.recv() => {
                    match msg {
                        Ok(msg) => {
                            let msgs = (self.converter)(msg, self.writer_id.clone());
                            self.buf.extend(msgs.into_iter());
                            debug!("[{}] Queued up a message for sending, there are {} messages in the queue", self.name, self.buf.len());
                            if self.buf.len() > self.batch_size {
                                debug!("[{}] Blocking to send {} messages", self.name, self.buf.len());
                                Self::send(&self.client, self.url.clone(), &self.buf).await?;
                                debug!("[{}] messages send {} clearing buffer", self.name, self.buf.len());
                                self.buf.clear();
                            }
                        },
                        Err(err) => {
                            error!("[{}] Shutting down due to error receiving flow packet {err}", self.name);
                            return Ok(self.name)
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum HttpPublisherActorHandleError {
    SendError,
    ReceiveError,
}

impl std::error::Error for HttpPublisherActorHandleError {}
impl std::fmt::Display for HttpPublisherActorHandleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone)]
pub struct HttpPublisherActorHandle {
    name: String,
    cmd_tx: mpsc::Sender<HttpPublisherActorCommand>,
}

impl HttpPublisherActorHandle {
    pub const fn name(&self) -> &String {
        &self.name
    }

    fn create_http_client(
        config: &HttpPublisherEndpoint,
    ) -> Result<reqwest::Client, reqwest::Error> {
        let mut builder = reqwest::Client::builder();
        if let Some(timeout) = config.tcp_keepalive {
            builder = builder.timeout(timeout);
        }
        if let Some(pool_idle_timeout) = config.pool_idle_timeout {
            builder = builder.pool_idle_timeout(pool_idle_timeout);
        }
        if let Some(pool_max_idle_per_host) = config.pool_max_idle_per_host {
            builder = builder.pool_max_idle_per_host(pool_max_idle_per_host);
        }
        if let Some(timeout) = config.timeout {
            builder = builder.timeout(timeout);
        }
        if let Some(timeout_secs) = config.connect_timeout {
            builder = builder.connect_timeout(timeout_secs);
        }
        builder.build()
    }

    pub fn new<
        T: Serialize + Send + Sync + 'static,
        O: Serialize + Clone + Send + Sync + 'static,
        F: Fn(Arc<T>, String) -> Vec<Message<O>> + Send + 'static,
    >(
        name: String,
        config: HttpPublisherEndpoint,
        converter: F,
        msg_recv: async_channel::Receiver<Arc<T>>,
    ) -> Result<(JoinHandle<Result<String, reqwest::Error>>, Self), reqwest::Error> {
        let client = HttpPublisherActorHandle::create_http_client(&config)?;
        let (cmd_tx, cmd_rx) = mpsc::channel(100);
        info!("[{}] Starting HTTP publisher", name);
        let actor =
            HttpPublisherActor::new(name.clone(), client, config, converter, msg_recv, cmd_rx);
        let join_handle = tokio::spawn(actor.run());
        Ok((join_handle, Self { name, cmd_tx }))
    }

    pub async fn shutdown(&self) -> Result<String, HttpPublisherActorHandleError> {
        let (tx, mut rx) = mpsc::channel(1);
        self.cmd_tx
            .send(HttpPublisherActorCommand::Shutdown(tx))
            .await
            .map_err(|_| HttpPublisherActorHandleError::SendError)?;
        match rx.recv().await {
            Some(actor_id) => Ok(actor_id),
            None => Err(HttpPublisherActorHandleError::ReceiveError),
        }
    }
}
