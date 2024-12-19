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

use futures_util::{stream::FuturesOrdered, StreamExt};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, error, info};

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct HttpPublisherEndpoint {
    pub url: String,
    pub writer_id: String,

    /// See [reqwest::ClientBuilder::pool_idle_timeout]
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

struct HttpPublisherActor<T, O: std::clone::Clone, F: Fn(Arc<T>, String) -> Message<O>> {
    /// Human friendly name for logging purposes
    name: String,
    /// Writer ID used to annotate the messages
    writer_id: String,
    /// HTTP client -> if configured correctly it will use HTTP2 keep-alive
    /// method to avoid opening new TCP connection for each message
    client: reqwest::Client,
    /// URL to post messages to
    url: String,
    /// Function pointer to a function that converts the collected messages of
    /// type `T` to a Feldera message `Message<O>`
    converter: F,
    msg_recv: async_channel::Receiver<Arc<T>>,
    cmd_recv: mpsc::Receiver<HttpPublisherActorCommand>,
    buf: Vec<Message<O>>,
}

impl<T: Serialize, O: Serialize + std::clone::Clone, F: Fn(Arc<T>, String) -> Message<O>>
    HttpPublisherActor<T, O, F>
{
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
            client,
            url: config.url,
            writer_id: config.writer_id,
            converter,
            msg_recv,
            cmd_recv,
            buf: Vec::new(),
        }
    }

    async fn send<M: Serialize>(client: &Client, url: String, value: M) -> reqwest::Result<()> {
        debug!("Sending new batch");
        client
            .post(url.as_str())
            .json(&value)
            .send()
            .await
            .map(|_| {debug!("Batch sent")})
    }

    async fn run(mut self) -> Result<String, reqwest::Error> {
        let mut futures = FuturesOrdered::new();
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
                            let msg = (self.converter)(msg, self.writer_id.clone());
                            if futures.len() > 10 {
                               // while futures.len() > 0 {
                                debug!("[{}] clearing futures {}", self.name, futures.len());
                                    futures.next().await;
                                debug!("[{}] futures cleared {}", self.name, futures.len());
                                //}
                            }
                            self.buf.push(msg);
                            debug!("[{}] Queued up a message for sending, there are {} messages in flights", self.name, futures.len());
                            if self.buf.len() > 100 {
                                futures.push_back(Self::send(&self.client, self.url.clone(), self.buf.clone()));
                                self.buf.clear();
                            }
                        },
                        Err(err) => {
                            error!("[{}] Shutting down due to error receiving flow packet {err}", self.name);
                            return Ok(self.name)
                        }
                    }
                }
                Some(ret) = futures.next() => {

                    debug!("[{}] message sent: {ret:?}, there are {} messages in flights", self.name, futures.len());
                    //}
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
        O: Serialize + std::clone::Clone + Send + Sync + 'static,
        F: Fn(Arc<T>, String) -> Message<O> + Send + 'static,
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
