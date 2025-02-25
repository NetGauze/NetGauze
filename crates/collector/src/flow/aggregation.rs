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

//! Aggregation actor for flow records
//!
//! TODO: Currently this is placeholder that doesn't do much

use netgauze_analytics::aggregation::Window;
use netgauze_flow_pkt::FlatFlowInfo;
use netgauze_flow_service::FlowRequest;
use std::{net::SocketAddr, sync::Arc};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{error, info};

#[derive(Debug, Clone, Copy)]
pub enum AggregationCommand {
    Shutdown,
}

#[derive(Debug)]
struct AggregationActor {
    cmd_recv: mpsc::Receiver<AggregationCommand>,
    rx: async_channel::Receiver<Arc<FlowRequest>>,
    tx: async_channel::Sender<(Window, (SocketAddr, FlatFlowInfo))>,
}

impl AggregationActor {
    fn new(
        cmd_recv: mpsc::Receiver<AggregationCommand>,
        rx: async_channel::Receiver<Arc<FlowRequest>>,
        tx: async_channel::Sender<(Window, (SocketAddr, FlatFlowInfo))>,
    ) -> Self {
        Self { cmd_recv, rx, tx }
    }

    async fn run(mut self) -> anyhow::Result<String> {
        loop {
            tokio::select! {
                biased;
                cmd_recv = self.cmd_recv.recv() => {
                    match cmd_recv {
                        Some(AggregationCommand::Shutdown) => {
                            info!("Received shutdown command, shutting down AggregationActor");
                        }
                        None => {
                            info!("Command channel closed, shutting down AggregationActor");
                        }
                    }
                    return Ok("AggregationTerminated".to_string());
                }
                flow = self.rx.recv() => {
                    match flow {
                        Ok(flow) => {
                            let (peer, flow) = flow.as_ref().clone();
                            let flat_flows = flow.flatten();
                            // TODO: call aggregation
                            let ts = chrono::Utc::now();
                            let window = (ts, ts);
                            for flat in flat_flows {
                                if let Err(err) = self.tx.send((window, (peer, flat))).await {
                                    error!("Error sending flat aggregated flow: {err:?}");
                                }
                            }
                        }
                        Err(err) => {
                            error!("Shutting down aggregation actor due to error receiving flow: {err:?}");
                            return Err(anyhow::Error::new(err));
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum AggregationActorHandleError {
    SendError,
}

#[derive(Debug)]
pub struct AggregationActorHandle {
    cmd_send: mpsc::Sender<AggregationCommand>,
    rx: async_channel::Receiver<(Window, (SocketAddr, FlatFlowInfo))>,
}

impl AggregationActorHandle {
    pub fn new(
        buffer_size: usize,
        flow_rx: async_channel::Receiver<Arc<FlowRequest>>,
    ) -> (JoinHandle<anyhow::Result<String>>, Self) {
        let (cmd_send, cmd_recv) = mpsc::channel(10);
        let (tx, rx) = async_channel::bounded(buffer_size);
        let actor = AggregationActor::new(cmd_recv, flow_rx, tx);
        let join_handle = tokio::spawn(actor.run());
        let handle = Self { cmd_send, rx };
        (join_handle, handle)
    }

    pub async fn shutdown(&self) -> Result<(), AggregationActorHandleError> {
        self.cmd_send
            .send(AggregationCommand::Shutdown)
            .await
            .map_err(|_| AggregationActorHandleError::SendError)
    }

    pub fn subscribe(&self) -> async_channel::Receiver<(Window, (SocketAddr, FlatFlowInfo))> {
        self.rx.clone()
    }
}
