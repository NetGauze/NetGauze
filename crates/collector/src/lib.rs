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

use crate::{
    config::{FlowConfig, PublisherEndpoint},
    http::{HttpPublisherActorHandle, Message},
};
use futures_util::{stream::FuturesUnordered, StreamExt};
use netgauze_flow_service::{flow_supervisor::FlowCollectorsSupervisorActorHandle, FlowRequest};
use std::sync::Arc;
use tracing::{info, warn};

pub mod config;
pub mod http;

pub async fn init_flow_collection(flow_config: FlowConfig) -> anyhow::Result<()> {
    let supervisor_config = flow_config.supervisor_config();
    let (supervisor_join_handle, supervisor_handle) =
        FlowCollectorsSupervisorActorHandle::new(supervisor_config).await;
    let mut http_handlers = Vec::new();
    let mut http_join_set = FuturesUnordered::new();
    for (group_name, publisher_config) in flow_config.publishers {
        info!("Starting publishers group '{group_name}'");
        let (flow_recv, _) = supervisor_handle
            .subscribe(publisher_config.buffer_size)
            .await?;
        for (endpoint_name, endpoint) in publisher_config.endpoints {
            info!("Creating publisher '{endpoint_name}'");
            match &endpoint {
                PublisherEndpoint::Http(config) => {
                    let (http_join, http_handler) = HttpPublisherActorHandle::new(
                        endpoint_name.clone(),
                        config.clone(),
                        |x: Arc<FlowRequest>, writer_id: String| Message::insert {
                            ts: format!("{}", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S")),
                            peer_src: format!("{}", x.0.ip()),
                            writer_id,
                            payload: x.1.clone(),
                        },
                        flow_recv.clone(),
                    )?;
                    http_join_set.push(http_join);
                    http_handlers.push(http_handler);
                }
            }
        }
    }
    let ret = tokio::select! {
        _ = supervisor_join_handle => {
            info!("Flow supervisor exited, shutting down all publishers");
           for handler in http_handlers {
                let shutdown_result = tokio::time::timeout(std::time::Duration::from_secs(1), handler.shutdown()).await;
                if shutdown_result.is_err() {
                    warn!("Timeout shutting down flow http publisher {}", handler.name())
                }
                if let Ok(Err(err)) = shutdown_result {
                    warn!("Error in shutting down flow http publisher {}: {err}", handler.name())
                }
            }
            Ok(())
        },
        _ = http_join_set.next() => {
            warn!("Flow http publisher exited, shutting down flow collection and publishers");
            let _ = tokio::time::timeout(std::time::Duration::from_secs(1), supervisor_handle.shutdown()).await;
            for handler in http_handlers {
                let shutdown_result = tokio::time::timeout(std::time::Duration::from_secs(1), handler.shutdown()).await;
                if shutdown_result.is_err() {
                    warn!("Timeout shutting down flow http publisher {}", handler.name())
                }
                if let Ok(Err(err)) = shutdown_result {
                    warn!("Error in shutting down flow http publisher {}: {err}", handler.name())
                }
            }
            Ok(())
        }
    };
    ret
}
