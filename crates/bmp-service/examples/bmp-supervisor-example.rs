// Copyright (C) 2026-present The NetGauze Authors.
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

//! # BMP Supervisor Example
//!
//! This example demonstrates how to use the `BmpSupervisor` to manage multiple
//! BMP actors.
//!
//! It performs the following tasks:
//! 1. **Configures the Supervisor**: Sets up a configuration to listen on port
//!    1790 (leveraging SO_REUSEPORT) with 2 actors.
//! 2. **Starts the Supervisor**: Launches the supervisor which spawns the
//!    configured actors.
//! 3. **Subscribes to Messages**: Subscribes to the supervisor to receive
//!    aggregated BMP messages from all actors.
//! 4. **Logs Messages**: Logs received BMP messages as JSON.
//! 5. **Monitors Peers**: Periodically logs the status and connected peers of
//!    all managed actors.

use netgauze_bmp_service::supervisor::{BindingAddress, BmpSupervisorHandle, SupervisorConfig};
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use tracing::{error, info};

fn init_tracing() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::{EnvFilter, fmt};

    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .expect("Failed to set default tracing env filter");

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer())
        .try_init()
        .expect("Failed to register tracing subscriber");

    Ok(())
}

pub fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    // Number of Tokio threads to run
    let num_worker_threads = std::env::var("NUM_WORKERS")
        .unwrap_or("4".to_string())
        .parse()?;
    let config = SupervisorConfig {
        binding_addresses: vec![BindingAddress {
            socket_addr: SocketAddr::from_str("[::]:1790").unwrap(),
            num_workers: 2, // 2 actors (2 TCP accept loops)
            interface: None,
        }],
        cmd_buffer_size: 100,
        subscriber_timeout: Duration::from_secs(1),
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(num_worker_threads)
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        init_tracing()?;
        let (supervisor_join_handle, handler) =
            BmpSupervisorHandle::new(config, opentelemetry::global::meter("example"))?;

        let (pkt_rx, subscriptions) = handler.subscribe(100).await?;
        for subscription in &subscriptions {
            info!(subscription = ?subscription, "Subscribed");
        }

        // Use local_addresses() to see where all workers are listening
        match handler.local_addresses().await {
            Ok(addresses) => {
                for (actor_id, addr) in addresses {
                    info!(actor_id = %actor_id, listening_on = %addr, "Actor listening",);
                }
            }
            Err(e) => error!(error = %e, "Failed to get local addresses"),
        }

        // Spawn a task to print received BMP messages
        tokio::spawn(async move {
            while let Ok(pkt) = pkt_rx.recv().await {
                // pkt: Arc<BmpRequest> where BmpRequest = (AddrInfo, BmpMessage)
                let (addrinfo, bmp_msg) = &*pkt;

                // try to produce a JSON representation of the BMP message, fall back to debug
                // if serialization fails
                let json_msg = match serde_json::to_string(&bmp_msg) {
                    Ok(s) => s,
                    Err(e) => {
                        error!(error = %e, "Failed to serialize BMP message (should never happen)");
                        format!("{:?}", bmp_msg)
                    }
                };

                // use tracing structured fields and print AddrInfo inside brackets plus the
                // JSON message
                tracing::info!(
                    local_addr = %addrinfo.local_socket(),
                    peer_addr = %addrinfo.remote_socket(),
                    "Received BMP message: {}", json_msg);
            }
        });

        // Periodically log connected peers (for demonstration)
        let handler_clone = handler.clone();
        let status_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                match handler_clone.get_connected_peers().await {
                    Ok(results) => {
                        for (actor_id, peers) in results {
                            info!(
                                actor_id = %actor_id,
                                peers_count = %peers.len(),
                                peers = ?peers,
                                "Actor connected peers status"
                            );
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to get connected peers");
                    }
                }
            }
        });

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Termination signal received, gracefully shutting down actors");
                status_task.abort();
                let _ = handler.shutdown().await;
            }
            _ = supervisor_join_handle => {
                error!("Supervisor shutdown unexpectedly");
                status_task.abort();
            }
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync + 'static>>(())
    })
}
