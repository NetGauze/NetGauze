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

//! # BMP Actor Example
//!
//! This example demonstrates how to use the `BmpActor` directly to collect BMP
//! messages.
//!
//! It performs the following tasks:
//! 1. **Starts a `BmpActor`**: Listens for incoming BMP connections on port
//!    1792.
//! 2. **Subscribes to Messages**: Subscribes to the actor to receive received
//!    BMP messages.
//! 3. **Logs Messages**: formatting them as JSON.
//! 4. **Monitors Peers**: Periodically logs the list of connected peers.
//! 5. **REST API**: Starts a simple HTTP server (default port 31313) exposing
//!    management endpoints.
//!
//! ## REST API
//!
//! - `POST /api/disconnect`: Disconnects a specific peer.
//!     - Body: `{"peer_addr": "[peer_ip]:port"}`
//!
//! Example:
//!
//! curl -X POST http://127.0.0.1:31313/api/disconnect \
//!   -H "Content-Type: application/json" \
//!   -d '{"peer_addr": "[2001:db8::1]:12345"}'

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use netgauze_bmp_service::actor::BmpActorHandle;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
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

#[derive(Debug, Deserialize)]
struct DisconnectRequest {
    peer_addr: SocketAddr,
}

#[derive(Debug, Serialize)]
struct DisconnectResponse {
    success: bool,
    message: String,
}

async fn disconnect_peer_handler(
    State(handler): State<BmpActorHandle>,
    Json(payload): Json<DisconnectRequest>,
) -> Result<Json<DisconnectResponse>, StatusCode> {
    let peer_addr = payload.peer_addr;

    match handler.disconnect_peer(peer_addr).await {
        Ok(true) => Ok(Json(DisconnectResponse {
            success: true,
            message: format!("Successfully disconnected peer {peer_addr}"),
        })),
        Ok(false) => Ok(Json(DisconnectResponse {
            success: false,
            message: format!("Peer {peer_addr} not found"),
        })),
        Err(e) => {
            tracing::error!(error = %e, "Error disconnecting peer");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    // Number of Tokio threads to run
    let num_worker_threads = std::env::var("NUM_WORKERS")
        .unwrap_or("4".to_string())
        .parse()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(num_worker_threads)
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        init_tracing()?;
        let socket_addr = "[::]:1792".parse().unwrap();
        let actor_id = 0;
        let cmd_buffer_size = 10;
        let (join_handle, handler) = BmpActorHandle::new(
            actor_id,
            socket_addr,
            None,
            cmd_buffer_size,
            Duration::from_millis(500),
            either::Either::Left(opentelemetry::global::meter("example")),
        )?;

        let (pkt_rx, subscription) = handler.subscribe(100).await?;
        info!(subscription = ?subscription, "Subscribed");

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
                        format!("{bmp_msg:?}")
                    }
                };

                // use tracing structured fields and print AddrInfo inside brackets plus the
                // JSON message
                tracing::info!(
                    local_addr = %addrinfo.local_socket(),
                    peer_addr = %addrinfo.remote_socket(),
                    "Received BMP message: {json_msg}");
            }
        });

        // Periodically log connected peers (for demonstration)
        let handler_clone = handler.clone();
        let status_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                match handler_clone.get_connected_peers().await {
                    Ok((actor_id, peers)) => {
                        info!(
                            actor_id,
                            peers_count = peers.len(),
                            peers = ?peers,
                            "Actor connected peers status"
                        );
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to get connected peers");
                    }
                }
            }
        });

        // Start simple REST API server
        let app = Router::new()
            .route("/api/disconnect", post(disconnect_peer_handler))
            .with_state(handler.clone());

        let api_addr = "127.0.0.1:31313".parse::<SocketAddr>().unwrap();
        info!(api_addr = %api_addr, "Starting REST API");

        let api_task = tokio::spawn(async move {
            axum::serve(tokio::net::TcpListener::bind(api_addr).await.unwrap(), app)
                .await
                .unwrap();
        });

        // Wait for the actor to finish
        let result = join_handle.await?;
        status_task.abort();
        api_task.abort();
        result?;

        Ok::<(), Box<dyn std::error::Error + Send + Sync + 'static>>(())
    })
}
