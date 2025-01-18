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

use netgauze_udp_notif_service::supervisor::{SupervisorConfig, UdpNotifSupervisorHandle};
use std::time::Duration;
use tracing::{error, info};

fn init_tracing() {
    // Very simple setup at the moment to validate the instrumentation in the code
    // is working in the future that should be configured automatically based on
    // configuration options
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
}

pub fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    // Number of Tokio threads to run
    let num_worker_threads = std::env::var("NUM_WORKERS")
        .unwrap_or("4".to_string())
        .parse()?;
    let config = SupervisorConfig::default();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(num_worker_threads)
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        init_tracing();
        let (supervisor_join_handle, handler) = UdpNotifSupervisorHandle::new(config).await;
        let (pkt_rx, subscriptions) = handler.subscribe(10).await?;
        for subscription in &subscriptions {
            info!("subscribed to {:?}", subscription);
        }
        tokio::spawn(async move {
            while let Ok(pkt) = pkt_rx.recv().await {
                info!("received packet: {:?}", pkt);
            }
        });

        // Purge old entries periodically
        let handler_clone = handler.clone();
        let cleanup_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                handler_clone
                    .purge_unused_peers(Duration::from_secs(60))
                    .await
                    .expect("failed to purge unused peers");
            }
        });

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("termination signal received, gracefully shutting down actors");
                cleanup_task.abort();
                let _ = handler.shutdown().await;
            }
            _ = supervisor_join_handle => {
                error!("unexpected supervisor shutdown");
                cleanup_task.abort();
            }
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync + 'static>>(())
    })
}
