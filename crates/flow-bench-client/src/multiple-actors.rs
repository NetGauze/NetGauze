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

use netgauze_flow_service::flow_supervisor::{
    BindingAddress, FlowCollectorsSupervisorActorHandle, SupervisorConfig,
};
use std::{
    net::SocketAddr,
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tracing::info;

fn init_tracing() {
    // Very simple setup at the moment to validate the instrumentation in the code
    // is working in the future that should be configured automatically based on
    // configuration options
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
}

pub fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    // Number of Tokio threads to run
    let num_worker_threads = std::env::var("NUM_WORKERS")
        .unwrap_or("8".to_string())
        .parse()?;
    let config = SupervisorConfig {
        binding_addresses: vec![BindingAddress {
            socket_addr: SocketAddr::from_str("0.0.0.0:9999").unwrap(),
            num_workers: 4,
        }],
        cmd_buffer_size: 1000,
        subscriber_timeout: Duration::from_millis(100),
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(num_worker_threads)
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        init_tracing();
        let (supervisor_join_handle, handler) =
            FlowCollectorsSupervisorActorHandle::new(config).await;
        let (pkt_rx, subscriptions) = handler.subscribe(1000).await?;
        for subscription in &subscriptions {
            info!("Subscribed to {:?}", subscription);
        }

        let recv_counter = Arc::new(AtomicU64::new(0));
        let recv_counter_total = Arc::new(AtomicU64::new(0));
        for _i in 0..4 {
            let rec_counter_clone = recv_counter.clone();
            let recv_counter_total_clone = recv_counter_total.clone();
            let pkt_rx_clone = pkt_rx.clone();
            tokio::spawn(async move {
                while let Ok(_pkt) = pkt_rx_clone.recv().await {
                    rec_counter_clone.fetch_add(1, Ordering::Relaxed);
                    recv_counter_total_clone.fetch_add(1, Ordering::Relaxed);
                }
            });
        }

        let mut interval = tokio::time::interval(Duration::from_secs(1));
        tokio::spawn(async move {
            loop {
                interval.tick().await;
                let recv_count = recv_counter.swap(0, Ordering::Relaxed);
                let total = recv_counter_total.load(Ordering::Relaxed);
                info!(
                    "received: {}/sec with total: {} messages",
                    recv_count, total
                );
            }
        });

        // Purge old entries periodically
        let forever = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                handler
                    .purge_unused_peers(Duration::from_secs(6000))
                    .await
                    .expect("failed purge unused_peers");
            }
        });
        tokio::join!(supervisor_join_handle).0?;
        forever.abort();
        Ok::<(), Box<dyn std::error::Error + Send + Sync + 'static>>(())
    })
}
