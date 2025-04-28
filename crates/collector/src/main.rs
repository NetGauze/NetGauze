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

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use futures::Future;
use netgauze_collector::{
    config::{CollectorConfig, TelemetryConfig},
    init_flow_collection, init_udp_notif_collection,
};
use opentelemetry::global;
use serde_yaml::from_reader;
use std::{env, fs::File, io::BufReader, path::PathBuf, pin::Pin, str::FromStr};
use tracing::{info, Level};

fn init_open_telemetry(
    config: &TelemetryConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    use opentelemetry::global;
    use opentelemetry_otlp::{Protocol, WithExportConfig};
    use opentelemetry_sdk::Resource;

    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .with_endpoint(config.url())
        .with_protocol(Protocol::Grpc)
        .with_timeout(config.exporter_timeout)
        .build()?;

    let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(exporter)
        .with_interval(config.reader_interval)
        .build();

    let resource = Resource::builder().with_service_name("NetGauze").build();
    let provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(resource)
        .build();

    global::set_meter_provider(provider);
    Ok(())
}

fn init_tracing(level: &'_ str) {
    // Very simple setup at the moment to validate the instrumentation in the code
    // is working in the future that should be configured automatically based on
    // configuration options
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(Level::from_str(level).expect("invalid logging level"))
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        return Err(format!("Usage: {} <config-file>", args[0]).into());
    }
    let config_file = PathBuf::from(&args[1]);
    let file = File::open(&config_file)?;
    let reader = BufReader::new(file);
    let config: CollectorConfig = match from_reader(reader) {
        Ok(config) => config,
        Err(err) => {
            return Err(format!("Parsing config file failed: {err}").into());
        }
    };
    init_tracing(&config.logging.level);

    let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
    // If num of threads is not configured then the default use all CPU cores is
    // used
    if let Some(num_threads) = config.runtime.threads {
        runtime_builder.worker_threads(num_threads);
    }
    runtime_builder.enable_all();
    let runtime = runtime_builder.build()?;

    runtime.block_on(async move {
        init_open_telemetry(&config.telemetry)?;
        let meter = global::meter_provider().meter("netgauze");
        let mut handles = vec![];

        if let Some(flow_config) = config.flow {
            let flow_handle: Pin<Box<dyn Future<Output = Result<(), anyhow::Error>>>> =
                Box::pin(init_flow_collection(flow_config, meter.clone()));
            handles.push(flow_handle);
        }

        if let Some(udp_notif_config) = config.udp_notif {
            let udp_notif_handle: Pin<Box<dyn Future<Output = Result<(), anyhow::Error>>>> =
                Box::pin(init_udp_notif_collection(udp_notif_config, meter.clone()));
            handles.push(udp_notif_handle);
        }

        // // Purge old entries periodically
        // let purge_timeout = config.flow.template_cache_purge_timeout;
        // let handler_clone = handler.clone();
        // let cleanup_task = tokio::spawn(async move {
        //     if let Some(duration) = purge_timeout {
        //         let mut interval = tokio::time::interval(duration);
        //         loop {
        //             interval.tick().await;
        //             handler_clone
        //                 .purge_unused_peers(Duration::from_secs(360))
        //                 .await
        //                 .expect("failed purge unused_peers");
        //         }
        //     }
        // });

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Termination signal received, gracefully shutting down actors");
            }
            _ = futures::future::try_join_all(handles) => {
                info!("collection and publishing is terminated, shutting down the collector");
            }
        }

        Ok::<(), Box<dyn std::error::Error + Send + Sync + 'static>>(())
    })
}
