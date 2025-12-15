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

use anyhow::anyhow;
use futures::Future;
use netgauze_collector::config::{CollectorConfig, TelemetryConfig};
use netgauze_collector::{init_flow_collection, init_udp_notif_collection};
use opentelemetry::global;
use serde_yaml::from_reader;
use shadow_rs::shadow;
use std::env;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use tracing::{Level, info};

shadow!(build);

fn init_tracing(level: &'_ str) {
    // Very simple setup at the moment to validate the instrumentation in the code
    // is working in the future that should be configured automatically based on
    // configuration options
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(Level::from_str(level).expect("invalid logging level"))
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
}

fn log_info() {
    info!(
        r#"

  __/\\\\\_____/\\\__________________________________/\\\\\\\\\\\\___________________________________________________________
  _\/\\\\\\___\/\\\________________________________/\\\//////////____________________________________________________________
   _\/\\\/\\\__\/\\\____________________/\\\_______/\\\_______________________________________________________________________
    _\/\\\//\\\_\/\\\_____/\\\\\\\\___/\\\\\\\\\\\_\/\\\____/\\\\\\\__/\\\\\\\\\_____/\\\____/\\\__/\\\\\\\\\\\_____/\\\\\\\\__
     _\/\\\\//\\\\/\\\___/\\\/////\\\_\////\\\////__\/\\\___\/////\\\_\////////\\\___\/\\\___\/\\\_\///////\\\/____/\\\/////\\\_
      _\/\\\_\//\\\/\\\__/\\\\\\\\\\\_____\/\\\______\/\\\_______\/\\\___/\\\\\\\\\\__\/\\\___\/\\\______/\\\/_____/\\\\\\\\\\\__
       _\/\\\__\//\\\\\\_\//\\///////______\/\\\_/\\__\/\\\_______\/\\\__/\\\/////\\\__\/\\\___\/\\\____/\\\/______\//\\///////___
        _\/\\\___\//\\\\\__\//\\\\\\\\\\____\//\\\\\___\//\\\\\\\\\\\\/__\//\\\\\\\\/\\_\//\\\\\\\\\___/\\\\\\\\\\\__\//\\\\\\\\\\_
         _\///_____\/////____\//////////______\/////_____\////////////_____\////////\//___\/////////___\///////////____\//////////__

  "#
    );
    info!("==================== Git/Source Control Information ====================");
    info!("         Package Version:    {}", build::PKG_VERSION);
    info!("         Commit Hash:        {}", build::COMMIT_HASH);
    info!("         Commit Date:        {}", build::COMMIT_DATE);
    info!("         Branch:             {}", build::BRANCH);
    info!("         Tag:                {}", build::TAG);

    info!("");
    info!("======================== Build Information =============================");
    info!("         Build Time:         {}", build::BUILD_TIME);
    info!("         Rust Build Channel: {}", build::BUILD_RUST_CHANNEL);
    info!("         Operating System:   {}", build::BUILD_OS);
    info!("         Rust Channel:       {}", build::RUST_CHANNEL);
    info!("         Rust Version:       {}", build::RUST_VERSION);
    info!("         Cargo Version:      {}", build::CARGO_VERSION);
    info!("========================================================================");
    info!("");
}

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

    let resource = Resource::builder()
        .with_service_name("NetGauze")
        .with_attributes([opentelemetry::KeyValue::new("id", config.id.clone())])
        .build();

    let provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(resource)
        .build();

    global::set_meter_provider(provider);
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        return Err(anyhow!("Usage: {} <config-file>", args[0]));
    }
    let config_file = PathBuf::from(&args[1]);
    let file = File::open(&config_file)?;
    let reader = BufReader::new(file);
    let config: CollectorConfig = match from_reader(reader) {
        Ok(config) => config,
        Err(err) => {
            return Err(anyhow!("Parsing config file failed: {err}"));
        }
    };

    init_tracing(&config.logging.level);
    log_info();

    let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
    // If num of threads is not configured then the default use all CPU cores is
    // used
    if let Some(num_threads) = config.runtime.threads {
        runtime_builder.worker_threads(num_threads);
    }
    runtime_builder.enable_all();
    let runtime = runtime_builder.build()?;

    runtime.block_on(async move {
        init_open_telemetry(&config.telemetry).map_err(|err| anyhow!(err))?;
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
                Ok(())
            }
            join_ret = futures::future::try_join_all(handles) => {
                info!("collection and publishing is terminated, shutting down the collector");
                match join_ret {
                    Ok(_) => {
                        Ok(())
                    }
                    Err(err) => {
                        Err(anyhow!(err))
                    },
                }
            }
        }
    })
}
