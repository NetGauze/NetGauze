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
use clap::Parser;
use futures::Future;
use netgauze_collector::config::{CollectorConfig, TelemetryConfig};
use netgauze_collector::{init_bmp_collection, init_flow_collection, init_udp_notif_collection};
use opentelemetry::global;
use serde_yaml::from_reader;
use shadow_rs::shadow;
use std::env;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Instant;
use tracing::info;

shadow!(build);

fn init_tracing(level: &'_ str, use_ansi: bool) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::{EnvFilter, fmt};

    // default to configured level from config file
    // override via RUST_LOG env var at runtime
    let rust_log = env::var("RUST_LOG").unwrap_or_default();
    let env_filter = if !rust_log.is_empty() {
        EnvFilter::builder().parse(&rust_log).expect(
            "Invalid RUST_LOG environment variable. Use valid filter directives like 'debug' or 'netgauze_collector=trace'",
        )
    } else {
        EnvFilter::builder().parse(level).expect(
            "Invalid log level in config file. Expected: trace, debug, info, warn, error, or filter directives like 'netgauze_collector=debug'",
        )
    };

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().with_ansi(use_ansi))
        .try_init()
        .expect("Failed to register tracing subscriber");
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

struct CollectorMetrics {
    _health: opentelemetry::metrics::ObservableGauge<u64>,
    _uptime: opentelemetry::metrics::ObservableGauge<f64>,
    _info: opentelemetry::metrics::ObservableGauge<u64>,
}

impl CollectorMetrics {
    fn new(meter: &opentelemetry::metrics::Meter, process_start: Instant) -> Self {
        let health = meter
            .u64_observable_gauge("netgauze.collector.health")
            .with_description("1 if the collector is healthy, 0 if degraded.")
            .with_callback(move |observer| {
                // TODO: implement actual health checks of the actors
                observer.observe(1, &[]);
            })
            .build();

        // Standard semantic convention:
        // https://opentelemetry.io/docs/specs/semconv/system/process-metrics/#metric-processuptime
        let uptime = meter
            .f64_observable_gauge("process.uptime")
            .with_unit("s")
            .with_description("The time the process has been running in seconds.")
            .with_callback(move |observer| {
                observer.observe(process_start.elapsed().as_secs_f64(), &[]);
            })
            .build();

        let info = meter
            .u64_observable_gauge("netgauze.collector.info")
            .with_description(
                "Always emits 1 while the collector is running. \
                 Carries version and build metadata as attributes.",
            )
            .with_callback(move |observer| {
                observer.observe(
                    1,
                    &[
                        opentelemetry::KeyValue::new(
                            "package_version",
                            build::PKG_VERSION.to_string(),
                        ),
                        opentelemetry::KeyValue::new("commit_hash", build::COMMIT_HASH.to_string()),
                        opentelemetry::KeyValue::new("commit_date", build::COMMIT_DATE.to_string()),
                        opentelemetry::KeyValue::new("branch", build::BRANCH.to_string()),
                        opentelemetry::KeyValue::new("tag", build::TAG.to_string()),
                        opentelemetry::KeyValue::new("build_time", build::BUILD_TIME.to_string()),
                        opentelemetry::KeyValue::new(
                            "build_rust_channel",
                            build::BUILD_RUST_CHANNEL.to_string(),
                        ),
                        opentelemetry::KeyValue::new("build_os", build::BUILD_OS.to_string()),
                        opentelemetry::KeyValue::new(
                            "rust_channel",
                            build::RUST_CHANNEL.to_string(),
                        ),
                        opentelemetry::KeyValue::new(
                            "rust_version",
                            build::RUST_VERSION.to_string(),
                        ),
                        opentelemetry::KeyValue::new(
                            "cargo_version",
                            build::CARGO_VERSION.to_string(),
                        ),
                    ],
                );
            })
            .build();

        Self {
            _health: health,
            _uptime: uptime,
            _info: info,
        }
    }
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

/// NetGauze network metrics collector CLI arguments
#[derive(clap::Parser, Debug)]
#[command(
    about = "NetGauze network telemetry collector",
    long_about = "\
NetGauze network telemetry collector.

Log level can also be overridden via the RUST_LOG environment variable:
  RUST_LOG=netgauze_collector=trace netgauze-collector config.yaml"
)]
struct Args {
    /// Path to the YAML config file
    #[arg(required_unless_present = "version")]
    config_file: Option<PathBuf>,

    /// Print version and build information, then exit
    #[arg(long, short = 'v', action = clap::ArgAction::SetTrue)]
    version: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if args.version {
        println!("NetGauze Collector");
        println!("  Version:     {}", build::PKG_VERSION);
        println!(
            "  Commit:      {} ({})",
            build::COMMIT_HASH,
            build::COMMIT_DATE
        );
        println!("  Branch/Tag:  {} / {}", build::BRANCH, build::TAG);
        println!("  Build Time:  {}", build::BUILD_TIME);
        println!(
            "  Rust:        {} ({})",
            build::RUST_VERSION,
            build::BUILD_RUST_CHANNEL
        );
        println!("  OS:          {}", build::BUILD_OS);
        std::process::exit(0);
    }

    // Safe to unwrap: clap guarantees config_file is Some when --version is absent
    let config_file = args.config_file.unwrap();
    let file = File::open(&config_file)?;
    let reader = BufReader::new(file);
    let config: CollectorConfig = match from_reader(reader) {
        Ok(config) => config,
        Err(err) => {
            return Err(anyhow!("Parsing config file failed: {err}"));
        }
    };

    init_tracing(&config.logging.level, config.logging.ansi);
    log_info();
    let process_start = Instant::now();

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
        // Keep the metrics alive for the entire process lifetime.
        let _collector_metrics = CollectorMetrics::new(&meter, process_start);

        let mut handles = vec![];

        if let Some(flow_config) = config.flow {
            let flow_handle: Pin<Box<dyn Future<Output = Result<(), anyhow::Error>>>> =
                Box::pin(init_flow_collection(flow_config, meter.clone()));
            handles.push(flow_handle);
        }

        if let Some(bmp_config) = config.bmp {
            let bmp_handle: Pin<Box<dyn Future<Output = Result<(), anyhow::Error>>>> =
                Box::pin(init_bmp_collection(bmp_config, meter.clone()));
            handles.push(bmp_handle);
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
