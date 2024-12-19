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

use figment::{
    providers::{Env, Format},
    Figment,
};

use figment::providers::Yaml;
use netgauze_collector::{config::CollectorConfig, init_flow_collection};
use std::{env, path::PathBuf, str::FromStr};
use tracing::{info, Level};

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
    let config: CollectorConfig = match Figment::new()
        .merge(Yaml::file(config_file))
        .merge(Env::prefixed("APP_"))
        .extract()
    {
        Ok(config) => config,
        Err(err) => {
            return Err(format!("Parsing config file failed: {err}").into());
        }
    };
    init_tracing(&config.logging.level);

    let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
    // If num threads is not configured then the default use all CPU cores is used
    if let Some(num_threads) = config.runtime.threads {
        runtime_builder.worker_threads(num_threads);
    }
    runtime_builder.enable_all();
    let runtime = runtime_builder.build()?;
    runtime.block_on(async move {
        let flow_handle = init_flow_collection(config.flow.clone());

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
            _ = flow_handle => {
                info!("Flow collection and publishing is terminated, shutting down the collector");
            }
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync + 'static>>(())
    })
}
