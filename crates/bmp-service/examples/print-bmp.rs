// Copyright (C) 2022-present The NetGauze Authors.
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

use std::{convert::Infallible, net::SocketAddr};
use tower::{service_fn, ServiceBuilder};

use netgauze_bmp_service::server::{BmpRequest, BmpServer, BmpServerResponse};
use tower::buffer::Buffer;

use netgauze_bmp_service::handle::BmpServerHandle;

fn init_tracing() {
    // Very simple setup at the moment to validate the instrumentation in the code
    // is working in the future that should be configured automatically based on
    // configuration options
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    init_tracing();
    let local_socket = SocketAddr::from(([0, 0, 0, 0], 33000));
    let print_svc = ServiceBuilder::new().service(service_fn(|x: BmpRequest| async move {
        println!("Received: {}", serde_json::to_string(&x).unwrap());
        Ok::<Option<BmpServerResponse>, Infallible>(None)
    }));
    let pipeline = ServiceBuilder::new()
        .service(print_svc);
    let buffer_svc = Buffer::new(pipeline, 100);

    let handle = BmpServerHandle::default();
    let handle_clone = handle.clone();
    let server_handle = tokio::spawn(async move {
        let server = BmpServer::new(local_socket, handle_clone);
        let _ = server.serve(buffer_svc).await;
    });
    //tokio::time::sleep(Duration::from_secs(3)).await;
    //handle.shutdown();
    let (_server_ret,) = tokio::join!(server_handle);

    Ok(())
}
