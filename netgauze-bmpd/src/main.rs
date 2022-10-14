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

use std::{convert::Infallible, net::SocketAddr, time::Duration};
use tower::{service_fn, ServiceBuilder};

use netgauze_bmpd::server::{BmpRequest, BmpServer, BmpServerResponse};
use tower::buffer::Buffer;

use netgauze_bmpd::handle::BmpServerHandle;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let local_socket = SocketAddr::from(([0, 0, 0, 0], 33000));
    let print_svc = ServiceBuilder::new().service(service_fn(|x: BmpRequest| async move {
        println!("Received: {:?}", x);
        Ok::<Option<BmpServerResponse>, Infallible>(None)
    }));
    let pipeline = ServiceBuilder::new()
        //.rate_limit(1, Duration::from_secs(30))
        .service(print_svc);
    let buffer_svc = Buffer::new(pipeline, 100);

    let handle = BmpServerHandle::default();
    let handle_clone = handle.clone();
    let server_handle = tokio::spawn(async move {
        let server = BmpServer::new(local_socket, handle_clone);
        server.serve(buffer_svc).await.unwrap();
    });
    tokio::time::sleep(Duration::from_secs(3)).await;
    handle.shutdown();
    let (_server_ret,) = tokio::join!(server_handle);

    Ok(())
}
