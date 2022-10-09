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

use futures::StreamExt;
use std::{convert::Infallible, io, net::SocketAddr, time::Duration};

use tokio::net::TcpListener;
use tokio_util::codec::FramedRead;
use tower::{service_fn, ServiceBuilder};

use netgauze_bmpd::{codec::BmpCodec, transport::TaggedFramedReadStream, AddrInfo};

use netgauze_bmp_pkt::BmpMessage;
use netgauze_bmpd::{codec::BmpCodecDecoderError, transport::TaggedFramedReadStreamResult};
use tower::{buffer::Buffer, ServiceExt};
use tower_service::Service;

type BmpResult = TaggedFramedReadStreamResult<AddrInfo, BmpMessage, BmpCodecDecoderError>;

/// Start a BMP Server listening on a local_socket and then pass all the
/// incoming messages to a [Buffer] tower service.
///
/// Example:
/// ```rust
/// let local_socket = SocketAddr::from(([0, 0, 0, 0], 33000));
/// let print_svc = ServiceBuilder::new().service(service_fn(|x: BmpResult| async move {
///     println!("Received: {:?}", x);
///     Ok::<(), Infallible>(())
/// }));
/// let buffer_svc = Buffer::new(print_svc, 100);
/// let server_handler = tokio::spawn(run_server(local_socket, buffer_svc));
/// tokio::join!(server_handler).0.expect("Server failed");
/// ```
async fn run_server<S>(local_socket: SocketAddr, buffer_svc: Buffer<S, BmpResult>) -> io::Result<()>
where
    S: Service<BmpResult> + 'static + Send,
    S::Error: Send + Sync + std::error::Error,
    S::Future: Send,
    <S as Service<BmpResult>>::Response: Send,
{
    let listener = TcpListener::bind(local_socket).await?;
    loop {
        let (tcp_stream, remote_socket) = listener.accept().await?;
        let (rx, tx) = tcp_stream.into_split();
        let addr_info = AddrInfo::new(local_socket, remote_socket);
        let bmp_stream =
            TaggedFramedReadStream::new(addr_info, FramedRead::new(rx, BmpCodec), Some(tx));
        let buffer_svc = buffer_svc.clone();
        tokio::spawn(async move {
            let mut responses = buffer_svc.call_all(bmp_stream);
            // Keep the stream going till is closed
            while (responses.next().await).is_some() {}
        });
    }
}

#[tokio::main]
async fn main() {
    let local_socket = SocketAddr::from(([0, 0, 0, 0], 33000));
    let print_svc = ServiceBuilder::new().service(service_fn(|x: BmpResult| async move {
        println!("Received: {:?}", x);
        Ok::<(), Infallible>(())
    }));
    let pipeline = ServiceBuilder::new()
        .rate_limit(1, Duration::from_secs(1))
        .service(print_svc);
    let buffer_svc = Buffer::new(pipeline, 100);
    let server_handler = tokio::spawn(run_server(local_socket, buffer_svc));
    let (server_ret,) = tokio::join!(server_handler);
    server_ret.unwrap().unwrap();
}
