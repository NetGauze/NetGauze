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
use std::{io, net::SocketAddr, time::Duration};
use tokio::sync::mpsc;

use tokio::net::TcpListener;
use tokio_util::codec::FramedRead;
use tower::ServiceBuilder;

use netgauze_bmpd::{codec::BmpCodec, transport::TaggedFramedStream, AddrInfo, TaggedData};

use netgauze_bmp_pkt::BmpMessage;
use netgauze_bmpd::{codec::BmpCodecDecoderError, service::MpscSenderService};
use tower::ServiceExt;

async fn run_server(
    local_socket: SocketAddr,
    sender: mpsc::Sender<
        Result<TaggedData<AddrInfo, BmpMessage>, TaggedData<AddrInfo, BmpCodecDecoderError>>,
    >,
) -> io::Result<()>
where {
    let listener = TcpListener::bind(local_socket).await?;
    loop {
        let (tcp_stream, remote_socket) = listener.accept().await?;
        let (rx, tx) = tcp_stream.into_split();
        let addr_info = AddrInfo::new(local_socket, remote_socket);
        let bmp_stream = TaggedFramedStream::new(addr_info, FramedRead::new(rx, BmpCodec), tx);
        let sender = sender.clone();
        tokio::spawn(async move {
            let mut responses = ServiceBuilder::new()
                .rate_limit(1, Duration::from_secs(10))
                .service(MpscSenderService::new(sender))
                .call_all(bmp_stream);
            while let Some(response) = responses.next().await {
                println!("MpscSenderService Response {:?}", response);
            }
        });
    }
}

#[tokio::main]
async fn main() {
    let local_socket = SocketAddr::from(([0, 0, 0, 0], 33000));
    let (sender, mut receiver) = mpsc::channel(1000);
    let server_handler = tokio::spawn(run_server(local_socket, sender));
    let receiver_handler = tokio::spawn(async move {
        loop {
            match receiver.recv().await {
                None => {
                    println!("MPSC Receiver closed");
                    return;
                }
                Some(value) => {
                    println!("MPSC Received value: {:?}", value);
                }
            }
        }
    });
    tokio::task::yield_now().await;
    let (server_ret, receiver_ret) = tokio::join!(server_handler, receiver_handler);
    server_ret.unwrap().unwrap();
    receiver_ret.unwrap();
}
