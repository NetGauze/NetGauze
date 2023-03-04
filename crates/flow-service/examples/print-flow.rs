use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use tokio::net::UdpSocket;
use tokio_util::{
    codec::{BytesCodec, Decoder},
    udp::UdpFramed,
};

use futures_util::stream::SplitSink;
use futures_util::StreamExt;

use netgauze_flow_service::codec::FlowInfoCodec;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let listen_addr = "0.0.0.0:8080";
    let socket = UdpSocket::bind(&listen_addr).await?;
    println!("Listening on addr: {}", listen_addr);

    let framed = UdpFramed::new(socket, BytesCodec::default());
    let (_tx, mut stream): (SplitSink<_, (Bytes, _)>, _) = framed.split();
    let clients = Arc::new(DashMap::new());
    while let Some(next) = stream.next().await {
        match next {
            Ok((mut buf, addr)) => {
                let result = clients
                    .entry(addr)
                    .or_insert(FlowInfoCodec::default())
                    .decode(&mut buf);
                match result {
                    Ok(Some(pkt)) => println!("Received Packet: {:?}", pkt),
                    Ok(None) => { 
                        println!("Stream closed, exiting");
                        return Ok(())
                    },
                    Err(err) => eprintln!("Error decoding packet: {:?}", err),
                }
            }
            Err(err) => {
                eprintln!("Error getting next packet: {:?}, exiting", err);
                return Ok(())
            }
        }
    }
    Ok(())
}
