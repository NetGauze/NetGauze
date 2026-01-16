use bytes::Bytes;
use futures_util::StreamExt;
use futures_util::stream::SplitSink;
use netgauze_flow_pkt::codec::FlowInfoCodec;
use std::collections::HashMap;
use tokio::net::UdpSocket;
use tokio_util::codec::{BytesCodec, Decoder};
use tokio_util::udp::UdpFramed;
use tracing::info;

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
    let listen_addr = "0.0.0.0:8080";
    let socket = UdpSocket::bind(&listen_addr).await?;
    println!("Listening on addr: {listen_addr}");

    let framed = UdpFramed::new(socket, BytesCodec::default());
    let (_tx, mut stream): (SplitSink<_, (Bytes, _)>, _) = framed.split();
    let mut clients = HashMap::new();
    while let Some(next) = stream.next().await {
        match next {
            Ok((mut buf, addr)) => {
                // If we haven't seen the client before, create a new FlowInfoCodec for it.
                // FlowInfoCodec handles the decoding/encoding of packets and caches
                // the templates learned from the client
                let result = clients
                    .entry(addr)
                    .or_insert(FlowInfoCodec::default())
                    .decode(&mut buf);
                match result {
                    Ok(Some(pkt)) => info!("{}", serde_json::to_string(&pkt).unwrap()),
                    Ok(None) => {
                        println!("Stream closed, exiting");
                        return Ok(());
                    }
                    Err(err) => tracing::error!("Error decoding packet: {:?}", err),
                }
            }
            Err(err) => {
                tracing::error!("Error getting next packet: {:?}, exiting", err);
                return Ok(());
            }
        }
    }
    Ok(())
}
