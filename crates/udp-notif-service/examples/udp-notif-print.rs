use bytes::Bytes;
use futures_util::{StreamExt, stream::SplitSink};
use std::collections::HashMap;
use tokio::net::UdpSocket;
use tokio_util::{
    codec::{BytesCodec, Decoder},
    udp::UdpFramed,
};
use tracing::{error, info};

use netgauze_udp_notif_pkt::codec::UdpPacketCodec;

fn init_tracing() {
    // Very simple setup at the moment to validate the instrumentation in the code
    // is working in the future that should be configured automatically based on
    // configuration options
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    init_tracing();
    let listen_addr = "0.0.0.0:9999";
    let socket = UdpSocket::bind(&listen_addr).await?;
    info!("listening on addr: {}", listen_addr);

    let framed = UdpFramed::new(socket, BytesCodec::default());
    let (_tx, mut stream): (SplitSink<_, (Bytes, _)>, _) = framed.split();
    let mut clients = HashMap::new();
    while let Some(next) = stream.next().await {
        match next {
            Ok((mut buf, addr)) => {
                // If we haven't seen the client before, create a new UdpPacketCodec for it.
                // UdpPacketCodec handles the decoding/encoding of udp-notif packets.
                let result = clients
                    .entry(addr)
                    .or_insert(UdpPacketCodec::default())
                    .decode(&mut buf);
                match result {
                    Ok(Some(msg)) => println!("{}", serde_json::to_string(&msg).unwrap()),
                    Ok(None) => info!("message incomplete or too short to decode"),
                    Err(err) => error!("error decoding packet: {:?}", err),
                }
            }
            Err(err) => {
                error!("error getting next packet: {:?}, exiting", err);
                return Ok(());
            }
        }
    }
    Ok(())
}
