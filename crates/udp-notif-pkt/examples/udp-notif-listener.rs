use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use rdkafka::{
    producer::{FutureProducer, FutureRecord},
    ClientConfig,
};
use serde::Serialize;
use std::time::Duration;
use bytes::Bytes;
use tokio::{sync::mpsc, task::JoinHandle};
use tokio::net::UdpSocket;
use tokio_util::codec::{BytesCodec, Decoder};
use tokio_util::udp::UdpFramed;
use netgauze_udp_notif_pkt::UdpNotifPacket;

use futures_util::{stream::SplitSink, StreamExt};
use netgauze_udp_notif_pkt::codec::UdpPacketCodec;

fn init_tracing() {
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
}

#[derive(Debug, Serialize)]
struct KafkaUdpNotifMessage {
    peer: SocketAddr,
    msg: UdpNotifPacket,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let listen_addr = "0.0.0.0:10003";
    let socket = UdpSocket::bind(&listen_addr).await?;
    tracing::info!("Listening for UDP-Notif Messages on addr: {}", listen_addr);
    let kafka_broker = env::var("KAFKA_BROKER").expect("KAFKA_BROKER env var is not set");
    let kafka_topic = env::var("KAFKA_TOPIC").expect("KAFKA_TOPIC env var is not set");
    let kafka_username = env::var("KAFKA_USERNAME").expect("KAFKA_USERNAME env var is not set");
    let kafka_password = env::var("KAFKA_PASSWORD").expect("KAFKA_PASSWORD env var is not set");
    let producer: FutureProducer = ClientConfig::new()
        .set("bootstrap.servers", &kafka_broker)
        .set("security.protocol", "SASL_SSL")
        .set("sasl.mechanisms", "SCRAM-SHA-512")
        .set("sasl.username", kafka_username)
        .set("sasl.password", kafka_password)
        .set("message.timeout.ms", "5000")
        .create()?;

    let framed = UdpFramed::new(socket, BytesCodec::default());
    let (_tx, mut stream): (SplitSink<_, (Bytes, _)>, _) = framed.split();
    let mut clients = HashMap::new();
    while let Some(next) = stream.next().await {
        match next {
            Ok((mut buf, addr)) => {
                let result = clients
                    .entry(addr)
                    .or_insert(UdpPacketCodec::default())
                    .decode(&mut buf);
                match result {
                    Ok(Some(pkt)) => {
                        tracing::info!("Received message {}", serde_json::to_string(&pkt).unwrap());
                        let kafka_msg = KafkaUdpNotifMessage {
                            peer: addr.clone(),
                            msg: pkt,
                        };
                        let serialized = serde_json::to_string(&kafka_msg).unwrap();
                        let key = addr.to_string();
                        let record = FutureRecord::to(&kafka_topic)
                            .payload(&serialized)
                            .key(&key);
                        if let Err(e) = producer.send(record, Duration::from_secs(0)).await {
                            tracing::error!("Failed to send message to Kafka: {:?}", e);
                        }
                    }
                    Ok(None) => {
                        tracing::info!("Stream closed, exiting");
                        return Ok(());
                    }
                    Err(err) => tracing::error!("Error decoding packet: {:?}", err),
                }
            }
            Err(err) => tracing::error!("Error: {}", err),
        }
    }
    Ok(())
}