use anyhow::Context;
use futures_util::{stream::SplitSink, SinkExt, StreamExt};
use std::{
    fs::read_to_string,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{task::JoinHandle, time};

use clap::Parser;
use futures_util::stream::SplitStream;

use tokio_util::sync::CancellationToken;

use netgauze_flow_pkt::{codec::FlowInfoCodec, FlowInfo};
use tokio::net::UdpSocket;
use tokio_util::udp::UdpFramed;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    server_addr: String,

    #[arg(short, long)]
    frequency: u64,

    #[arg(short, long)]
    client_count: u64,

    #[arg(short, long)]
    limit: u64,

    #[arg(short, long)]
    input: String,
}

#[allow(clippy::too_many_arguments)]
pub async fn start_sender(
    local_addr: SocketAddr,
    server_addr: SocketAddr,
    frequency: u64,
    buffers: &[FlowInfo],
    counter: Arc<AtomicU64>,
    total_counter: Arc<AtomicU64>,
    limit: u64,
    client_cancel: CancellationToken,
) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(local_addr).await?;
    let framed = UdpFramed::new(socket, FlowInfoCodec::default());
    let (mut tx, _stream): (SplitSink<_, (FlowInfo, SocketAddr)>, SplitStream<_>) = framed.split();

    tokio::time::sleep(Duration::from_secs(1)).await;
    let mut interval = time::interval(Duration::from_millis(1000 / frequency));
    let mut index = 0;
    while !client_cancel.is_cancelled() {
        interval.tick().await;
        if total_counter.load(Ordering::Relaxed) >= limit {
            break;
        }
        let buf = &buffers[index];
        tx.send((buf.clone(), server_addr)).await?;
        counter.fetch_add(1, Ordering::Relaxed);
        total_counter.fetch_add(1, Ordering::Relaxed);
        index += 1;
        if index >= buffers.len() {
            index = 0;
        }
    }
    tracing::info!("Client shutdown");
    Ok(())
}

fn read_input(file_path: String) -> anyhow::Result<Vec<FlowInfo>> {
    let mut ret = vec![];
    for line in read_to_string(file_path.as_str())?.lines() {
        let pkt: FlowInfo = serde_json::from_str(line)
            .with_context(|| format!("Cannot parse flow info from {file_path}"))?;
        ret.push(pkt);
    }
    Ok(ret)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let subscriber = tracing_subscriber::FmtSubscriber::new();
    tracing::subscriber::set_global_default(subscriber)
        .context("failed to setup tracing subscriber")?;

    let server_addr: SocketAddr = args
        .server_addr
        .parse()
        .context("failed to parse server address")?;
    eprintln!("Server {server_addr}");
    let limit = args.limit;

    let local_addr: SocketAddr = if server_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()
    .context("failed to parse local address")?;

    let cancel = CancellationToken::new();

    // let buffers = vec![FlowInfo::IPFIX(IpfixPacket::new(
    //     Utc.with_ymd_and_hms(2023, 3, 4, 12, 0, 0).unwrap(),
    //     3812,
    //     0,
    //     vec![Set::Template(vec![TemplateRecord::new(
    //         307,
    //         vec![
    //             FieldSpecifier::new(ie::IE::sourceIPv4Address, 4).unwrap(),
    //             FieldSpecifier::new(ie::IE::destinationIPv4Address, 4).unwrap(),
    //             FieldSpecifier::new(ie::IE::octetDeltaCount, 4).unwrap(),
    //             FieldSpecifier::new(ie::IE::packetDeltaCount, 4).unwrap(),
    //         ],
    //     )])],
    // )
    // )];
    let buffers = read_input(args.input)?;

    tracing::info!(
        "Starting client count: {}, connecting to {}, sending with frequency:{}",
        args.client_count,
        server_addr,
        args.frequency
    );

    let client_count = args.client_count;
    let sent_counter = Arc::new(AtomicU64::new(0));
    let total_sent_counter = Arc::new(AtomicU64::new(0));

    let joins = (0..client_count)
        .map(|_| {
            let buffers = buffers.clone();
            let client_cancel = cancel.clone();
            let counter_clone = sent_counter.clone();
            let total_sent_counter_clone = total_sent_counter.clone();
            tokio::spawn(async move {
                start_sender(
                    local_addr,
                    server_addr,
                    args.frequency,
                    &buffers,
                    counter_clone,
                    total_sent_counter_clone,
                    limit,
                    client_cancel,
                )
                .await
            })
        })
        .collect::<Vec<JoinHandle<anyhow::Result<()>>>>();

    let mut interval = time::interval(Duration::from_secs(1));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let sent_count = sent_counter.swap(0, Ordering::Relaxed);
                let total = total_sent_counter.load(Ordering::Relaxed);
                tracing::info!("sent {}, total sent: {}", sent_count, total);
                if total >= limit {
                    tracing::info!("Limit reached sleeping for one second before shutting down");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    cancel.cancel();
                    break;
                }
            }

            _ = cancel.cancelled() => {
                break;
            }
        }
    }

    for join in joins {
        join.await??;
    }

    let sent_count = sent_counter.swap(0, Ordering::Relaxed);
    //let total = total_sent_counter.fetch_add(sent_count, Ordering::Relaxed);
    let total = total_sent_counter.load(Ordering::Relaxed);
    let diff = total as i64 - limit as i64;
    tracing::info!(
        "Final tally: sent {}, total sent: {} with (total sent - limit) = {}",
        sent_count,
        total,
        diff
    );

    Ok(())
}
