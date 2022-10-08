use std::{io, net::SocketAddr};

use futures::StreamExt;

use tokio::net::TcpListener;
use tokio_util::codec::FramedRead;

use netgauze_bmpd::{codec::BmpCodec, transport::TaggedFramedStream, AddrInfo};

async fn run_server(local_socket: SocketAddr) -> io::Result<()>
where {
    let listener = TcpListener::bind(local_socket).await?;
    loop {
        let (tcp_stream, remote_socket) = listener.accept().await?;
        let (rx, tx) = tcp_stream.into_split();
        let addr_info = AddrInfo::new(local_socket, remote_socket);
        let mut bmp_stream = TaggedFramedStream::new(addr_info, FramedRead::new(rx, BmpCodec), tx);
        tokio::spawn(async move {
            while let Some(result) = bmp_stream.next().await {
                match result {
                    Ok(tagged_msg) => println!(
                        "[{:?}] BMP Message: {:?}",
                        tagged_msg.tag(),
                        tagged_msg.value()
                    ),
                    Err(tagged_err) => eprintln!(
                        "[{:?}], BMP Message Error: {:?}",
                        tagged_err.tag(),
                        tagged_err.value()
                    ),
                };
            }
            println!("[{:?}] BMP Stream is closed", addr_info);
        });
    }
}

#[tokio::main]
async fn main() {
    let local_socket = SocketAddr::from(([0, 0, 0, 0], 33000));
    let t = tokio::spawn(run_server(local_socket));
    tokio::task::yield_now().await;
    let _ = tokio::join!(t).0;
}
