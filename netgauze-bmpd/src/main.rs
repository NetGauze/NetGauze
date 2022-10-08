use futures::{
    future::{ready, Ready},
    StreamExt,
};
use std::{
    error::Error,
    io,
    net::SocketAddr,
    task::{Context, Poll},
    time::Duration,
};

use tokio::net::TcpListener;
use tokio_util::codec::FramedRead;
use tower::ServiceBuilder;

use netgauze_bmpd::{codec::BmpCodec, transport::TaggedFramedStream, AddrInfo, TaggedData};

use netgauze_bmp_pkt::BmpMessage;
use netgauze_bmpd::codec::BmpCodecDecoderError;
use tower::ServiceExt;
use tower_service::Service;

#[derive(Debug, Eq, PartialEq)]
struct DummyService;

impl Service<Result<TaggedData<AddrInfo, BmpMessage>, TaggedData<AddrInfo, BmpCodecDecoderError>>>
    for DummyService
{
    type Response =
        Result<TaggedData<AddrInfo, BmpMessage>, TaggedData<AddrInfo, BmpCodecDecoderError>>;
    type Error = Box<dyn Error + Send + Sync>;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(
        &mut self,
        req: Result<TaggedData<AddrInfo, BmpMessage>, TaggedData<AddrInfo, BmpCodecDecoderError>>,
    ) -> Self::Future {
        println!("In service {:?}", req);
        ready(Ok(req))
    }
}

async fn run_server(local_socket: SocketAddr) -> io::Result<()>
where {
    let listener = TcpListener::bind(local_socket).await?;
    loop {
        let (tcp_stream, remote_socket) = listener.accept().await?;
        let (rx, tx) = tcp_stream.into_split();
        let addr_info = AddrInfo::new(local_socket, remote_socket);
        let bmp_stream = TaggedFramedStream::new(addr_info, FramedRead::new(rx, BmpCodec), tx);

        tokio::spawn(async move {
            let mut responses = ServiceBuilder::new()
                .rate_limit(1, Duration::from_secs(10))
                .service(DummyService)
                .call_all(bmp_stream);
            while let Some(response) = responses.next().await {
                println!("Response {:?}", response);
            }
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
