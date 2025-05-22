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

use std::{fmt::Debug, io, net::SocketAddr};
use tokio::net::{TcpListener, TcpStream};
use tokio_stream::StreamExt;
use tokio_util::codec::Framed;
use tower::ServiceExt;
use tower_service::Service;

use netgauze_bmp_pkt::{codec::BmpCodec, BmpMessage};

use crate::{handle::BmpServerHandle, AddrInfo, BmpCodecDecoderError, TaggedData};

/// Tagged BMP Protocol request
pub type BmpRequest =
    Result<TaggedData<AddrInfo, Option<BmpMessage>>, TaggedData<AddrInfo, BmpCodecDecoderError>>;

/// Allows the consuming service of BMP to send some messages back to
/// [`BmpServer`]
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum BmpServerResponse {
    /// Ask BmpServer to close the given connection to the BMP sender.
    CloseConnection,
}

/// Listen and serve BMP Protocol
#[derive(Debug)]
pub struct BmpServer {
    local_addr: SocketAddr,
    handle: BmpServerHandle,
}

impl BmpServer {
    pub const fn new(local_addr: SocketAddr, handle: BmpServerHandle) -> Self {
        Self { local_addr, handle }
    }

    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    #[tracing::instrument(skip(self,service), fields(local_addr=format!("{}", self.local_addr)))]
    pub async fn serve<S, E>(self, service: S) -> io::Result<()>
    where
        S: Service<BmpRequest, Response = Option<BmpServerResponse>, Error = E>
            + 'static
            + Send
            + Clone,
        S::Future: Send + 'static,
        S::Error: Send,
        E: Debug,
    {
        let local_addr = self.local_addr;
        tracing::info!("binding on socket");
        let listener = TcpListener::bind(local_addr).await?;
        let handle = self.handle;
        handle.notify_listening();
        tracing::info!("started listening");
        let accept_loop_future = async {
            loop {
                let (tcp_stream, remote_addr) = tokio::select! {
                    biased;
                    result = listener.accept() => {
                        let (tcp_stream, remote_addr) = result?;
                        tracing::info!("accepted new connection: {:?}", remote_addr);
                        (tcp_stream, remote_addr)
                    },
                    _ = handle.wait_graceful_shutdown() => {
                        tracing::info!("graceful_shutdown");
                        return Ok::<(), io::Error>(())
                    },
                };
                let addr_info = AddrInfo::new(local_addr, remote_addr);
                let framed = Framed::new(tcp_stream, BmpCodec::default());
                let svc = service.clone();
                let watcher = handle.watcher();
                tokio::spawn(async move {
                    tracing::trace_span!("client_worker");
                    tracing::info!("worker_started");
                    tokio::select! {
                        biased;
                        _ = watcher.wait_shutdown() => {
                             tracing::info!("worker_shutdown: {:?}", addr_info);
                        },
                        ret = Self::handle_connection(svc.clone(), addr_info, framed) =>{
                            tracing::info!("worker closed {:?} and service ret: {:?}", addr_info, ret);
                        },
                    }
                    tracing::info!("worker_ended");
                });
            }
        };
        tokio::select! {
            biased;
            _ = handle.wait_shutdown() => {
                tracing::info!("server is shutting down on request by handle");
                return Ok(())
            },
            result = accept_loop_future => {
                tracing::info!("server is shutting down due to: {:?}", result);
                result
            },
        }?;

        tracing::info!(
            "waiting on connections to be cleanly closed. remaining connections: {}",
            handle.connection_count()
        );
        handle.wait_connections_end().await;
        tracing::info!("server closed");
        Ok(())
    }

    #[tracing::instrument(
        skip(service, addr_info, framed),
        fields(
            local_socket=format!("{}", addr_info.local_socket()),
            remote_socket=format!("{}", addr_info.remote_socket())
        )
    )]
    async fn handle_connection<S, E>(
        mut service: S,
        addr_info: AddrInfo,
        mut framed: Framed<TcpStream, BmpCodec>,
    ) -> Result<(), E>
    where
        S: Service<BmpRequest, Response = Option<BmpServerResponse>, Error = E>
            + 'static
            + Send
            + Clone,
        S::Future: Send + 'static,
        S::Error: Send,
    {
        loop {
            let result = StreamExt::try_next(&mut framed).await;
            match result {
                Ok(msg) => {
                    let is_last = msg.is_none();
                    let tagged = Ok(TaggedData::new(addr_info, msg));
                    service.ready().await?;
                    let svc_response = service.call(tagged).await?;
                    if is_last || svc_response == Some(BmpServerResponse::CloseConnection) {
                        return Ok(());
                    }
                }
                Err(err) => {
                    let tagged = Err(TaggedData::new(addr_info, err));
                    service.ready().await?;
                    service.call(tagged).await?;
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        net::{IpAddr, Ipv4Addr},
        time::Duration,
    };

    use super::*;
    use futures_util::SinkExt;
    use netgauze_bmp_pkt::v3::{BmpMessageValue, InitiationMessage};
    use rand::Rng;
    use tokio::task::JoinHandle;
    use tower::{service_fn, ServiceBuilder};

    #[tokio::test]
    async fn test_start() {
        let (handle, server, addr) = start_server().await;
        let mut client = connect(addr).await;
        let msg = BmpMessage::V3(BmpMessageValue::Initiation(InitiationMessage::new(vec![])));
        client.send(msg).await.unwrap();
        handle.shutdown();
        // yield to let the server handle the shutdown signal
        tokio::task::yield_now().await;
        assert!(server.is_finished());
    }

    #[tokio::test]
    async fn test_shutdown() {
        let (handle, server, addr) = start_server().await;
        let mut client = connect(addr).await;
        let msg = BmpMessage::V3(BmpMessageValue::Initiation(InitiationMessage::new(vec![])));
        client.send(msg.clone()).await.unwrap();
        handle.shutdown();
        // yield to let the server handle the shutdown signal
        tokio::time::sleep(Duration::from_millis(100)).await;
        // No clients should be able to connect
        assert!(client.send(msg).await.is_err());
        assert!(server.is_finished());
    }

    fn get_free_socket() -> SocketAddr {
        let mut rng = rand::rng();
        let port: u16 = rng.random_range(25000..50000);
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    async fn connect(addr: SocketAddr) -> Framed<TcpStream, BmpCodec> {
        let stream = TcpStream::connect(addr).await.unwrap();
        Framed::new(stream, BmpCodec::default())
    }

    async fn start_server() -> (BmpServerHandle, JoinHandle<io::Result<()>>, SocketAddr) {
        let handle = BmpServerHandle::default();
        let server_handle = handle.clone();
        let addr = get_free_socket();
        let server_task = tokio::spawn(async move {
            let empty_svc = ServiceBuilder::new().service(service_fn(|_x| async move {
                Ok::<Option<BmpServerResponse>, Infallible>(None)
            }));

            BmpServer::new(addr, server_handle).serve(empty_svc).await
        });
        handle.listening().await;
        (handle, server_task, addr)
    }
}
