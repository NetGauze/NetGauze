// Copyright (C) 2025-present The NetGauze Authors.
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

use crate::{
    capabilities::{Capability, NetconfVersion},
    codec::{SshCodec, SshCodecError},
    protocol::{Hello, NetConfMessage, Rpc, RpcOperation, RpcReply},
};
use futures_util::{stream::StreamExt, SinkExt};
use secrecy::ExposeSecret;
use std::{collections::HashSet, io, net::SocketAddr, sync::Arc};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;

/// SSH client handler to enable certain behaviors in the russh::client
/// at the moment, this is simple implementation that accepts connections to all
/// servers.
///
/// TODO: extend the handler to handle known hosts or host certs checks
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct SshHandler {}

impl russh::client::Handler for SshHandler {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        // Don't check the server public key
        Ok(true)
    }
}

/// This error type encapsulates all possible errors that can occur when using
/// the NetConfSshClient.
#[derive(Debug, strum::Display)]
pub enum NetConfSshClientError {
    #[strum(to_string = "SSH connection error {0}")]
    SshError(russh::Error),

    #[strum(to_string = "SSH codec error {0}")]
    SshCodec(SshCodecError),

    #[strum(
        to_string = "Unexpected NETCONF message, expecting `{expected}` but received `{actual:?}`"
    )]
    UnexpectedMessage {
        expected: String,
        actual: NetConfMessage,
    },

    #[strum(
        to_string = "Session ID is not defined in the <hello> message received from the server"
    )]
    SessionIdIsNotDefined,
}

impl std::error::Error for NetConfSshClientError {}

impl From<SshCodecError> for NetConfSshClientError {
    fn from(err: SshCodecError) -> Self {
        NetConfSshClientError::SshCodec(err)
    }
}

impl From<russh::Error> for NetConfSshClientError {
    fn from(err: russh::Error) -> Self {
        NetConfSshClientError::SshError(err)
    }
}

/// SSH authentication methods supported by the NetConfSshClient
///
/// TODO: add support for more authentication methods, such as SSH agent auth.
#[derive(Debug)]
pub enum SshAuth {
    /// Username/Password authentication
    Password {
        user: String,
        password: secrecy::SecretBox<String>,
    },
    /// UserName/Private key authentication
    Key {
        user: String,
        private_key: Arc<russh::keys::ssh_key::PrivateKey>,
    },
}

pub struct NetconfSshConnectConfig<H> {
    auth: SshAuth,
    host: SocketAddr,
    handler: H,
    config: Arc<russh::client::Config>,
}

impl<H: russh::client::Handler> NetconfSshConnectConfig<H> {
    pub const fn new(
        auth: SshAuth,
        host: SocketAddr,
        handler: H,
        config: Arc<russh::client::Config>,
    ) -> Self {
        Self {
            auth,
            host,
            handler,
            config,
        }
    }

    pub const fn auth(&self) -> &SshAuth {
        &self.auth
    }

    pub const fn host(&self) -> SocketAddr {
        self.host
    }

    pub const fn handler(&self) -> &H {
        &self.handler
    }

    pub fn config(&self) -> &russh::client::Config {
        self.config.as_ref()
    }
}

pub async fn connect<H: russh::client::Handler + 'static>(
    config: NetconfSshConnectConfig<H>,
) -> Result<NetConfSshClient<russh::ChannelStream<russh::client::Msg>>, NetConfSshClientError>
where
    NetConfSshClientError: From<<H as russh::client::Handler>::Error>,
{
    tracing::debug!("TCP connecting to {}", config.host);
    let mut session = russh::client::connect(config.config, config.host, config.handler).await?;
    tracing::debug!("TCP connected to {}", config.host);

    let (user, auth_result) = match &config.auth {
        SshAuth::Password { user, password } => {
            tracing::info!("Using password authentication for user {user}");
            (
                user,
                session
                    .authenticate_password(user, password.expose_secret())
                    .await?,
            )
        }
        SshAuth::Key { user, private_key } => {
            tracing::info!("Using private key authentication for user {user}");
            let private_key = russh::keys::PrivateKeyWithHashAlg::new(
                Arc::clone(private_key),
                session.best_supported_rsa_hash().await?.flatten(),
            );
            tracing::info!(
                "Negotiated private key and using {} hashing algorithm",
                private_key.algorithm()
            );
            (
                user,
                session.authenticate_publickey(user, private_key).await?,
            )
        }
    };
    if !auth_result.success() {
        tracing::error!("Authentication failed");
        return Err(NetConfSshClientError::SshError(
            russh::Error::NotAuthenticated,
        ));
    }
    tracing::info!(
        "Authentication successful to {user}@{}, requesting the NETCONF subsystem",
        config.host
    );
    let channel = session.channel_open_session().await?;
    channel.request_subsystem(true, "netconf").await?;
    tracing::info!("NETCONF subsystem connected to {user}@{}", config.host);
    let stream = channel.into_stream();
    NetConfSshClient::connect(stream).await
}

pub struct NetConfSshClient<T> {
    /// Bidirectional channel to the NETCONF peer
    framed: Framed<T, SshCodec>,

    /// Capabilities announced by the NETCONF peer
    peer_caps: HashSet<Capability>,

    /// Session ID assigned by the NETCONF server
    session_id: u32,

    /// Keep track of the message IDs sent to the peer
    next_message_id: u32,
}

impl<T> NetConfSshClient<T> {
    pub const fn peer_caps(&self) -> &HashSet<Capability> {
        &self.peer_caps
    }

    pub const fn session_id(&self) -> u32 {
        self.session_id
    }

    pub fn inner(self) -> Framed<T, SshCodec> {
        self.framed
    }

    pub const fn next_message_id(&mut self) -> u32 {
        let ret = self.next_message_id;
        self.next_message_id += 1;
        ret
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> NetConfSshClient<T> {
    async fn exchange_hello(
        mut framed: Framed<T, SshCodec>,
    ) -> Result<(Framed<T, SshCodec>, u32, HashSet<Capability>), NetConfSshClientError> {
        let msg = framed.next().await.ok_or_else(|| {
            SshCodecError::IO(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "session closed".to_string(),
            ))
        })??;
        let received_hello = if let NetConfMessage::Hello(hello) = msg {
            hello
        } else {
            return Err(NetConfSshClientError::UnexpectedMessage {
                expected: "hello".to_string(),
                actual: msg,
            });
        };
        let session_id = received_hello
            .session_id()
            .ok_or_else(|| NetConfSshClientError::SessionIdIsNotDefined)?;
        let peer_caps = received_hello.capabilities().clone();
        // NetGauze doesn't support the old version of NETCONF SSH
        let mut announce_caps = peer_caps.clone();
        announce_caps.remove(&Capability::NetconfBase(NetconfVersion::V1_0));
        let hello = NetConfMessage::Hello(Hello::new(None, announce_caps.clone()));
        framed.send(hello).await?;
        Ok((framed, session_id, peer_caps))
    }

    pub async fn connect(stream: T) -> Result<Self, NetConfSshClientError> {
        let framed = Framed::new(stream, SshCodec::default());
        let (framed, session_id, peer_caps) = Self::exchange_hello(framed).await?;
        let next_message_id = 10110;
        Ok(Self {
            framed,
            peer_caps,
            session_id,
            next_message_id,
        })
    }

    pub async fn rpc(
        &mut self,
        operation: RpcOperation,
    ) -> Result<Box<str>, NetConfSshClientError> {
        let message_id = self.next_message_id().to_string().into_boxed_str();
        let rpc = Rpc::new(message_id.clone(), operation);
        self.framed.send(NetConfMessage::Rpc(rpc)).await?;
        Ok(message_id)
    }

    pub async fn rpc_reply(&mut self) -> Option<Result<RpcReply, NetConfSshClientError>> {
        let msg = self.framed.next().await;
        match msg {
            None => None,
            Some(Ok(NetConfMessage::RpcReply(reply))) => Some(Ok(reply)),
            Some(Ok(NetConfMessage::Hello(hello))) => {
                Some(Err(NetConfSshClientError::UnexpectedMessage {
                    expected: "<rpc-reply>".to_string(),
                    actual: NetConfMessage::Hello(hello),
                }))
            }
            Some(Ok(NetConfMessage::Rpc(rpc))) => {
                Some(Err(NetConfSshClientError::UnexpectedMessage {
                    expected: "<rpc-reply>".to_string(),
                    actual: NetConfMessage::Rpc(rpc),
                }))
            }
            Some(Err(e)) => Some(Err(e.into())),
        }
    }

    pub async fn close(mut self) -> Result<(), NetConfSshClientError> {
        let message_id = self.next_message_id.to_string().into_boxed_str();
        self.framed
            .send(NetConfMessage::Rpc(Rpc::new(
                message_id,
                RpcOperation::Raw("<close-session/>".into()),
            )))
            .await?;
        if let Some(reply) = self.rpc_reply().await {
            let reply = reply?;
            if !reply.reply().is_ok() {
                return Err(NetConfSshClientError::UnexpectedMessage {
                    expected: "ok".to_string(),
                    actual: NetConfMessage::RpcReply(reply),
                });
            }
        }
        self.framed.close().await?;
        Ok(())
    }
}
