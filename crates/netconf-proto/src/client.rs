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

use crate::capabilities::{Capability, NetconfVersion};
use crate::codec::{SshCodec, SshCodecError};
use crate::protocol::{
    Hello, NetConfMessage, Rpc, RpcOperation, RpcReply, RpcReplyContent, RpcResponse,
    WellKnownOperation, WellKnownRpcResponse, YangSchemaFormat,
};
use crate::yanglib::{
    BackwardCompatibilityChecker, DependencyError, ImportOnlyModule, Module, ModuleSetBuilder,
    Submodule, YangLibrary,
};
use crate::yangparser::extract_yang_dependencies;
use futures_util::SinkExt;
use futures_util::stream::StreamExt;
use secrecy::ExposeSecret;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
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

    #[strum(to_string = "Encountered an error while parsing YANG Module {name}: {error}")]
    YangSchemaParsingError { name: String, error: String },

    #[strum(to_string = "Error computing the YANG dependency graph {0}")]
    DependencyError(DependencyError),
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
    let peer = config.host;
    tracing::debug!("[{peer}] Initiating TCP connection");
    let mut session = russh::client::connect(config.config, config.host, config.handler).await?;
    tracing::debug!("[{peer}] TCP connected");

    let (user, auth_result) = match &config.auth {
        SshAuth::Password { user, password } => {
            tracing::debug!("[{peer}] Using password authentication for user `{user}`");
            (
                user,
                session
                    .authenticate_password(user, password.expose_secret())
                    .await?,
            )
        }
        SshAuth::Key { user, private_key } => {
            tracing::debug!("[{peer}] Using private key authentication for user `{user}`");
            let private_key = russh::keys::PrivateKeyWithHashAlg::new(
                Arc::clone(private_key),
                session.best_supported_rsa_hash().await?.flatten(),
            );
            tracing::debug!(
                "[{peer}] Negotiated private key and using `{}` hashing algorithm",
                private_key.algorithm()
            );
            (
                user,
                session.authenticate_publickey(user, private_key).await?,
            )
        }
    };
    if !auth_result.success() {
        tracing::error!("[{peer}] Authentication failed");
        return Err(NetConfSshClientError::SshError(
            russh::Error::NotAuthenticated,
        ));
    }
    tracing::debug!(
        "[{peer}] Authentication successful to `{user}@{}`, requesting the NETCONF subsystem",
        config.host
    );
    let channel = session.channel_open_session().await?;
    channel.request_subsystem(true, "netconf").await?;
    tracing::info!(
        "[{peer}] NETCONF subsystem connected to `{user}@{}`",
        config.host
    );
    let stream = channel.into_stream();
    NetConfSshClient::connect(config.host, stream).await
}

pub struct NetConfSshClient<T> {
    /// Address of NETCONF server
    peer: SocketAddr,

    /// Bidirectional channel to the NETCONF peer
    framed: Framed<T, SshCodec>,

    /// Capabilities announced by the NETCONF peer
    peer_caps: HashSet<Capability>,

    /// Session ID assigned by the NETCONF server
    session_id: u32,

    /// Keep track of the message IDs sent to the peer
    next_message_id: u32,

    /// Cache peer's YANG Library
    yang_library: Option<Arc<YangLibrary>>,
}

impl<T> NetConfSshClient<T> {
    pub const fn peer(&self) -> SocketAddr {
        self.peer
    }

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

    pub fn yang_library(&self) -> Option<Arc<YangLibrary>> {
        self.yang_library.as_ref().map(Arc::clone)
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

    pub async fn connect(peer: SocketAddr, stream: T) -> Result<Self, NetConfSshClientError> {
        let framed = Framed::new(stream, SshCodec::default());
        let (framed, session_id, peer_caps) = Self::exchange_hello(framed).await?;
        let next_message_id = 10110;
        Ok(Self {
            peer,
            framed,
            peer_caps,
            session_id,
            next_message_id,
            yang_library: None,
        })
    }

    pub async fn rpc(
        &mut self,
        operation: RpcOperation,
    ) -> Result<Box<str>, NetConfSshClientError> {
        let message_id = self.next_message_id().to_string().into_boxed_str();
        let rpc = Rpc::new(message_id.clone(), operation);
        if tracing::enabled!(tracing::Level::TRACE) {
            tracing::trace!(
                "[{}] Sending RPC Request with message id `{}` and payload `{rpc:?}`",
                self.peer,
                message_id
            );
        }
        self.framed.send(NetConfMessage::Rpc(rpc)).await?;
        Ok(message_id)
    }

    pub async fn rpc_reply(&mut self) -> Result<RpcReply, NetConfSshClientError> {
        let msg = self.framed.next().await;
        if tracing::enabled!(tracing::Level::TRACE) {
            tracing::trace!("[{}] Received NETCONF message: `{msg:?}`", self.peer);
        }
        match msg {
            None => {
                tracing::warn!("[{}] Broken connection", self.peer);
                Err(NetConfSshClientError::SshError(russh::Error::IO(
                    io::Error::new(io::ErrorKind::BrokenPipe, "No response from the server"),
                )))
            }
            Some(Ok(NetConfMessage::RpcReply(reply))) => Ok(reply),
            Some(Ok(NetConfMessage::Hello(hello))) => {
                Err(NetConfSshClientError::UnexpectedMessage {
                    expected: "<rpc-reply>".to_string(),
                    actual: NetConfMessage::Hello(hello),
                })
            }
            Some(Ok(NetConfMessage::Rpc(rpc))) => Err(NetConfSshClientError::UnexpectedMessage {
                expected: "<rpc-reply>".to_string(),
                actual: NetConfMessage::Rpc(rpc),
            }),
            Some(Err(e)) => Err(e.into()),
        }
    }

    pub async fn close(mut self) -> Result<(), NetConfSshClientError> {
        let message_id = self.next_message_id.to_string().into_boxed_str();
        tracing::debug!(
            "[{}] sending close message RPC with id `{message_id}`",
            self.peer
        );
        self.framed
            .send(NetConfMessage::Rpc(Rpc::new(
                message_id,
                RpcOperation::Raw("<close-session/>".into()),
            )))
            .await?;
        let reply = self.rpc_reply().await?;
        if reply.reply().is_ok() {
            tracing::debug!("[{}] received ok response to close connection", self.peer);
        } else {
            tracing::warn!(
                "[{}] received unexpected response to close connection: {reply:?}",
                self.peer
            );
            return Err(NetConfSshClientError::UnexpectedMessage {
                expected: "ok".to_string(),
                actual: NetConfMessage::RpcReply(reply),
            });
        }
        self.framed.close().await?;
        tracing::info!("[{}] gracefully closed connection", self.peer);
        Ok(())
    }

    /// Get YANG schema from the device
    pub async fn get_schema(
        &mut self,
        name: &str,
        version: Option<&str>,
    ) -> Result<Box<str>, NetConfSshClientError> {
        tracing::debug!(
            "[{}] Getting a YANG schema with name `{name}` and version {version:?}",
            self.peer
        );
        let rpc = RpcOperation::WellKnown(WellKnownOperation::GetSchema {
            identifier: name.into(),
            version: version.map(Into::into),
            format: Some(YangSchemaFormat::Yang),
        });
        let message_id = self.rpc(rpc).await?;
        let rpc_reply = self.rpc_reply().await?;
        self.validate_message_id(&message_id, &rpc_reply)?;

        if let Some(RpcResponse::WellKnown(WellKnownRpcResponse::YangSchema { .. })) =
            rpc_reply.reply().responses()
        {
            // Some logic to unwrap the response without cloning the schema
            let reply_content: RpcReplyContent = rpc_reply.into();
            let rpc_response: RpcResponse =
                Into::<Option<RpcResponse>>::into(reply_content).unwrap();
            if let RpcResponse::WellKnown(WellKnownRpcResponse::YangSchema { schema }) =
                rpc_response
            {
                return Ok(schema);
            } else {
                unreachable!()
            }
        }
        Err(NetConfSshClientError::UnexpectedMessage {
            expected: "YANG schema".to_string(),
            actual: NetConfMessage::RpcReply(rpc_reply),
        })
    }

    /// Get the YANG Library of the device.
    ///
    /// Caching is used to avoid multiple requests to the device.
    pub async fn get_yang_library(&mut self) -> Result<Arc<YangLibrary>, NetConfSshClientError> {
        // Return cached version if any
        if let Some(lib) = self.yang_library() {
            return Ok(lib);
        }
        let message_id = self
            .rpc(RpcOperation::WellKnown(WellKnownOperation::GetYangLibrary))
            .await?;
        let rpc_reply = self.rpc_reply().await?;
        self.validate_message_id(&message_id, &rpc_reply)?;
        if let Some(RpcResponse::WellKnown(WellKnownRpcResponse::YangLibrary { .. })) =
            rpc_reply.reply().responses()
        {
            // Some logic to unwrap the response without cloning the response
            let reply_content: RpcReplyContent = rpc_reply.into();
            let rpc_response: RpcResponse =
                Into::<Option<RpcResponse>>::into(reply_content).unwrap();
            if let RpcResponse::WellKnown(WellKnownRpcResponse::YangLibrary(library)) = rpc_response
            {
                return Ok(library);
            } else {
                unreachable!()
            }
        }
        Err(NetConfSshClientError::UnexpectedMessage {
            expected: "YANG Library".to_string(),
            actual: NetConfMessage::RpcReply(rpc_reply),
        })
    }

    /// Helper to validate message ID matches between request and reply
    fn validate_message_id(
        &self,
        expected_id: &str,
        reply: &RpcReply,
    ) -> Result<(), NetConfSshClientError> {
        let received_id = reply.message_id().unwrap_or(expected_id);
        if expected_id != received_id {
            Err(NetConfSshClientError::UnexpectedMessage {
                expected: format!("<rpc-reply message-id=\"{expected_id}\">"),
                actual: NetConfMessage::RpcReply(reply.clone()),
            })
        } else {
            Ok(())
        }
    }

    /// Recursively load the dependency graph from a list of seed YANG modules,
    /// then connect to the Device via NETCONF to load all the dependencies,
    /// including the imports/include and  modules that deviate or augment any
    /// of the modules in the dependency graph.
    pub async fn load_from_modules(
        &mut self,
        seed: &[&str],
        checker: &impl BackwardCompatibilityChecker,
    ) -> Result<(YangLibrary, HashMap<Box<str>, Box<str>>), NetConfSshClientError> {
        let default_name: Box<str> = "ALL".into();

        let mut builder = ModuleSetBuilder::new(default_name.clone());
        let mut to_process: VecDeque<ModuleType> = VecDeque::new();
        let mut visited: HashSet<String> = HashSet::new();

        // Get YANG Library once
        let yang_lib = self.get_yang_library().await?;

        // Add seed modules to the process queue
        for name in seed {
            if let Some(module) = yang_lib.find_module(name) {
                to_process.push_back(ModuleType::Full(module.clone()));
            } else if let Some(module) = yang_lib.find_import_module(name) {
                for module in module {
                    to_process.push_back(ModuleType::ImportOnly(module.clone()));
                }
            } else {
                Err(NetConfSshClientError::DependencyError(
                    DependencyError::ModuleNotFound {
                        module_name: name.to_string(),
                    },
                ))?;
            }
        }

        // Process modules breadth-first
        while let Some(module) = to_process.pop_front() {
            // Skip if already processed
            if visited.contains(module.name()) {
                continue;
            }
            visited.insert(module.name().to_string());

            // Fetch the YANG schema
            let schema = self.get_schema(module.name(), module.revision()).await?;
            // Parse dependencies from schema
            let deps = extract_yang_dependencies(&schema).map_err(|error| {
                NetConfSshClientError::YangSchemaParsingError {
                    name: module.name().to_string(),
                    error,
                }
            })?;

            // Add imports
            for import in &deps.imports {
                if let Some(dep_module) = yang_lib.find_module(&import.module_name) {
                    if !visited.contains(dep_module.name()) {
                        to_process.push_back(ModuleType::Full(dep_module.clone()));
                    }
                } else if let Some(dep_modules) = yang_lib.find_import_module(&import.module_name) {
                    for dep_module in dep_modules {
                        if !visited.contains(dep_module.name()) {
                            to_process.push_back(ModuleType::ImportOnly(dep_module.clone()));
                        }
                    }
                }
            }

            // Add includes
            for include in &deps.includes {
                if let Some(dep_module) = yang_lib.find_module(&include.submodule_name) {
                    if !visited.contains(dep_module.name()) {
                        to_process.push_back(ModuleType::Full(dep_module.clone()));
                    }
                } else if let Some(dep_module) = yang_lib.find_submodule(&include.submodule_name)
                    && !visited.contains(dep_module.name())
                {
                    if matches!(module, ModuleType::Full(_))
                        || matches!(module, ModuleType::FullSubmodule(_, _))
                    {
                        to_process.push_back(ModuleType::FullSubmodule(
                            module.name().into(),
                            dep_module.clone(),
                        ));
                    } else {
                        to_process.push_back(ModuleType::ImportOnlySubmodule(
                            module.name().into(),
                            dep_module.clone(),
                        ));
                    }
                }
            }

            // Add deviations
            for deviation_name in module.deviations() {
                if let Some(dev_module) = yang_lib.find_module(deviation_name)
                    && !visited.contains(dev_module.name())
                {
                    to_process.push_back(ModuleType::Full(dev_module.clone()));
                }
            }

            // Add augmentations
            for augmentation_name in module.augmented_by() {
                if let Some(augmented_by) = yang_lib.find_module(augmentation_name)
                    && !visited.contains(augmented_by.name())
                {
                    to_process.push_back(ModuleType::Full(augmented_by.clone()));
                }
            }
            match module {
                ModuleType::Full(module) => {
                    builder
                        .add_module(module, schema, checker)
                        .map_err(NetConfSshClientError::DependencyError)?;
                }
                ModuleType::FullSubmodule(module_name, submodule) => {
                    builder
                        .add_submodule_for_module(module_name.as_ref(), submodule, schema, checker)
                        .map_err(NetConfSshClientError::DependencyError)?;
                }
                ModuleType::ImportOnly(module) => {
                    builder
                        .add_import_only_module(module, schema, checker)
                        .map_err(NetConfSshClientError::DependencyError)?;
                }
                ModuleType::ImportOnlySubmodule(module_name, submodule) => {
                    builder
                        .add_submodule_for_import_only_module(
                            module_name.as_ref(),
                            submodule,
                            schema,
                            checker,
                        )
                        .map_err(NetConfSshClientError::DependencyError)?;
                }
            }
        }

        let (yang_lib, schemas) = builder.build_yang_lib();
        Ok((yang_lib, schemas))
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
enum ModuleType {
    Full(Module),
    FullSubmodule(Box<str>, Submodule),
    ImportOnly(ImportOnlyModule),
    ImportOnlySubmodule(Box<str>, Submodule),
}
impl ModuleType {
    const fn name(&self) -> &str {
        match self {
            ModuleType::Full(module) => module.name(),
            ModuleType::FullSubmodule(_, submodule) => submodule.name(),
            ModuleType::ImportOnly(module) => module.name(),
            ModuleType::ImportOnlySubmodule(_, submodule) => submodule.name(),
        }
    }

    fn revision(&self) -> Option<&str> {
        match self {
            ModuleType::Full(module) => module.revision(),
            ModuleType::FullSubmodule(_, submodule) => submodule.revision(),
            ModuleType::ImportOnly(module) => module.revision(),
            ModuleType::ImportOnlySubmodule(_, submodule) => submodule.revision(),
        }
    }

    const fn deviations(&self) -> &[Box<str>] {
        match self {
            ModuleType::Full(module) => module.deviations(),
            ModuleType::FullSubmodule(_, _) => &[],
            ModuleType::ImportOnly(_) => &[],
            ModuleType::ImportOnlySubmodule(_, _) => &[],
        }
    }

    const fn augmented_by(&self) -> &[Box<str>] {
        match self {
            ModuleType::Full(module) => module.augmented_by(),
            ModuleType::FullSubmodule(_, _) => &[],
            ModuleType::ImportOnly(_) => &[],
            ModuleType::ImportOnlySubmodule(_, _) => &[],
        }
    }
}
