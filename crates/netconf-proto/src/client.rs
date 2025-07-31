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
    capabilities::{Base, Capability, CapabilityImpl, YangLibrary},
    protocol::{Hello, NetConfMessage, Rpc, RpcReply, RpcReplyValue},
};
use futures::{SinkExt, StreamExt};
use std::{collections::HashMap, fmt::Debug};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Decoder, Encoder, Framed};
use yang3::{
    context::{Context, ContextFlags},
    data::{DataFormat, DataOperation, DataTree},
};

#[derive(Debug)]
pub enum SshNetConfClientError<E: std::error::Error + Debug> {
    UnexpectedMessage {
        expecting: String,
        received: String,
    },
    /// RFC 6241: A NETCONF server must send a session-id in the hello message.
    SessionIdNotIncluded,
    YangError(yang3::Error),
    CodecError(E),
}

impl<E: std::error::Error + Debug> From<yang3::Error> for SshNetConfClientError<E> {
    fn from(err: yang3::Error) -> Self {
        SshNetConfClientError::YangError(err)
    }
}

impl<E: std::error::Error + Debug> std::fmt::Display for SshNetConfClientError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedMessage {
                expecting,
                received,
            } => {
                write!(
                    f,
                    "unexpected message: received `{received}` while expecting: `{expecting}`"
                )
            }
            Self::YangError(e) => write!(f, "Yang error: {e}"),
            Self::SessionIdNotIncluded => {
                write!(f, "session id not included in the server's hello message")
            }
            Self::CodecError(e) => write!(f, "Codec error: {e}"),
        }
    }
}

impl<E: std::error::Error> std::error::Error for SshNetConfClientError<E> {}

/// High-level NETCONF client
pub struct NetConfClient<
    E: From<std::io::Error> + std::error::Error + Send + Sync + 'static,
    T: AsyncRead + AsyncWrite,
    C: Decoder<Item = NetConfMessage, Error = E> + Encoder<NetConfMessage, Error = E>,
> {
    /// Bidirectional channel to the NETCONF peer
    framed: Framed<T, C>,

    /// Capabilities announced by the NETCONF peer
    peer_caps: HashMap<Box<str>, Capability>,

    /// Session ID assigned by the NETCONF peer
    session_id: u32,

    /// libyang validation context
    ctx: Context,

    /// Keep track of the message IDs sent to the peer
    next_message_id: u32,
}

impl<
        E: From<std::io::Error> + std::error::Error + Send + Sync + Debug + 'static,
        T: AsyncRead + AsyncWrite + Unpin,
        C: Decoder<Item = NetConfMessage, Error = E> + Encoder<NetConfMessage, Error = E>,
    > NetConfClient<E, T, C>
{
    pub const fn session_id(&self) -> u32 {
        self.session_id
    }

    pub const fn peer_capabilities(&self) -> &HashMap<Box<str>, Capability> {
        &self.peer_caps
    }

    pub async fn connect(
        framed: Framed<T, C>,
        yang_search_dir: String,
    ) -> Result<Self, SshNetConfClientError<E>> {
        tracing::info!("Waiting for hello message");
        let (mut framed, session_id, mut peer_caps) = Self::recv_hello(framed).await?;
        peer_caps.remove(&Capability::Base(Base::V1_0).shorthand());
        peer_caps.remove(&Capability::Base(Base::V1_0).urn());
        tracing::info!("Hello message received and processed");
        tracing::info!("Sending hello back");
        framed
            .send(NetConfMessage::Hello(Hello {
                session_id: Some(session_id),
                capabilities: peer_caps.clone(),
            }))
            .await
            .map_err(|e| SshNetConfClientError::CodecError(e))?;

        Self::init_yang_context(&mut framed, &peer_caps).await?;

        tracing::info!("Starting new YANG context");
        let mut ctx = Context::new(ContextFlags::NO_YANGLIBRARY)?;
        tracing::info!("Context created");
        ctx.set_searchdir(yang_search_dir)?;
        tracing::info!("Search dir set");
        ctx.load_module(
            "ietf-netconf",
            Some("2011-06-01"),
            &[
                "writable-running",
                "candidate",
                "confirmed-commit",
                "rollback-on-error",
                "validate",
                "startup",
                "url",
                "xpath",
            ],
        )
        .expect("Failed to load module");

        ctx.load_module("ietf-yang-library", Some("2019-01-04"), &[])
            .expect("Failed to load module");
        ctx.load_module("ietf-datastores", Some("2018-02-14"), &[])
            .expect("Failed to load module");
        tracing::info!("Loaded modules");

        Ok(Self {
            framed,
            peer_caps,
            session_id,
            ctx,
            next_message_id: 1,
        })
    }

    async fn recv_hello(
        mut framed: Framed<T, C>,
    ) -> Result<(Framed<T, C>, u32, HashMap<Box<str>, Capability>), SshNetConfClientError<E>> {
        // Wait for hello message from the server
        let next_msg = loop {
            tracing::info!("Receiving hello message");
            let next_msg = framed.next().await;
            tracing::info!("GOT {:?}", next_msg);
            if let Some(msg) = next_msg {
                break msg;
            }
        };
        match next_msg {
            Ok(NetConfMessage::Hello(hello)) => {
                let session_id = if let Some(id) = hello.session_id {
                    id
                } else {
                    return Err(SshNetConfClientError::SessionIdNotIncluded);
                };
                Ok((framed, session_id, hello.capabilities.clone()))
            }
            Ok(msg) => Err(SshNetConfClientError::UnexpectedMessage {
                expecting: "hello".to_string(),
                received: format!("{msg:?}"),
            }),
            Err(err) => Err(SshNetConfClientError::CodecError(err)),
        }
    }

    async fn init_yang_context(
        framed: &mut Framed<T, C>,
        capabilities: &HashMap<Box<str>, Capability>,
    ) -> Result<Context, SshNetConfClientError<E>> {
        let mut known = HashMap::new();
        for (key, cap) in capabilities {
            if !matches!(cap, Capability::Unknown(_)) {
                known.insert(key.clone(), cap.clone());
            } else {
                tracing::info!("CAPABILITY: `{key}`: `{cap:?}`");
            }
        }
        tracing::info!("---- KNOWN CAPABILITIES --------");
        for (key, cap) in &known {
            tracing::info!("CAPABILITY: `{key}`: `{cap:?}`");
        }

        if !capabilities.contains_key(":ietf-yang-library") {
            todo!("YANG LIBRARY NOT SUPPORTED BY THE ROUTER")
        };
        let yang_library_request = r#"<get-schema xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring"><identifier>ietf-ip</identifier></get-schema>"#.to_string();
        framed
            .send(NetConfMessage::Rpc(Rpc {
                message_id: "10100".to_string(),
                operation: yang_library_request,
            }))
            .await
            .unwrap();
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        while let next = framed.next().await {
            match next {
                Some(msg) => match msg {
                    Ok(NetConfMessage::RpcReply(reply)) => {
                        todo!("GOT REPLY: {:?}", reply);
                    }
                    Ok(msg) => {
                        tracing::info!("Got REPLY: {:?}", msg);
                        todo!("INVALID reply")
                    }
                    Err(err) => {
                        todo!("GOT INVALID reply: {err}")
                    }
                },
                None => {
                    eprintln!("Channel closed");
                    break;
                    //tokio::time::sleep(tokio::time::Duration::from_secs(1)).
                    // await;
                }
            }
        }
        if !capabilities.contains_key(":yang-library:1.1")
            && !capabilities.contains_key(":ietf-yang-library")
        {
            todo!("YANG LIBRARY not supported ")
        };
        framed
            .send(NetConfMessage::Rpc(Rpc {
                message_id: "urn:uuid:2b780556-86e9-4475-af65-8298ef1c0e73".to_string(),
                operation: r#"
    <get>
      <filter type="subtree">
        <yang-library xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-library">
        </yang-library>
        <modules-state xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-library">
        </modules-state>
      </filter>
    </get>"#
                    .to_string(),
            }))
            .await
            .expect("Failed to send RPC message");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let mut count = 0;
        loop {
            let msg = framed.next().await;
            let msg = if let Some(msg) = msg {
                msg
            } else {
                count += 1;
                if count > 120 {
                    todo!("too many retries")
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            };
            tracing::info!("GOT {:?}", msg);
            let msg = msg.expect("Failed to receive yang library message");
            let reply = if let NetConfMessage::RpcReply(reply) = msg {
                reply
            } else {
                tracing::error!("Received unexpected message");
                todo!()
            };
            let value = if let RpcReplyValue::Data(err, resp) = reply.reply {
                resp
            } else {
                tracing::error!("Received unexpected reply");
                todo!()
            };
            todo!("Finish libyang context: {value}")
        }
    }

    pub async fn send(
        &mut self,
        msg: NetConfMessage,
    ) -> Result<Option<RpcReply>, SshNetConfClientError<E>> {
        match &msg {
            NetConfMessage::Hello(_) => {
                self.framed
                    .send(msg)
                    .await
                    .map_err(|e| SshNetConfClientError::CodecError(e))?;
                Ok(None)
            }
            NetConfMessage::Rpc(_) => {
                self.framed
                    .send(msg)
                    .await
                    .map_err(|e| SshNetConfClientError::CodecError(e))?;
                loop {
                    let next_msg = self.framed.next().await;
                    match next_msg {
                        None => continue,
                        Some(Ok(NetConfMessage::RpcReply(reply))) => {
                            return Ok(Some(reply));
                        }
                        Some(Ok(msg)) => {
                            return Err(SshNetConfClientError::UnexpectedMessage {
                                expecting: "RpcReply".to_string(),
                                received: format!("{msg:?}"),
                            })
                        }
                        Some(Err(err)) => {
                            return Err(SshNetConfClientError::CodecError(err));
                        }
                    }
                }
            }
            NetConfMessage::RpcReply(_) => {
                self.framed
                    .send(msg)
                    .await
                    .map_err(|e| SshNetConfClientError::CodecError(e))?;
                Ok(None)
            }
        }
    }

    pub async fn get_yang_lib(&mut self) -> anyhow::Result<DataTree<'_>> {
        if let Some(Capability::YangLibrary(YangLibrary::V1_1 {
            revision: _,
            content_id,
        })) = self.peer_caps.get(&Box::from(":yang-library:1.1"))
        {
            let content_id = content_id.parse::<u32>()?;
            eprintln!("content id {content_id:#x}");
            let operation = "<get><filter type=\"subtree\"><yang-library xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-library\"></yang-library></filter></get>".to_string();
            self.next_message_id += 1;
            let message_id = format!("{}", self.next_message_id);

            self.framed
                .send(NetConfMessage::Rpc(Rpc {
                    message_id: "urn:uuid:2b780556-86e9-4475-af65-8298ef1c0e76".to_string(),
                    operation,
                }))
                .await?;
        }
        if let Some(Ok(NetConfMessage::RpcReply(value))) = self.framed.next().await {
            match value.reply {
                RpcReplyValue::Ok => Err(anyhow::anyhow!("Received unexpected message")),
                RpcReplyValue::Data(_, value) => {
                    eprintln!("received data: `{value}`");
                    let dtree = DataTree::parse_op_string(
                        &self.ctx,
                        value,
                        DataFormat::XML,
                        DataOperation::ReplyYang, /* DataParserFlags::NO_VALIDATION,
                                                   * DataValidationFlags::empty(), */
                    )?;
                    for dnode in dtree.traverse() {
                        eprintln!("{dnode:?}");
                    }
                    //let x = dtree.find_path("/data")?.tree();
                    Ok(dtree)
                }
            }
        } else {
            Err(anyhow::anyhow!("Received unexpected message"))
        }
    }
}
