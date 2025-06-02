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
    capabilities::{Capability, YangLibrary},
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
            Self::CodecError(e) => write!(f, "Yang error: {e}"),
        }
    }
}

impl<E: std::error::Error + Debug> std::error::Error for SshNetConfClientError<E> {}

pub struct SshNetConfClient<
    E: From<std::io::Error> + std::error::Error + Send + Sync + 'static,
    T: AsyncRead + AsyncWrite,
    C: Decoder<Item = NetConfMessage, Error = E> + Encoder<NetConfMessage, Error = E>,
> {
    framed: Framed<T, C>,
    pub peer_caps: HashMap<Box<str>, Capability>,
    session_id: u32,
    ctx: Context,
    next_message_id: u32,
}

impl<
        E: From<std::io::Error> + std::error::Error + Send + Sync + Debug + 'static,
        T: AsyncRead + AsyncWrite + Unpin,
        C: Decoder<Item = NetConfMessage, Error = E> + Encoder<NetConfMessage, Error = E>,
    > SshNetConfClient<E, T, C>
{
    pub const fn session_id(&self) -> u32 {
        self.session_id
    }

    pub async fn connect(
        framed: Framed<T, C>,
        yang_search_dir: String,
    ) -> Result<Self, SshNetConfClientError<E>> {
        let (mut framed, session_id, peer_caps) = Self::recv_hello(framed).await?;

        framed
            .send(NetConfMessage::Hello(Hello {
                session_id: Some(session_id),
                capabilities: peer_caps.clone(),
            }))
            .await
            .map_err(|e| SshNetConfClientError::CodecError(e))?;

        let mut ctx = Context::new(ContextFlags::NO_YANGLIBRARY)?;
        ctx.set_searchdir(yang_search_dir)?;
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
            let next_msg = framed.next().await;
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
            let message_id = format!("{}", self.next_message_id);
            self.next_message_id += 1;
            self.framed
                .send(NetConfMessage::Rpc(Rpc {
                    message_id,
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
