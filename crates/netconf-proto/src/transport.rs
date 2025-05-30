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
    protocol::{Hello, NetConfMessage, Rpc, RpcReplyValue},
};
use futures::{SinkExt, StreamExt};
use std::collections::HashMap;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Decoder, Encoder, Framed};
use yang3::{
    context::{Context, ContextFlags},
    data::{DataFormat, DataOperation, DataTree},
};

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
        E: From<std::io::Error> + std::error::Error + Send + Sync + 'static,
        T: AsyncRead + AsyncWrite + Unpin,
        C: Decoder<Item = NetConfMessage, Error = E> + Encoder<NetConfMessage, Error = E>,
    > SshNetConfClient<E, T, C>
{
    pub fn new(framed: Framed<T, C>) -> Self {
        let mut ctx = Context::new(ContextFlags::NO_YANGLIBRARY).expect("Failed to create context");
        ctx.set_searchdir("../../assets/yang/")
            .expect("Failed to set YANG search directory");
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

        Self {
            framed,
            peer_caps: HashMap::new(),
            session_id: 0,
            ctx,
            next_message_id: 1,
        }
    }

    pub async fn hello(&mut self) -> anyhow::Result<()> {
        if let Some(Ok(NetConfMessage::Hello(value))) = self.framed.next().await {
            self.peer_caps = value.capabilities.clone();
            self.session_id = value.session_id.unwrap();
        } else {
            return Err(anyhow::anyhow!("Received unexpected message"));
        };
        self.framed
            .send(NetConfMessage::Hello(Hello {
                session_id: None,
                capabilities: self.peer_caps.clone(),
            }))
            .await?;
        Ok(())
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
