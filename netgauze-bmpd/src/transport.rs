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

use crate::TaggedData;
use futures_core::{Stream, TryStream};
use pin_project::pin_project;
use std::{
    fmt::Debug,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Decoder, FramedRead};

#[derive(Debug)]
#[pin_project]
pub struct TaggedFramedStream<
    RX: AsyncRead,
    TX: AsyncWrite,
    Tag: Copy,
    Data,
    Error,
    Codec: Decoder<Item = Data, Error = Error>,
> {
    tag: Tag,
    #[pin]
    framed: FramedRead<RX, Codec>,
    _tx: TX,
}

impl<
        RX: AsyncRead + Unpin,
        TX: AsyncWrite,
        Tag: Copy,
        Data,
        Error,
        Codec: Decoder<Item = Data, Error = Error>,
    > TaggedFramedStream<RX, TX, Tag, Data, Error, Codec>
{
    pub fn new(tag: Tag, framed: FramedRead<RX, Codec>, tx: TX) -> Self {
        Self {
            tag,
            framed,
            _tx: tx,
        }
    }

    pub const fn tag(&self) -> Tag {
        self.tag
    }
}

impl<
        RX: AsyncRead + Unpin,
        TX: AsyncWrite,
        Tag: Debug + Copy,
        Data,
        Error,
        Codec: Decoder<Item = Data, Error = Error>,
    > Stream for TaggedFramedStream<RX, TX, Tag, Data, Error, Codec>
where
    Self: Unpin,
{
    type Item = Result<TaggedData<Tag, Data>, TaggedData<Tag, Error>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let tag = self.tag;
        let this = self.project();
        let mut framed: Pin<_> = this.framed;
        framed.as_mut().try_poll_next(cx).map(|msg_option| {
            msg_option.map(|result| {
                result
                    .map(|msg| TaggedData::new(tag, msg))
                    .map_err(|err| TaggedData::new(tag, err))
            })
        })
    }
}
