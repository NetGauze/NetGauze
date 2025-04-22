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

use bytes::BytesMut;
use netgauze_pcap_reader::TransportProtocol;
use serde::Serialize;
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
};

#[derive(Debug, serde::Serialize)]
pub struct SerializableInfo<I> {
    pub(crate) source_address: SocketAddr,
    pub(crate) destination_address: SocketAddr,
    pub(crate) info: I,
}

#[derive(Debug, Serialize)]
pub enum DecodeOutcome<M, E> {
    Success(((IpAddr, u16, IpAddr, u16), M)),
    Error(E),
}

pub trait ProtocolHandler<Message, Codec, ErrorMessage>
where
    Codec: Default,
{
    fn decode(
        &self,
        flow_key: (IpAddr, u16, IpAddr, u16),
        protocol: TransportProtocol,
        packet_data: &[u8],
        exporter_peers: &mut HashMap<(IpAddr, u16, IpAddr, u16), (Codec, BytesMut)>,
    ) -> Option<Vec<DecodeOutcome<Message, ErrorMessage>>>;

    fn serialize(
        &self,
        data: DecodeOutcome<Message, ErrorMessage>,
    ) -> io::Result<serde_json::Value>;
}
