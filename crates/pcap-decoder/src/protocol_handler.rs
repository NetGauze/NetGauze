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
