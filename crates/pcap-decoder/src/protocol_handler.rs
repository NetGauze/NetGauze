use bytes::BytesMut;
use netgauze_pcap_reader::TransportProtocol;
use serde::Serialize;
use std::{
    collections::HashMap,
    io::Result,
    net::{IpAddr, SocketAddr},
};

#[derive(Debug, serde::Serialize)]
pub struct SerializableInfo<I> {
    pub(crate) info: I,
    pub(crate) source_address: SocketAddr,
}

#[derive(Debug, Serialize)]
pub enum DecodeOutcome<M, E> {
    Success((SocketAddr, M)),
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
        exporter_peers: &mut HashMap<
            (IpAddr, u16, IpAddr, u16),
            (Codec, BytesMut),
        >,
    ) -> Option<DecodeOutcome<Message, ErrorMessage>>;

    fn serialize(&self, data: DecodeOutcome<Message, ErrorMessage>) -> Result<String>;
}
