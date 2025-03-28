use crate::flow::aggregation::{AggregationConfig, InputMessage};
use chrono::Utc;
use indexmap::IndexMap;
use netgauze_analytics::{
    aggregation::{Aggregator, TimeSeriesData},
    flow::{AggrOp, AggregationError},
};
use netgauze_flow_pkt::{ie, ipfix::IpfixPacket, FlatFlowDataInfo, FlowInfo};
use serde::{Deserialize, Serialize};
use std::{
    collections::{hash_map::Entry, HashMap},
    net::{IpAddr, Ipv4Addr, SocketAddr},
};
use tracing::error;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InputMessage2 {
    pub peer: SocketAddr,
    pub flow: FlowInfo,
}

impl InputMessage2 {
    fn reduce(
        &mut self,
        incoming: InputMessage2,
        transform: &IndexMap<ie::IE, AggrOp>,
    ) -> Result<(), AggregationError> {
        self.flow.reduce(incoming.flow, transform)?;
        Ok(())
    }
}

impl Default for InputMessage2 {
    fn default() -> Self {
        Self {
            peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            flow: FlowInfo::IPFIX(IpfixPacket::new(Utc::now(), 0, 0, Box::new([]))),
        }
    }
}

impl TimeSeriesData<String> for InputMessage2 {
    fn get_key(&self) -> String {
        self.peer.ip().to_string()
    }
    fn get_ts(&self) -> chrono::DateTime<chrono::Utc> {
        self.flow.export_time()
    }
}

impl From<(SocketAddr, FlowInfo)> for InputMessage2 {
    fn from((peer, flow): (SocketAddr, FlowInfo)) -> Self {
        Self { peer, flow }
    }
}

#[derive(Clone, Debug)]
pub struct FlowAggregator2 {
    pub cache: InputMessage2,
    pub config: AggregationConfig,
}

impl Aggregator<(InputMessage2, AggregationConfig), InputMessage2, InputMessage2>
    for FlowAggregator2
{
    fn init(init: (InputMessage2, AggregationConfig)) -> Self {
        let (cache, config) = init;
        Self { cache, config }
    }

    // TODO: extend to return Result<>
    fn push(&mut self, incoming: InputMessage2) {
        self.cache
            .reduce(incoming, &self.config.transform)
            .expect("Failed to reduce");
    }
    fn flush(self) -> InputMessage2 {
        self.cache
    }
}
