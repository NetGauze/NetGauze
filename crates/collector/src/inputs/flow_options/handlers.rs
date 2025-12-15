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

use crate::flow::enrichment::{EnrichmentOperation, Scope, UpsertPayload};
use crate::flow::types::IndexedDataRecord;
use crate::inputs::InputProcessingError;
use crate::inputs::flow_options::normalize::OptionsDataRecord;
use std::net::IpAddr;

/// **Generic Flow Options Handler Trait**
///
/// Trait for handling a flow options data record
pub trait FlowOptionsHandler<T>: Send + Sync + 'static {
    /// Parse an [`OptionsDataRecord`] object into a vector of output type `T`
    fn handle_option_record(
        &mut self,
        option_record: OptionsDataRecord,
        peer_ip: IpAddr,
        obs_id: u32,
    ) -> Result<Vec<T>, InputProcessingError>;
}

/// **Flow Enrichment Options Handler**
///
/// Handler that converts IPFIX/NetFlow options data records into enrichment
/// operations for flow metadata caching.
#[derive(Debug, Clone)]
pub struct FlowEnrichmentOptionsHandler {
    weight: u8,
}

impl FlowEnrichmentOptionsHandler {
    pub fn new(weight: u8) -> Self {
        Self { weight }
    }
    pub fn weight(&self) -> u8 {
        self.weight
    }
}

impl FlowOptionsHandler<EnrichmentOperation> for FlowEnrichmentOptionsHandler {
    fn handle_option_record(
        &mut self,
        option_record: OptionsDataRecord,
        peer_ip: IpAddr,
        obs_id: u32,
    ) -> Result<Vec<EnrichmentOperation>, InputProcessingError> {
        let mut ops = Vec::new();

        let records = option_record.into_normalized_records().map_err(|e| {
            InputProcessingError::ConversionError {
                context: "EnrichmentOptionsHandler Normalization".to_string(),
                reason: e.to_string(),
            }
        })?;
        for rec in records {
            ops.push(upsert_from_rec(peer_ip, obs_id, self.weight(), &rec));
        }
        Ok(ops
            .into_iter()
            .filter(|op| op.validate()) // drop useless no-field ops
            .collect())
    }
}

/// Helper function to create an [`EnrichmentOperation`] of Upsert type
/// from an [`IndexedDataRecord`]
fn upsert_from_rec(
    peer_ip: IpAddr,
    obs_id: u32,
    weight: u8,
    record: &IndexedDataRecord,
) -> EnrichmentOperation {
    EnrichmentOperation::Upsert(UpsertPayload {
        ip: peer_ip,
        scope: Scope::new(
            obs_id,
            Some(record.scope_fields().values().cloned().collect()),
        ),
        weight,
        fields: record.fields().values().cloned().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use netgauze_flow_pkt::ie::Field;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_handle_option_record_sampling() {
        let mut handler = FlowEnrichmentOptionsHandler::new(16);

        let scope_fields = vec![Field::selectorId(42)];
        let fields = vec![Field::samplingInterval(1000)];

        let indexed_record = IndexedDataRecord::new(&scope_fields, &fields);
        let options_record = OptionsDataRecord::Sampling(indexed_record);

        let peer_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let obs_id = 100;

        let ops = handler
            .handle_option_record(options_record, peer_ip, obs_id)
            .unwrap();

        assert_eq!(ops.len(), 1);
        if let EnrichmentOperation::Upsert(payload) = &ops[0] {
            assert_eq!(payload.ip, peer_ip);
            assert_eq!(payload.weight, 16);
            assert_eq!(payload.scope.obs_domain_id(), obs_id);
        } else {
            panic!("Expected Upsert operation");
        }
    }

    #[test]
    fn test_handle_option_record_interface_matching_ids() {
        let mut handler = FlowEnrichmentOptionsHandler::new(16);

        let scope_fields = vec![Field::ingressInterface(1), Field::egressInterface(1)];
        let fields = vec![Field::interfaceName("eth0".to_string().into())];

        let indexed_record = IndexedDataRecord::new(&scope_fields, &fields);
        let options_record = OptionsDataRecord::Interface(indexed_record);

        let peer_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let obs_id = 200;

        let ops = handler
            .handle_option_record(options_record, peer_ip, obs_id)
            .unwrap();

        assert_eq!(ops.len(), 2); // Should create 2 operations (ingress +
        // egress)
    }

    #[test]
    fn test_handle_option_record_unclassified() {
        let mut handler = FlowEnrichmentOptionsHandler::new(10);

        let scope_fields = vec![Field::selectorId(1)];
        let fields = vec![Field::octetDeltaCount(1000)];

        let indexed_record = IndexedDataRecord::new(&scope_fields, &fields);
        let options_record = OptionsDataRecord::Unclassified(indexed_record);

        let peer_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let obs_id = 300;

        let ops = handler
            .handle_option_record(options_record, peer_ip, obs_id)
            .unwrap();

        assert_eq!(ops.len(), 1);
        if let EnrichmentOperation::Upsert(payload) = &ops[0] {
            assert_eq!(payload.weight, 10);
        }
    }
}
