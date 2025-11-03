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

//! This module provides functionality for:
//!
//! - Classifying options data records by type (Sampling, Interface, VRF)
//! - Normalizing records into enrichment-ready format
//! - Converting records to enrichment operations

use crate::flow::types::{FieldRefLookup, IndexedDataRecord};
use netgauze_flow_pkt::{
    ie::{netgauze, Field, IE},
    ipfix,
};
use std::string::ToString;
use tracing::debug;

#[derive(strum_macros::Display, Debug, Clone, PartialEq, Eq)]
pub enum OptionsDataRecordError {
    #[strum(to_string = "DataRecord has no scope fields: not an Options Data Record")]
    NoScopeFields,
    #[strum(to_string = "Unsupported interface options data record format")]
    UnsupportedInterfaceType,
    #[strum(to_string = "Unsupported VRF options data record format")]
    UnsupportedVrfType,
    #[strum(to_string = "Missing required fields for {record_type}")]
    MissingRequiredFields { record_type: String },
}

impl std::error::Error for OptionsDataRecordError {}

/// Classified options data record
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptionsDataRecord {
    Sampling(IndexedDataRecord),

    Interface(IndexedDataRecord),

    Vrf(IndexedDataRecord),

    Unclassified(IndexedDataRecord),
}

impl TryFrom<ipfix::DataRecord> for OptionsDataRecord {
    type Error = OptionsDataRecordError;

    fn try_from(record: ipfix::DataRecord) -> Result<Self, Self::Error> {
        if record.scope_fields().is_empty() {
            return Err(OptionsDataRecordError::NoScopeFields);
        }

        let record: IndexedDataRecord = record.into();
        Ok(Self::classify(record))
    }
}

impl From<OptionsDataRecord> for ipfix::DataRecord {
    fn from(record: OptionsDataRecord) -> Self {
        match record {
            OptionsDataRecord::Sampling(record) => record.into(),
            OptionsDataRecord::Interface(record) => record.into(),
            OptionsDataRecord::Vrf(record) => record.into(),
            OptionsDataRecord::Unclassified(record) => record.into(),
        }
    }
}

impl OptionsDataRecord {
    /// Classify an indexed data record into a specific options type
    fn classify(record: IndexedDataRecord) -> Self {
        if Self::is_sampling_type(&record) {
            debug!("Sampling option data record found");
            Self::Sampling(record)
        } else if Self::is_interface_type(&record) {
            debug!("Interface option data record found");
            Self::Interface(record)
        } else if Self::is_vrf_type(&record) {
            debug!("VRF option data record found");
            Self::Vrf(record)
        } else {
            Self::Unclassified(record)
        }
    }

    /// Check if a record contains sampling-related information elements
    fn is_sampling_type(record: &IndexedDataRecord) -> bool {
        let has_sampling_interval = record.contains_ie(IE::samplingInterval);
        let has_sampler_random_interval = record.contains_ie(IE::samplerRandomInterval);
        let has_sampling_packet_interval = record.contains_ie(IE::samplingPacketInterval);
        let has_sampling_packet_space = record.contains_ie(IE::samplingPacketSpace);
        let has_sampling_time_interval = record.contains_ie(IE::samplingTimeInterval);
        let has_sampling_time_space = record.contains_ie(IE::samplingTimeSpace);
        let has_sampling_size = record.contains_ie(IE::samplingSize);
        let has_sampling_population = record.contains_ie(IE::samplingPopulation);
        let has_sampling_probability = record.contains_ie(IE::samplingProbability);

        has_sampling_interval
            || has_sampler_random_interval
            || (has_sampling_packet_interval && has_sampling_packet_space)
            || (has_sampling_time_interval && has_sampling_time_space)
            || (has_sampling_size && has_sampling_population)
            || has_sampling_probability
    }

    /// Normalize sampling records by filtering and organizing fields
    fn normalize_sampling_type(record: IndexedDataRecord) -> Vec<IndexedDataRecord> {
        let mut records = Vec::new();

        let (scope_fields, fields) = record.into_parts();

        let scope_fields: Vec<Field> = scope_fields
            .into_values()
            .filter(|field| {
                !matches!(
                    field,
                    Field::paddingOctets(_) | Field::exportingProcessId(_) /* ignore to support
                                                                            * 6wind */
                )
            })
            .collect();

        let fields: Vec<Field> = fields
            .into_values()
            .filter(|field| !matches!(field, Field::paddingOctets(_)))
            .collect();

        records.push(IndexedDataRecord::new(&scope_fields, &fields));
        records
    }

    /// Check if a record contains interface mapping information
    fn is_interface_type(record: &IndexedDataRecord) -> bool {
        let has_ingress_interface = record.contains_ie(IE::ingressInterface);
        let has_egress_interface = record.contains_ie(IE::egressInterface);
        let has_interface_name = record.contains_ie(IE::interfaceName);
        let has_interface_description = record.contains_ie(IE::interfaceDescription);

        (has_ingress_interface || has_egress_interface)
            && (has_interface_name || has_interface_description)
    }

    /// Create a normalized interface record with ingress or egress specific
    /// fields
    fn create_interface_record(
        iface: &Field,
        add_scope: &[Field],
        iface_name: Option<&Field>,
        iface_desc: Option<&Field>,
    ) -> Option<IndexedDataRecord> {
        let mut scope_fields = vec![iface.clone()];
        scope_fields.extend_from_slice(add_scope);

        let mut fields = Vec::new();
        match iface {
            Field::ingressInterface(_) => {
                if let Some(Field::interfaceName(name)) = iface_name {
                    fields.push(Field::NetGauze(netgauze::Field::ingressInterfaceName(
                        name.clone(),
                    )));
                }
                if let Some(Field::interfaceDescription(desc)) = iface_desc {
                    fields.push(Field::NetGauze(
                        netgauze::Field::ingressInterfaceDescription(desc.clone()),
                    ));
                }
            }
            Field::egressInterface(_) => {
                if let Some(Field::interfaceName(name)) = iface_name {
                    fields.push(Field::NetGauze(netgauze::Field::egressInterfaceName(
                        name.clone(),
                    )));
                }
                if let Some(Field::interfaceDescription(desc)) = iface_desc {
                    fields.push(Field::NetGauze(
                        netgauze::Field::egressInterfaceDescription(desc.clone()),
                    ));
                }
            }
            _ => return None,
        }

        if !fields.is_empty() {
            Some(IndexedDataRecord::new(&scope_fields, &fields))
        } else {
            None
        }
    }

    /// Normalize interface records into separate ingress/egress mappings
    ///
    /// Creates separate records for ingress and egress interfaces when
    /// they share the same interface ID, mapping to specific ingress/egress
    /// interface name and description fields.
    fn normalize_interface_type(
        record: IndexedDataRecord,
    ) -> Result<Vec<IndexedDataRecord>, OptionsDataRecordError> {
        let in_iface = record.get_by_ie(IE::ingressInterface);
        let out_iface = record.get_by_ie(IE::egressInterface);
        let iface_name = record.fields().get_by_ie(IE::interfaceName);
        let iface_desc = record.fields().get_by_ie(IE::interfaceDescription);

        let add_scope: Vec<_> = record
            .scope_fields()
            .values()
            .filter(|field| {
                !matches!(
                    field,
                    Field::ingressInterface(_)
                        | Field::egressInterface(_)
                        | Field::paddingOctets(_)
                        | Field::exportingProcessId(_) // ignore to support 6wind
                )
            })
            .cloned()
            .collect();

        let mut records = Vec::new();
        match (in_iface, out_iface) {
            (
                Some(in_iface @ Field::ingressInterface(in_id)),
                Some(out_iface @ Field::egressInterface(out_id)),
            ) if in_id == out_id => {
                // Both interfaces with matching IDs - create both records
                records.extend(Self::create_interface_record(
                    in_iface, &add_scope, iface_name, iface_desc,
                ));
                records.extend(Self::create_interface_record(
                    out_iface, &add_scope, iface_name, iface_desc,
                ));
            }
            (Some(iface @ Field::ingressInterface(_)), None) => {
                // Only ingress interface
                records.extend(Self::create_interface_record(
                    iface, &add_scope, iface_name, iface_desc,
                ));
            }
            (None, Some(iface @ Field::egressInterface(_))) => {
                // Only egress interface
                records.extend(Self::create_interface_record(
                    iface, &add_scope, iface_name, iface_desc,
                ));
            }
            _ => {
                return Err(OptionsDataRecordError::UnsupportedInterfaceType);
            }
        }

        if records.is_empty() {
            return Err(OptionsDataRecordError::MissingRequiredFields {
                record_type: "interface".to_string(),
            });
        }

        Ok(records)
    }

    /// Check if a record contains VRF mapping information
    fn is_vrf_type(record: &IndexedDataRecord) -> bool {
        let has_ingress_vrfid = record.contains_ie(IE::ingressVRFID);
        let has_egress_vrfid = record.contains_ie(IE::egressVRFID);
        let has_vrf_name = record.contains_ie(IE::VRFname);
        let has_rd = record.contains_ie(IE::mplsVpnRouteDistinguisher);

        (has_ingress_vrfid || has_egress_vrfid) && (has_vrf_name || has_rd)
    }

    /// Create a normalized vrf record with ingress or egress specific fields
    fn create_vrf_record(
        vrf: &Field,
        add_scope: &[Field],
        vrf_name: Option<&Field>,
        rd: Option<&Field>,
    ) -> Option<IndexedDataRecord> {
        let mut scope_fields = vec![vrf.clone()];
        scope_fields.extend_from_slice(add_scope);

        let mut fields = Vec::new();
        match vrf {
            Field::ingressVRFID(_) => {
                if let Some(Field::VRFname(name)) = vrf_name {
                    fields.push(Field::NetGauze(netgauze::Field::ingressVRFname(
                        name.clone(),
                    )));
                }
                if let Some(Field::mplsVpnRouteDistinguisher(rd_val)) = rd {
                    fields.push(Field::NetGauze(
                        netgauze::Field::ingressMplsVpnRouteDistinguisher(rd_val.clone()),
                    ));
                }
            }
            Field::egressVRFID(_) => {
                if let Some(Field::VRFname(name)) = vrf_name {
                    fields.push(Field::NetGauze(netgauze::Field::egressVRFname(
                        name.clone(),
                    )));
                }
                if let Some(Field::mplsVpnRouteDistinguisher(rd_val)) = rd {
                    fields.push(Field::NetGauze(
                        netgauze::Field::egressMplsVpnRouteDistinguisher(rd_val.clone()),
                    ));
                }
            }
            _ => return None,
        }

        if !fields.is_empty() {
            Some(IndexedDataRecord::new(&scope_fields, &fields))
        } else {
            None
        }
    }

    /// Normalize VRF records into separate ingress/egress mappings
    ///
    /// Creates separate records for ingress and egress VRFs when they
    /// share the same VRF ID, mapping to specific ingress/egress VRF name
    /// and route distinguisher fields.
    fn normalize_vrf_type(
        record: IndexedDataRecord,
    ) -> Result<Vec<IndexedDataRecord>, OptionsDataRecordError> {
        let in_vrf = record.get_by_ie(IE::ingressVRFID);
        let out_vrf = record.get_by_ie(IE::egressVRFID);
        let vrf_name = record.fields().get_by_ie(IE::VRFname);
        let rd = record.fields().get_by_ie(IE::mplsVpnRouteDistinguisher);

        let add_scope: Vec<_> = record
            .scope_fields()
            .values()
            .filter(|field| {
                !matches!(
                    field,
                    Field::ingressVRFID(_)
                        | Field::egressVRFID(_)
                        | Field::paddingOctets(_)
                        | Field::exportingProcessId(_) // ignore to support 6wind
                )
            })
            .cloned()
            .collect();

        let mut records = Vec::new();
        match (in_vrf, out_vrf) {
            (
                Some(in_vrf @ Field::ingressVRFID(in_id)),
                Some(out_vrf @ Field::egressVRFID(out_id)),
            ) if in_id == out_id => {
                // Both VRFs with matching IDs - create both records
                records.extend(Self::create_vrf_record(in_vrf, &add_scope, vrf_name, rd));
                records.extend(Self::create_vrf_record(out_vrf, &add_scope, vrf_name, rd));
            }
            (Some(vrf @ Field::ingressVRFID(_)), None) => {
                // Single ingress VRF
                records.extend(Self::create_vrf_record(vrf, &add_scope, vrf_name, rd));
            }
            (None, Some(vrf @ Field::egressVRFID(_))) => {
                // Single egress VRF
                records.extend(Self::create_vrf_record(vrf, &add_scope, vrf_name, rd));
            }
            _ => {
                return Err(OptionsDataRecordError::UnsupportedVrfType);
            }
        }

        if records.is_empty() {
            return Err(OptionsDataRecordError::MissingRequiredFields {
                record_type: "VRF".to_string(),
            });
        }

        Ok(records)
    }

    /// Normalize unclassified records by filtering out some IEs
    fn normalize_unclassified_type(record: IndexedDataRecord) -> IndexedDataRecord {
        let (scope_fields, fields) = record.into_parts();

        let scope_fields: Vec<Field> = scope_fields
            .into_values()
            .filter(|field| {
                !matches!(
                    field,
                    Field::paddingOctets(_) | Field::exportingProcessId(_) /* ignore to support
                                                                            * 6wind */
                )
            })
            .collect();

        let fields: Vec<Field> = fields
            .into_values()
            .filter(|field| !matches!(field, Field::paddingOctets(_)))
            .collect();

        IndexedDataRecord::new(&scope_fields, &fields)
    }

    /// Normalize this OptionsDataRecord into one or more IndexedDataRecord(s)
    pub fn into_normalized_records(self) -> Result<Vec<IndexedDataRecord>, OptionsDataRecordError> {
        match self {
            OptionsDataRecord::Sampling(record) => Ok(Self::normalize_sampling_type(record)),
            OptionsDataRecord::Interface(record) => Self::normalize_interface_type(record),
            OptionsDataRecord::Vrf(record) => Self::normalize_vrf_type(record),
            OptionsDataRecord::Unclassified(record) => {
                Ok(vec![Self::normalize_unclassified_type(record)])
            }
        }
    }
}

#[cfg(test)]
mod tests;
