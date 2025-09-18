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

//! # Pmacct Maps Format Parsing Module
//!
//! This module provides functionality to parse pmacct map files and convert
//! them into NetGauze enrichment operations.
//!
//! ## Supported Map Types
//!
//! The parser supports the following types of pmacct map entries:
//!
//! - **flow_to_rd maps**: Associate ip + interface/vrf IDs to MPLS VPN RDs
//! - **sampling maps**: Associate ip (+ optionally interface IDs) with sampling
//!   rates
//!
//! ## File Format
//!
//! Pmacct map files use a key-value format with space-separated entries:
//!
//! ```text
//! # Comments start with # or !
//! id=<identifier> ip=<ip_address> [scope_field=<value>]
//! ```
//!
//! ### Supported Keys
//!
//! - `id`: The identifier value (required)
//! - `ip`: IP address to associate with the identifier (required)
//! - `in`: Ingress interface number (optional scope)
//! - `out`: Egress interface number (optional scope)
//! - `mpls_vpn_id`: MPLS VPN ID (optional scope)
//!
//! ### Examples
//!
//! ```text
//! # Route Distinguisher with ingress interface scope
//! id=0:65500:1000056012 ip=138.187.56.12 in=381
//!
//! # Sampling interval with global scope
//! id=1024 ip=138.187.55.2
//!
//! # Route Distinguisher with vrf id as scope
//  (counts for both ingress+egress vrf ids)
//! id=0:6837:1054 ip=138.187.21.71 mpls_vpn_id=18
//! ```
//!

use crate::flow::enrichment::{
    EnrichmentOperation, EnrichmentOperationType, EnrichmentPayload, Scope, Weight,
};
use netgauze_flow_pkt::ie::{netgauze, Field, IE};
use std::{
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
};

#[derive(Debug, Clone, strum_macros::Display)]
pub enum PmacctMapError {
    #[strum(to_string = "Invalid route distinguisher format: {reason}")]
    InvalidRD { reason: String },

    #[strum(to_string = "Invalid IP address: {reason}")]
    InvalidIpAddress { reason: String },

    #[strum(to_string = "Invalid numeric value for field '{field}': {reason}")]
    InvalidNumericValue { field: String, reason: String },

    #[strum(to_string = "Unknown key: {key}")]
    UnknownKey { key: String },

    #[strum(to_string = "Multiple scope fields specified, only one is allowed")]
    MultipleScope,

    #[strum(to_string = "Missing mandatory field(s): {field}")]
    MissingMandatoryField { field: String },

    #[strum(to_string = "Unsupported IE for PmacctMaps: {ie}")]
    UnsupportedIE { ie: String },
}

impl std::error::Error for PmacctMapError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PmacctMapEntry {
    id: String,
    ip: IpAddr,
    scope: Option<PmacctMapEntryScope>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PmacctMapEntryScope {
    In(u32),
    Out(u32),
    MplsVpnId(u32),
}

impl PmacctMapEntry {
    /// Parse a single line from a PMAcct map file
    ///
    /// Returns:
    /// * `Ok(Some(entry))` - Successfully parsed entry
    /// * `Ok(None)` - Empty line or comment
    /// * `Err(error)` - Parsing error
    pub fn parse_line(line: &str) -> Result<Option<Self>, PmacctMapError> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
            // Empty lines or comments
            return Ok(None);
        }

        let mut id = None;
        let mut ip = None;
        let mut in_if = None;
        let mut out_if = None;
        let mut mpls_vpn_id = None;

        for entry in line.split_whitespace() {
            if let Some((key, value)) = entry.split_once('=') {
                match key {
                    "id" => {
                        id = Some(value.to_string());
                    }
                    "ip" => {
                        ip = Some(IpAddr::from_str(value).map_err(|e| {
                            PmacctMapError::InvalidIpAddress {
                                reason: e.to_string(),
                            }
                        })?);
                    }
                    "in" => {
                        in_if = Some(value.parse::<u32>().map_err(|e| {
                            PmacctMapError::InvalidNumericValue {
                                field: "in".to_string(),
                                reason: e.to_string(),
                            }
                        })?);
                    }
                    "out" => {
                        out_if = Some(value.parse::<u32>().map_err(|e| {
                            PmacctMapError::InvalidNumericValue {
                                field: "out".to_string(),
                                reason: e.to_string(),
                            }
                        })?);
                    }
                    "mpls_vpn_id" => {
                        mpls_vpn_id = Some(value.parse::<u32>().map_err(|e| {
                            PmacctMapError::InvalidNumericValue {
                                field: "mpls_vpn_id".to_string(),
                                reason: e.to_string(),
                            }
                        })?);
                    }
                    _ => {
                        return Err(PmacctMapError::UnknownKey {
                            key: key.to_string(),
                        });
                    }
                }
            }
        }

        match (id, ip) {
            (Some(id), Some(ip)) => {
                let scope = match (in_if, out_if, mpls_vpn_id) {
                    (Some(iface), None, None) => Some(PmacctMapEntryScope::In(iface)),
                    (None, Some(iface), None) => Some(PmacctMapEntryScope::Out(iface)),
                    (None, None, Some(vpn_id)) => Some(PmacctMapEntryScope::MplsVpnId(vpn_id)),
                    (None, None, None) => None,
                    _ => return Err(PmacctMapError::MultipleScope),
                };
                Ok(Some(PmacctMapEntry { id, ip, scope }))
            }
            (Some(_), None) => Err(PmacctMapError::MissingMandatoryField {
                field: "ip".to_string(),
            }),
            (None, Some(_)) => Err(PmacctMapError::MissingMandatoryField {
                field: "id".to_string(),
            }),
            (None, None) => Err(PmacctMapError::MissingMandatoryField {
                field: "id and ip".to_string(),
            }),
        }
    }

    /// Parse a string value into a Field based on the Information Element type
    ///
    /// Currently supports:
    /// - `mplsVpnRouteDistinguisher`: Parses RD format (type:admin:assigned)
    /// - `samplerRandomInterval`: Parses numeric sampling interval
    ///
    /// TODO: replace with proper RD type when supported
    fn parse_field_from_string(ie: &IE, value: &str) -> Result<Field, PmacctMapError> {
        match ie {
            IE::mplsVpnRouteDistinguisher => {
                let parts: Vec<_> = value.split(':').collect();

                if parts.len() != 3 {
                    return Err(PmacctMapError::InvalidRD {
                        reason: "Expected format: type:admin:assigned".to_string(),
                    });
                }

                let rd_type = parts[0]
                    .parse::<u16>()
                    .map_err(|e| PmacctMapError::InvalidRD {
                        reason: format!("invalid type field: {e}"),
                    })?;
                let mut rd = [0u8; 8];
                rd[0..2].copy_from_slice(&rd_type.to_be_bytes());

                match rd_type {
                    0 => {
                        let admin =
                            parts[1]
                                .parse::<u16>()
                                .map_err(|e| PmacctMapError::InvalidRD {
                                    reason: format!("invalid admin field: {e}"),
                                })?;
                        let assigned =
                            parts[2]
                                .parse::<u32>()
                                .map_err(|e| PmacctMapError::InvalidRD {
                                    reason: format!("invalid assigned-number field: {e}"),
                                })?;
                        rd[2..4].copy_from_slice(&admin.to_be_bytes());
                        rd[4..8].copy_from_slice(&assigned.to_be_bytes());
                    }
                    1 => {
                        let admin = parts[1].parse::<Ipv4Addr>().map_err(|e| {
                            PmacctMapError::InvalidRD {
                                reason: format!("invalid admin field: {e}"),
                            }
                        })?;
                        let assigned: u16 =
                            parts[2]
                                .parse::<u16>()
                                .map_err(|e| PmacctMapError::InvalidRD {
                                    reason: format!("invalid assigned-number field: {e}"),
                                })?;
                        rd[2..6].copy_from_slice(&admin.octets());
                        rd[6..8].copy_from_slice(&assigned.to_be_bytes());
                    }
                    2 => {
                        let admin =
                            parts[1]
                                .parse::<u32>()
                                .map_err(|e| PmacctMapError::InvalidRD {
                                    reason: format!("invalid admin field: {e}"),
                                })?;
                        let assigned =
                            parts[2]
                                .parse::<u16>()
                                .map_err(|e| PmacctMapError::InvalidRD {
                                    reason: format!("invalid assigned-number field: {e}"),
                                })?;
                        rd[2..6].copy_from_slice(&admin.to_be_bytes());
                        rd[6..8].copy_from_slice(&assigned.to_be_bytes());
                    }
                    _ => {
                        return Err(PmacctMapError::InvalidRD {
                            reason: "invalid type field (must be 0, 1, or 2".to_string(),
                        })
                    }
                }

                Ok(Field::mplsVpnRouteDistinguisher(rd.into()))
            }
            IE::samplerRandomInterval => {
                let id = value
                    .parse::<u32>()
                    .map_err(|e| PmacctMapError::InvalidNumericValue {
                        field: "id (samplerRandomInterval)".to_string(),
                        reason: e.to_string(),
                    })?;
                Ok(Field::samplerRandomInterval(id))
            }
            _ => Err(PmacctMapError::UnsupportedIE {
                ie: format!("{ie}"),
            }),
        }
    }

    /// Convert PmacctMapEntry to EnrichmentOperation
    pub fn try_into_enrichment_operations(
        self,
        ie: &IE,
        op_type: EnrichmentOperationType,
        weight: Weight,
    ) -> Result<Vec<EnrichmentOperation>, PmacctMapError> {
        let ip = self.ip;
        let id_field = Self::parse_field_from_string(ie, &self.id)?;

        match self.scope {
            Some(PmacctMapEntryScope::In(in_iface)) => {
                let ingress_field = if let Field::mplsVpnRouteDistinguisher(rd) = id_field {
                    Field::NetGauze(netgauze::Field::ingressMplsVpnRouteDistinguisher(rd))
                } else {
                    id_field
                };

                let payload = EnrichmentPayload {
                    ip,
                    scope: Scope::new(0, Some(vec![Field::ingressInterface(in_iface)])),
                    weight,
                    fields: Some(vec![ingress_field]),
                };
                Ok(vec![EnrichmentOperation::from((payload, op_type))])
            }
            Some(PmacctMapEntryScope::Out(out_iface)) => {
                let egress_field = if let Field::mplsVpnRouteDistinguisher(rd) = id_field {
                    Field::NetGauze(netgauze::Field::egressMplsVpnRouteDistinguisher(rd))
                } else {
                    id_field
                };

                let payload = EnrichmentPayload {
                    ip,
                    scope: Scope::new(0, Some(vec![Field::egressInterface(out_iface)])),
                    weight,
                    fields: Some(vec![egress_field]),
                };
                Ok(vec![EnrichmentOperation::from((payload, op_type))])
            }
            Some(PmacctMapEntryScope::MplsVpnId(vrfid)) => {
                let ingress_field = if let Field::mplsVpnRouteDistinguisher(ref rd) = id_field {
                    Field::NetGauze(netgauze::Field::ingressMplsVpnRouteDistinguisher(
                        rd.clone(),
                    ))
                } else {
                    id_field.clone()
                };

                let egress_field = if let Field::mplsVpnRouteDistinguisher(rd) = id_field {
                    Field::NetGauze(netgauze::Field::egressMplsVpnRouteDistinguisher(rd))
                } else {
                    id_field
                };

                let operations = vec![
                    EnrichmentOperation::from((
                        EnrichmentPayload {
                            ip,
                            scope: Scope::new(0, Some(vec![Field::ingressVRFID(vrfid)])),
                            weight,
                            fields: Some(vec![ingress_field]),
                        },
                        op_type,
                    )),
                    EnrichmentOperation::from((
                        EnrichmentPayload {
                            ip,
                            scope: Scope::new(0, Some(vec![Field::egressVRFID(vrfid)])),
                            weight,
                            fields: Some(vec![egress_field]),
                        },
                        op_type,
                    )),
                ];
                Ok(operations)
            }
            None => {
                // Global operation (system scoped)
                let payload = EnrichmentPayload {
                    ip,
                    scope: Scope::new(0, None),
                    weight,
                    fields: Some(vec![id_field]),
                };
                Ok(vec![EnrichmentOperation::from((payload, op_type))])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netgauze_flow_pkt::ie::{netgauze, Field, IE};

    #[test]
    fn test_parse_route_distinguisher_with_interface() {
        // Test parse line
        let line = "id=0:65500:1000056012 ip=138.187.56.12 in=381";
        let entry = PmacctMapEntry::parse_line(line).unwrap().unwrap();

        let expected_entry = PmacctMapEntry {
            id: "0:65500:1000056012".to_string(),
            ip: "138.187.56.12".parse().unwrap(),
            scope: Some(PmacctMapEntryScope::In(381)),
        };

        assert_eq!(entry, expected_entry);

        // Test conversion to enrichment operations
        let ops = entry
            .try_into_enrichment_operations(
                &IE::mplsVpnRouteDistinguisher,
                EnrichmentOperationType::Upsert,
                5,
            )
            .unwrap();

        let expected_ops = vec![EnrichmentOperation::Upsert(EnrichmentPayload {
            ip: "138.187.56.12".parse().unwrap(),
            scope: Scope::new(0, Some(vec![Field::ingressInterface(381)])),
            weight: 5,
            fields: Some(vec![Field::NetGauze(
                netgauze::Field::ingressMplsVpnRouteDistinguisher(
                    [0, 0, 255, 220, 59, 155, 164, 204].into(),
                ),
            )]),
        })];

        assert_eq!(ops, expected_ops);
    }

    #[test]
    fn test_parse_sampling_map_global_scope() {
        // Test parse line
        let line = "id=1024 ip=138.187.55.2";
        let entry = PmacctMapEntry::parse_line(line).unwrap().unwrap();

        let expected_entry = PmacctMapEntry {
            id: "1024".to_string(),
            ip: "138.187.55.2".parse().unwrap(),
            scope: None,
        };

        assert_eq!(entry, expected_entry);

        // Test conversion to enrichment operations
        let ops = entry
            .try_into_enrichment_operations(
                &IE::samplerRandomInterval,
                EnrichmentOperationType::Upsert,
                10,
            )
            .unwrap();

        let expected_ops = vec![EnrichmentOperation::Upsert(EnrichmentPayload {
            ip: "138.187.55.2".parse().unwrap(),
            scope: Scope::new(0, None),
            weight: 10,
            fields: Some(vec![Field::samplerRandomInterval(1024)]),
        })];

        assert_eq!(ops, expected_ops);
    }

    #[test]
    fn test_parse_mpls_vpn_scope() {
        // Test parse line
        let line = "id=0:6837:1054 ip=138.187.21.71 mpls_vpn_id=18";
        let entry = PmacctMapEntry::parse_line(line).unwrap().unwrap();

        let expected_entry = PmacctMapEntry {
            id: "0:6837:1054".to_string(),
            ip: "138.187.21.71".parse().unwrap(),
            scope: Some(PmacctMapEntryScope::MplsVpnId(18)),
        };

        assert_eq!(entry, expected_entry);

        // Test conversion - should create 2 operations (ingress + egress)
        let ops = entry
            .try_into_enrichment_operations(
                &IE::mplsVpnRouteDistinguisher,
                EnrichmentOperationType::Upsert,
                15,
            )
            .unwrap();

        let expected_ops = vec![
            EnrichmentOperation::Upsert(EnrichmentPayload {
                ip: "138.187.21.71".parse().unwrap(),
                scope: Scope::new(0, Some(vec![Field::ingressVRFID(18)])),
                weight: 15,
                fields: Some(vec![Field::NetGauze(
                    netgauze::Field::ingressMplsVpnRouteDistinguisher(
                        [0, 0, 26, 181, 0, 0, 4, 30].into(),
                    ),
                )]),
            }),
            EnrichmentOperation::Upsert(EnrichmentPayload {
                ip: "138.187.21.71".parse().unwrap(),
                scope: Scope::new(0, Some(vec![Field::egressVRFID(18)])),
                weight: 15,
                fields: Some(vec![Field::NetGauze(
                    netgauze::Field::egressMplsVpnRouteDistinguisher(
                        [0, 0, 26, 181, 0, 0, 4, 30].into(),
                    ),
                )]),
            }),
        ];

        assert_eq!(ops, expected_ops);
    }

    #[test]
    fn test_parse_errors_and_comments() {
        // Comments and empty lines are ignored
        assert!(PmacctMapEntry::parse_line("! This is a comment")
            .unwrap()
            .is_none());
        assert!(PmacctMapEntry::parse_line("# This is a comment")
            .unwrap()
            .is_none());
        assert!(PmacctMapEntry::parse_line("").unwrap().is_none());

        // Test missing mandatory fields
        assert!(matches!(
            PmacctMapEntry::parse_line("id=1234"),
            Err(PmacctMapError::MissingMandatoryField { .. })
        ));

        // Test multiple scope fields (should error)
        assert!(matches!(
            PmacctMapEntry::parse_line("id=1234 ip=1.1.1.1 in=123 out=456"),
            Err(PmacctMapError::MultipleScope)
        ));

        // Test invalid IP address
        assert!(matches!(
            PmacctMapEntry::parse_line("id=1234 ip=invalid.ip in=123"),
            Err(PmacctMapError::InvalidIpAddress { .. })
        ));

        // Test invalid uint parsing if ingress interface scope
        assert!(matches!(
            PmacctMapEntry::parse_line("id=1 ip=1.1.1.1 in=not-a-number"),
            Err(PmacctMapError::InvalidNumericValue { field, .. }) if field == "in"
        ));

        // Test unknown key
        assert!(matches!(
            PmacctMapEntry::parse_line("id=5 ip=1.1.1.1 unknown_key=value"),
            Err(PmacctMapError::UnknownKey { .. })
        ));
    }
}
