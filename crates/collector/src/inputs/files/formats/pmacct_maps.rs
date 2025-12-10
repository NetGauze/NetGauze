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

//! # Pmacct Maps Modeling and Parsing Module
//!
//! This module provides functionality for parsing pmacct map entries into
//! structured data (`PmacctMapEntry`).
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
use netgauze_flow_pkt::ie::{Field, IE};
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

impl PmacctMapEntry {
    #[cfg(test)]
    pub fn new(id: &str, ip: IpAddr, scope: Option<PmacctMapEntryScope>) -> Self {
        PmacctMapEntry {
            id: id.to_string(),
            ip,
            scope,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn ip(&self) -> IpAddr {
        self.ip
    }

    pub fn into_scope(self) -> Option<PmacctMapEntryScope> {
        self.scope
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PmacctMapEntryScope {
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
    pub fn parse_field_from_string(ie: &IE, value: &str) -> Result<Field, PmacctMapError> {
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
                        });
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use netgauze_flow_pkt::ie::IE;
    use std::{net::IpAddr, str::FromStr};

    #[test]
    fn parse_line_empty_and_comments() {
        assert_eq!(PmacctMapEntry::parse_line("").unwrap(), None);
        assert_eq!(PmacctMapEntry::parse_line("   ").unwrap(), None);
        assert_eq!(PmacctMapEntry::parse_line("# a comment").unwrap(), None);
        assert_eq!(
            PmacctMapEntry::parse_line("! another comment").unwrap(),
            None
        );
    }

    #[test]
    fn parse_line_basic_without_scope() {
        let line = "id=1024 ip=138.187.55.2";
        let entry = PmacctMapEntry::parse_line(line)
            .unwrap()
            .expect("expected entry");

        let expected = PmacctMapEntry::new("1024", IpAddr::from_str("138.187.55.2").unwrap(), None);
        assert_eq!(entry, expected);
    }

    #[test]
    fn parse_line_with_in_scope() {
        let line = "id=0:0:0 ip=1.2.3.4 in=381";
        let entry = PmacctMapEntry::parse_line(line)
            .unwrap()
            .expect("expected entry");

        let expected = PmacctMapEntry::new(
            "0:0:0",
            IpAddr::from_str("1.2.3.4").unwrap(),
            Some(PmacctMapEntryScope::In(381)),
        );
        assert_eq!(entry, expected);
    }

    #[test]
    fn parse_line_with_out_scope() {
        let line = "id=0:0:0 ip=10.0.0.1 out=42";
        let entry = PmacctMapEntry::parse_line(line)
            .unwrap()
            .expect("expected entry");

        let expected = PmacctMapEntry::new(
            "0:0:0",
            IpAddr::from_str("10.0.0.1").unwrap(),
            Some(PmacctMapEntryScope::Out(42)),
        );
        assert_eq!(entry, expected);
    }

    #[test]
    fn parse_line_with_mpls_vpn_scope() {
        let line = "id=0:0:0 ip=::1 mpls_vpn_id=18";
        let entry = PmacctMapEntry::parse_line(line)
            .unwrap()
            .expect("expected entry");

        let expected = PmacctMapEntry::new(
            "0:0:0",
            IpAddr::from_str("::1").unwrap(),
            Some(PmacctMapEntryScope::MplsVpnId(18)),
        );
        assert_eq!(entry, expected);
    }

    #[test]
    fn parse_line_multiple_scope_error() {
        let line = "id=1 ip=1.2.3.4 in=1 out=2";
        match PmacctMapEntry::parse_line(line).unwrap_err() {
            PmacctMapError::MultipleScope => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn parse_line_unknown_key_error() {
        let line = "id=1 ip=1.2.3.4 foo=bar";
        match PmacctMapEntry::parse_line(line) {
            Err(PmacctMapError::UnknownKey { key }) => assert_eq!(key, "foo"),
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn parse_line_missing_fields() {
        match PmacctMapEntry::parse_line("id=only") {
            Err(PmacctMapError::MissingMandatoryField { field }) => assert_eq!(field, "ip"),
            other => panic!("unexpected result: {other:?}"),
        }
        match PmacctMapEntry::parse_line("ip=1.2.3.4") {
            Err(PmacctMapError::MissingMandatoryField { field }) => assert_eq!(field, "id"),
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn parse_field_from_string_mpls_rd_type0() {
        let res =
            PmacctMapEntry::parse_field_from_string(&IE::mplsVpnRouteDistinguisher, "0:65500:100")
                .unwrap();

        let expected_rd: [u8; 8] = [0, 0, 255, 220, 0, 0, 0, 100];
        let expected = Field::mplsVpnRouteDistinguisher(expected_rd.into());
        assert_eq!(res, expected);
    }

    #[test]
    fn parse_field_from_string_mpls_rd_type1() {
        let res = PmacctMapEntry::parse_field_from_string(
            &IE::mplsVpnRouteDistinguisher,
            "1:192.0.2.5:42",
        )
        .unwrap();

        let expected_rd: [u8; 8] = [0, 1, 192, 0, 2, 5, 0, 42];
        let expected = Field::mplsVpnRouteDistinguisher(expected_rd.into());
        assert_eq!(res, expected);
    }

    #[test]
    fn parse_field_from_string_mpls_rd_type2() {
        let res = PmacctMapEntry::parse_field_from_string(
            &IE::mplsVpnRouteDistinguisher,
            "2:4200137808:1001",
        )
        .unwrap();

        let expected_rd: [u8; 8] = [0, 2, 250, 89, 4, 80, 3, 233];
        let expected = Field::mplsVpnRouteDistinguisher(expected_rd.into());
        assert_eq!(res, expected);
    }

    #[test]
    fn parse_field_from_string_mpls_rd_invalid_format() {
        let res =
            PmacctMapEntry::parse_field_from_string(&IE::mplsVpnRouteDistinguisher, "badformat");
        match res {
            Err(PmacctMapError::InvalidRD { .. }) => {}
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn parse_field_from_string_sampler_interval() {
        let res =
            PmacctMapEntry::parse_field_from_string(&IE::samplerRandomInterval, "1024").unwrap();

        let expected = Field::samplerRandomInterval(1024);
        assert_eq!(res, expected);
    }

    #[test]
    fn parse_field_from_string_sampler_interval_invalid() {
        let res =
            PmacctMapEntry::parse_field_from_string(&IE::samplerRandomInterval, "not-a-number");
        match res {
            Err(PmacctMapError::InvalidNumericValue { field, .. }) => {
                assert!(field.contains("samplerRandomInterval"));
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }
}
