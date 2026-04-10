// Copyright (C) 2026-present The NetGauze Authors.
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

//! Flattened pmacct-compatible Avro schema for BMP messages.
//!
//! This module defines the data structures and conversion logic required to
//! transform hierarchical NetGauze [`BmpRequest`] objects into flat,
//! serialization-ready structures that match the schema used by the
//! [pmacct](https://github.com/pmacct/pmacct) project.
//!
//! The main entry point is [`PmacctBmpMessage::try_from_bmp_request`].

use apache_avro::types::Value;
use apache_avro::{AvroSchema, Schema};
use chrono::{DateTime, Utc};
use netgauze_bgp_pkt::BgpMessage;
use netgauze_bgp_pkt::nlri::{MplsLabel, RouteDistinguisher};
use netgauze_bgp_pkt::path_attribute::{
    Aigp, As4Path, AsPath, AsPathSegmentType, BgpSidAttribute, Communities, ExtendedCommunities,
    LargeCommunities, MpReach, MpUnreach, Origin, PathAttributeValue,
};
use netgauze_bmp_pkt::{BmpMessage, BmpPeerType, PeerHeader, v3, v4};
use netgauze_bmp_service::{AddrInfo, BmpRequest};
use netgauze_iana::address_family::AddressType;
use serde::de::Error;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a single flattened BMP message
///
/// Use [`PmacctBmpMessage::try_from_bmp_request`] to convert a raw NetGauze
/// [`BmpRequest`] into one or more of these messages.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(untagged)]
pub enum PmacctBmpMessage {
    RouteMonitoring(PmacctRouteMonitoringMessage),
    StatisticsReport(PmacctStatisticsReportMessage),
    PeerDownNotification(PmacctPeerDownNotificationMessage),
    PeerUpNotification(PmacctPeerUpNotificationMessage),
    Initiation(PmacctInitiationMessage),
    Termination(PmacctTerminationMessage),
}

impl AvroSchema for PmacctBmpMessage {
    /// Generates the Avro schema union for all possible pmacct BMP message
    /// types.
    fn get_schema() -> Schema {
        let schemas = vec![
            PmacctRouteMonitoringMessage::get_schema(),
            PmacctStatisticsReportMessage::get_schema(),
            PmacctPeerDownNotificationMessage::get_schema(),
            PmacctPeerUpNotificationMessage::get_schema(),
            PmacctInitiationMessage::get_schema(),
            PmacctTerminationMessage::get_schema(),
        ];
        Schema::Union(apache_avro::schema::UnionSchema::new(schemas).expect("valid union schema"))
    }
}

impl PmacctBmpMessage {
    pub fn get_avro_schema(&self) -> Schema {
        PmacctBmpMessage::get_schema()
    }

    pub fn get_avro_value(self) -> Result<Value, apache_avro::Error> {
        match self {
            PmacctBmpMessage::RouteMonitoring(msg) => {
                let v = apache_avro::to_value(msg)?;
                Ok(Value::Union(0, Box::new(v)))
            }
            PmacctBmpMessage::StatisticsReport(msg) => {
                let v = apache_avro::to_value(msg)?;
                Ok(Value::Union(1, Box::new(v)))
            }
            PmacctBmpMessage::PeerDownNotification(msg) => {
                let v = apache_avro::to_value(msg)?;
                Ok(Value::Union(2, Box::new(v)))
            }
            PmacctBmpMessage::PeerUpNotification(msg) => {
                let v = apache_avro::to_value(msg)?;
                Ok(Value::Union(3, Box::new(v)))
            }
            PmacctBmpMessage::Initiation(msg) => {
                let v = apache_avro::to_value(msg)?;
                Ok(Value::Union(4, Box::new(v)))
            }
            PmacctBmpMessage::Termination(msg) => {
                let v = apache_avro::to_value(msg)?;
                Ok(Value::Union(5, Box::new(v)))
            }
        }
    }

    #[allow(dead_code)]
    fn from_avro_value(value: &Value) -> Result<Self, apache_avro::Error> {
        if let Value::Union(idx, inner) = value {
            match *idx {
                0 => {
                    if let Ok(msg) = apache_avro::from_value::<PmacctRouteMonitoringMessage>(inner)
                    {
                        return Ok(PmacctBmpMessage::RouteMonitoring(msg));
                    }
                }
                1 => {
                    if let Ok(msg) = apache_avro::from_value::<PmacctStatisticsReportMessage>(inner)
                    {
                        return Ok(PmacctBmpMessage::StatisticsReport(msg));
                    }
                }
                2 => {
                    if let Ok(msg) =
                        apache_avro::from_value::<PmacctPeerDownNotificationMessage>(inner)
                    {
                        return Ok(PmacctBmpMessage::PeerDownNotification(msg));
                    }
                }
                3 => {
                    if let Ok(msg) =
                        apache_avro::from_value::<PmacctPeerUpNotificationMessage>(inner)
                    {
                        return Ok(PmacctBmpMessage::PeerUpNotification(msg));
                    }
                }
                4 => {
                    if let Ok(msg) = apache_avro::from_value::<PmacctInitiationMessage>(inner) {
                        return Ok(PmacctBmpMessage::Initiation(msg));
                    }
                }
                5 => {
                    if let Ok(msg) = apache_avro::from_value::<PmacctTerminationMessage>(inner) {
                        return Ok(PmacctBmpMessage::Termination(msg));
                    }
                }
                _ => {}
            }
        }

        if let Ok(msg) = apache_avro::from_value::<PmacctRouteMonitoringMessage>(value) {
            return Ok(PmacctBmpMessage::RouteMonitoring(msg));
        }
        if let Ok(msg) = apache_avro::from_value::<PmacctStatisticsReportMessage>(value) {
            return Ok(PmacctBmpMessage::StatisticsReport(msg));
        }
        if let Ok(msg) = apache_avro::from_value::<PmacctPeerDownNotificationMessage>(value) {
            return Ok(PmacctBmpMessage::PeerDownNotification(msg));
        }
        if let Ok(msg) = apache_avro::from_value::<PmacctPeerUpNotificationMessage>(value) {
            return Ok(PmacctBmpMessage::PeerUpNotification(msg));
        }
        if let Ok(msg) = apache_avro::from_value::<PmacctInitiationMessage>(value) {
            return Ok(PmacctBmpMessage::Initiation(msg));
        }
        if let Ok(msg) = apache_avro::from_value::<PmacctTerminationMessage>(value) {
            return Ok(PmacctBmpMessage::Termination(msg));
        }
        Err(apache_avro::Error::custom(
            "Could not match Avro value to any PmacctBmpMessage variant",
        ))
    }

    pub fn set_seq(&mut self, seq: u32) {
        match self {
            PmacctBmpMessage::RouteMonitoring(m) => m.seq = seq,
            PmacctBmpMessage::StatisticsReport(m) => m.seq = seq,
            PmacctBmpMessage::PeerDownNotification(m) => m.seq = seq,
            PmacctBmpMessage::PeerUpNotification(m) => m.seq = seq,
            PmacctBmpMessage::Initiation(m) => m.seq = seq,
            PmacctBmpMessage::Termination(m) => m.seq = seq,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, AvroSchema, PartialEq, Clone)]
#[avro(name = "bmp_msglog_rm")]
pub struct PmacctRouteMonitoringMessage {
    log_type: LogType,
    seq: u32,
    timestamp: String,
    event_type: EventType,
    writer_id: String,
    tag: Option<i64>,
    label: Option<HashMap<String, String>>,
    afi: u16,
    safi: u8,
    ip_prefix: Option<String>,
    rd: Option<String>,
    rd_origin: Option<RdOrigin>,
    bgp_nexthop: Option<String>,
    as_path: Option<String>,
    as_path_id: Option<u32>,
    comms: Option<String>,
    ecomms: Option<String>,
    lcomms: Option<String>,
    origin: Option<BgpOrigin>,
    local_pref: Option<u32>,
    med: Option<u32>,
    aigp: Option<i64>,
    psid_li: Option<u32>,
    otc: Option<u32>,
    mpls_label: Option<String>,
    peer_ip: String,
    peer_asn: u32,
    peer_type: u8,
    peer_type_str: Option<String>,
    peer_tcp_port: Option<u16>,
    timestamp_arrival: Option<String>,
    bmp_router: String,
    bmp_router_port: Option<u16>,
    bmp_msg_type: BmpMsgType,
    bmp_rib_type: BmpRibType,
    bgp_id: String,
    is_filtered: u8,
    is_in: Option<u8>,
    is_loc: Option<u8>,
    is_post: Option<u8>,
    is_out: Option<u8>,
}

#[derive(Debug, Serialize, Deserialize, AvroSchema, PartialEq, Clone)]
#[avro(name = "bmp_stats")]
pub struct PmacctStatisticsReportMessage {
    seq: u32,
    timestamp: String,
    timestamp_event: Option<String>,
    timestamp_arrival: Option<String>,
    event_type: EventType,
    bmp_router: String,
    bmp_router_port: Option<u16>,
    bmp_msg_type: BmpMsgType,
    writer_id: String,
    tag: Option<i64>,
    label: Option<HashMap<String, String>>,
    peer_ip: String,
    peer_asn: u32,
    peer_type: u8,
    peer_type_str: String,
    bmp_rib_type: BmpRibType,
    is_filtered: u8,
    is_in: Option<u8>,
    is_loc: Option<u8>,
    is_post: Option<u8>,
    is_out: Option<u8>,
    rd: Option<String>,
    rd_origin: Option<RdOrigin>,
    bgp_id: String,
    counter_type: u16,
    counter_type_str: String,
    counter_value: i64,
    afi: Option<u16>,
    safi: Option<u8>,
}

#[derive(Debug, Serialize, Deserialize, AvroSchema, PartialEq, Clone)]
#[avro(name = "bmp_peer_down")]
pub struct PmacctPeerDownNotificationMessage {
    seq: u32,
    timestamp: String,
    timestamp_event: Option<String>,
    timestamp_arrival: Option<String>,
    event_type: EventType,
    bmp_router: String,
    bmp_router_port: Option<u16>,
    bmp_msg_type: BmpMsgType,
    writer_id: String,
    tag: Option<i64>,
    label: Option<HashMap<String, String>>,
    peer_ip: String,
    peer_asn: u32,
    peer_type: u8,
    peer_type_str: Option<String>,
    bmp_rib_type: BmpRibType,
    is_filtered: u8,
    is_in: Option<u8>,
    is_loc: Option<u8>,
    is_post: Option<u8>,
    is_out: Option<u8>,
    rd: Option<String>,
    rd_origin: Option<RdOrigin>,
    bgp_id: String,
    reason_type: u8,
    reason_str: Option<String>,
    reason_loc_code: Option<u16>,
}

#[derive(Debug, Serialize, Deserialize, AvroSchema, PartialEq, Clone)]
#[avro(name = "bmp_peer_up")]
pub struct PmacctPeerUpNotificationMessage {
    seq: u32,
    timestamp: String,
    timestamp_event: Option<String>,
    timestamp_arrival: Option<String>,
    event_type: EventType,
    bmp_router: String,
    bmp_router_port: Option<u16>,
    bmp_msg_type: BmpMsgType,
    writer_id: String,
    tag: Option<i64>,
    label: Option<HashMap<String, String>>,
    peer_ip: String,
    peer_asn: u32,
    peer_type: u8,
    peer_type_str: Option<String>,
    bmp_rib_type: BmpRibType,
    is_filtered: u8,
    is_in: Option<u8>,
    is_loc: Option<u8>,
    is_post: Option<u8>,
    is_out: Option<u8>,
    rd: Option<String>,
    rd_origin: Option<RdOrigin>,
    bgp_id: String,
    local_port: u16,
    remote_port: u16,
    local_ip: String,
    bmp_peer_up_info_string: Option<String>,
    bmp_peer_up_info_vrf_table_name: Option<String>,
    bmp_peer_up_info_admin_label: Option<String>,
    bmp_peer_up_info_reserved: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, AvroSchema, PartialEq, Clone)]
#[avro(name = "bmp_init")]
pub struct PmacctInitiationMessage {
    seq: u32,
    timestamp: String,
    timestamp_event: Option<String>,
    timestamp_arrival: Option<String>,
    event_type: EventType,
    bmp_router: String,
    bmp_router_port: Option<u16>,
    bmp_msg_type: BmpMsgType,
    writer_id: String,
    tag: Option<i64>,
    label: Option<HashMap<String, String>>,
    bmp_init_info_string: Option<String>,
    bmp_init_info_sysdescr: Option<String>,
    bmp_init_info_sysname: Option<String>,
    bmp_init_info_reserved: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, AvroSchema, PartialEq, Clone)]
#[avro(name = "bmp_term")]
pub struct PmacctTerminationMessage {
    seq: u32,
    timestamp: String,
    timestamp_event: Option<String>,
    timestamp_arrival: Option<String>,
    event_type: EventType,
    bmp_router: String,
    bmp_router_port: Option<u16>,
    bmp_msg_type: BmpMsgType,
    writer_id: String,
    tag: Option<i64>,
    label: Option<HashMap<String, String>>,
    bmp_term_info_string: Option<String>,
    bmp_term_info_reason: Option<String>,
}

/// Classifies the type of route activity for a
/// [`PmacctRouteMonitoringMessage`].
#[derive(
    strum_macros::Display,
    strum_macros::EnumString,
    Debug,
    PartialEq,
    Clone,
    netgauze_serde_macros::StringBackedEnum,
)]
#[strum(serialize_all = "kebab-case")]
pub enum LogType {
    Update,
    Withdraw,
    Delete,
    EndOfRib,
}

/// Classifies the high-level event context (e.g., real-time log vs. state
/// dump).
#[derive(
    strum_macros::Display,
    strum_macros::EnumString,
    Debug,
    PartialEq,
    Clone,
    netgauze_serde_macros::StringBackedEnum,
)]
#[strum(serialize_all = "snake_case")]
pub enum EventType {
    Log,
    LogInit,
    LogClose,
    Dump,
    DumpInit,
    DumpClose,
}

/// Values for the BGP `Origin` path attribute.
#[derive(
    strum_macros::Display,
    strum_macros::EnumString,
    Debug,
    PartialEq,
    Clone,
    netgauze_serde_macros::StringBackedEnum,
)]
pub enum BgpOrigin {
    #[strum(to_string = "i")]
    IGP,
    #[strum(to_string = "e")]
    EGP,
    #[strum(to_string = "u")]
    Unknown,
}

/// The origin of the Route Distinguisher (RD)
#[derive(
    strum_macros::Display,
    strum_macros::EnumString,
    Debug,
    PartialEq,
    Clone,
    netgauze_serde_macros::StringBackedEnum,
)]
#[strum(serialize_all = "lowercase")]
pub enum RdOrigin {
    Unknown,
    Bgp,
    Bmp,
    Flow,
    Map,
}

/// Identifies the BMP message type.
#[derive(
    strum_macros::Display,
    strum_macros::EnumString,
    Debug,
    PartialEq,
    Clone,
    netgauze_serde_macros::StringBackedEnum,
)]
#[strum(serialize_all = "snake_case")]
pub enum BmpMsgType {
    RouteMonitor,
    Stats,
    PeerDown,
    PeerUp,
    Init,
    Term,
    Internal,
}

/// Identifies which Routing Information Base (RIB) the routes belongs to.
#[derive(
    strum_macros::Display,
    strum_macros::EnumString,
    Debug,
    PartialEq,
    Clone,
    netgauze_serde_macros::StringBackedEnum,
)]
pub enum BmpRibType {
    #[strum(to_string = "Unknown")]
    Unknown,
    #[strum(to_string = "Adj-Rib-In Pre-Policy")]
    AdjRibInPre,
    #[strum(to_string = "Adj-Rib-In Post-Policy")]
    AdjRibInPost,
    #[strum(to_string = "Loc-Rib")]
    LocRib,
    #[strum(to_string = "Adj-Rib-Out Pre-Policy")]
    AdjRibOutPre,
    #[strum(to_string = "Adj-Rib-Out Post-Policy")]
    AdjRibOutPost,
}

// ===== Conversion between BmpRequest and PmacctBmpMessage(s) ===============

/// Additional metadata that is required to produce a [`PmacctBmpMessage`] but
/// is not present in the BMP wire format.
#[derive(Debug, Clone)]
pub struct PmacctConversionContext {
    /// Identifies the publisher instance (e.g. `"collector01 2025-01.1"`).
    pub writer_id: String,
    /// The event classification (e.g. [`EventType::Log`] or
    /// [`EventType::Dump`]).
    pub event_type: EventType,
    /// Arrival time in the same `"<seconds>.<microseconds>"` format.
    pub timestamp_arrival: String,
    /// Optional tag value to attach to all produced messages.
    pub tag: Option<i64>,
    /// Optional label map (e.g. `node_id`, `platform_id`) to attach to all
    /// produced messages.
    pub label: Option<HashMap<String, String>>,
}

/// Errors produced during [`BmpRequest`] → [`PmacctBmpMessage`] conversion.
#[derive(Debug, Clone, strum_macros::Display)]
pub enum PmacctBmpConversionError {
    /// The BMP message has no pmacct schema equivalent (e.g. RouteMirroring).
    #[strum(to_string = "BMP message type '{0}' has no pmacct schema equivalent")]
    UnsupportedMessageType(String),
    /// A peer header was required but was not present in the message.
    #[strum(to_string = "expected peer header not found in BMP message")]
    MissingPeerHeader,
    /// The peer header carries no timestamp.
    #[strum(to_string = "peer header lacks a timestamp required by pmacct")]
    MissingTimestamp,
}

impl std::error::Error for PmacctBmpConversionError {}

// ----- Helpers -------------------------------------------------------------

/// Safely casts a `u64` to an `i64`, clamping at `i64::MAX` on overflow.
///
/// This is necessary because Avro supports up to signed 64-bit integers
/// (`long`), while BMP/BGP counters are often unsigned 64-bit integers.
fn u64_to_i64_clamp(v: u64) -> i64 {
    use std::convert::TryFrom;
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Format a [`DateTime`] as the `"<unix_seconds>.<microseconds>"` string that
/// pmacct uses for its `timestamp` and `timestamp_arrival` fields.
fn fmt_ts(ts: &DateTime<Utc>) -> String {
    format!("{}.{:06}", ts.timestamp(), ts.timestamp_subsec_micros())
}

/// Extract and format the timestamp from a [`PeerHeader`].
fn peer_header_ts(ph: &PeerHeader) -> Result<String, PmacctBmpConversionError> {
    ph.timestamp()
        .map(fmt_ts)
        .ok_or(PmacctBmpConversionError::MissingTimestamp)
}

/// Derive `(bmp_rib_type, is_filtered, is_in, is_loc, is_post, is_out)` from
/// a [`BmpPeerType`].
fn rib_type_and_flags(
    pt: BmpPeerType,
) -> (
    BmpRibType,
    u8,
    Option<u8>,
    Option<u8>,
    Option<u8>,
    Option<u8>,
) {
    match pt {
        BmpPeerType::LocRibInstancePeer { filtered } => (
            BmpRibType::LocRib,
            if filtered { 1 } else { 0 },
            None,
            Some(1),
            None,
            None,
        ),
        BmpPeerType::GlobalInstancePeer {
            post_policy,
            adj_rib_out,
            ..
        }
        | BmpPeerType::RdInstancePeer {
            post_policy,
            adj_rib_out,
            ..
        }
        | BmpPeerType::LocalInstancePeer {
            post_policy,
            adj_rib_out,
            ..
        } => {
            let rib = match (adj_rib_out, post_policy) {
                (false, false) => BmpRibType::AdjRibInPre,
                (false, true) => BmpRibType::AdjRibInPost,
                (true, false) => BmpRibType::AdjRibOutPre,
                (true, true) => BmpRibType::AdjRibOutPost,
            };
            let (is_in, is_loc, is_post, is_out) = match (adj_rib_out, post_policy) {
                (false, false) => (Some(1u8), None, None, None),
                (false, true) => (Some(1u8), None, Some(1u8), None),
                (true, false) => (None, None, None, Some(1u8)),
                (true, true) => (None, None, Some(1u8), Some(1u8)),
            };
            (rib, 0, is_in, is_loc, is_post, is_out)
        }
        _ => (BmpRibType::Unknown, 0, None, None, None, None),
    }
}

/// Derive `(peer_type_code, peer_type_string)` from a [`BmpPeerType`].
fn peer_type_fields(pt: BmpPeerType) -> (u8, String) {
    let code = pt.get_type();
    (code.into(), code.to_string())
}

/// Format a [`RouteDistinguisher`] according to pmacct format
fn rd_and_origin(
    rd: Option<RouteDistinguisher>,
    rd_origin: RdOrigin,
) -> (Option<String>, Option<RdOrigin>) {
    match rd {
        None => (None, None),
        Some(RouteDistinguisher::As2Administrator { asn2, number }) => {
            (Some(format!("0:{asn2}:{number}")), Some(rd_origin))
        }
        Some(RouteDistinguisher::Ipv4Administrator { ip, number }) => {
            (Some(format!("1:{ip}:{number}")), Some(rd_origin))
        }
        Some(RouteDistinguisher::As4Administrator { asn4, number }) => {
            (Some(format!("2:{asn4}:{number}")), Some(rd_origin))
        }
        Some(RouteDistinguisher::LeafAdRoutes) => {
            (Some("3:leaf-A-D-route".to_string()), Some(rd_origin))
        }
    }
}

/// Extract `(counter_value_as_i64, optional_address_type)` from a
/// [`v3::StatisticsCounter`].
fn counter_value_and_addr_type(c: &v3::StatisticsCounter) -> (i64, Option<AddressType>) {
    use v3::StatisticsCounter::*;
    match c {
        NumberOfPrefixesRejectedByInboundPolicy(v) => (**v as i64, None),
        NumberOfDuplicatePrefixAdvertisements(v) => (**v as i64, None),
        NumberOfDuplicateWithdraws(v) => (**v as i64, None),
        NumberOfUpdatesInvalidatedDueToClusterListLoop(v) => (**v as i64, None),
        NumberOfUpdatesInvalidatedDueToAsPathLoop(v) => (**v as i64, None),
        NumberOfUpdatesInvalidatedDueToOriginatorId(v) => (**v as i64, None),
        NumberOfUpdatesInvalidatedDueToAsConfederationLoop(v) => (**v as i64, None),
        NumberOfRoutesInAdjRibIn(v) => (u64_to_i64_clamp(**v), None),
        NumberOfRoutesInLocRib(v) => (u64_to_i64_clamp(**v), None),
        NumberOfRoutesInPerAfiSafiAdjRibIn(at, v) => (u64_to_i64_clamp(**v), Some(*at)),
        NumberOfRoutesInPerAfiSafiLocRib(at, v) => (u64_to_i64_clamp(**v), Some(*at)),
        NumberOfUpdatesSubjectedToTreatAsWithdraw(v) => (**v as i64, None),
        NumberOfPrefixesSubjectedToTreatAsWithdraw(v) => (**v as i64, None),
        NumberOfDuplicateUpdateMessagesReceived(v) => (**v as i64, None),
        NumberOfRoutesInPrePolicyAdjRibOut(v) => (u64_to_i64_clamp(**v), None),
        NumberOfRoutesInPostPolicyAdjRibOut(v) => (u64_to_i64_clamp(**v), None),
        NumberOfRoutesInPerAfiSafiPrePolicyAdjRibOut(at, v) => (u64_to_i64_clamp(**v), Some(*at)),
        NumberOfRoutesInPerAfiSafiPostPolicyAdjRibOut(at, v) => (u64_to_i64_clamp(**v), Some(*at)),
        NumberOfRoutesInPrePolicyAdjRibIn(v) => (u64_to_i64_clamp(**v), None),
        NumberOfRoutesInPerAfiSafiPrePolicyAdjRibIn(at, v) => (u64_to_i64_clamp(**v), Some(*at)),
        NumberOfRoutesInPostPolicyAdjRibIn(v) => (u64_to_i64_clamp(**v), None),
        NumberOfRoutesInPerAfiSafiPostPolicyAdjRibIn(at, v) => (u64_to_i64_clamp(**v), Some(*at)),
        NumberOfRoutesInPerAfiSafiPrePolicyAdjRibInRejected(at, v) => {
            (u64_to_i64_clamp(**v), Some(*at))
        }
        NumberOfRoutesInPerAfiSafiPostPolicyAdjRibInAccepted(at, v) => {
            (u64_to_i64_clamp(**v), Some(*at))
        }
        NumberOfRoutesInPerAfiSafiSuppressedByDamping(at, v) => (u64_to_i64_clamp(**v), Some(*at)),
        NumberOfRoutesInPerAfiSafiMarkedStaleByGr(at, v) => (u64_to_i64_clamp(**v), Some(*at)),
        NumberOfRoutesInPerAfiSafiMarkedStaleByLlgr(at, v) => (u64_to_i64_clamp(**v), Some(*at)),
        NumberOfRoutesInPostPolicyAdjRibInBeforeThreshold(v) => (u64_to_i64_clamp(**v), None),
        NumberOfRoutesInPerAfiSafiPostPolicyAdjRibInBeforeThreshold(at, v) => {
            (u64_to_i64_clamp(**v), Some(*at))
        }
        NumberOfRoutesInPostPolicyAdjRibInOrLocRibBeforeLicenseThreshold(v) => {
            (u64_to_i64_clamp(**v), None)
        }
        NumberOfRoutesInPerAfiSafiPostPolicyAdjRibInOrLocRibBeforeLicenseThreshold(at, v) => {
            (u64_to_i64_clamp(**v), Some(*at))
        }
        NumberOfRoutesInPrePolicyAdjRibInRejectedDueToAsPathLength(v) => {
            (u64_to_i64_clamp(**v), None)
        }
        NumberOfRoutesInPerAfiSafiPrePolicyAdjRibInRejectedDueToAsPathLength(at, v) => {
            (u64_to_i64_clamp(**v), Some(*at))
        }
        NumberOfRoutesInPerAfiSafiPostPolicyAdjRibInInvalidatedByRpki(at, v) => {
            (u64_to_i64_clamp(**v), Some(*at))
        }
        NumberOfRoutesInPerAfiSafiPostPolicyAdjRibInValidatedByRpki(at, v) => {
            (u64_to_i64_clamp(**v), Some(*at))
        }
        NumberOfRoutesInPerAfiSafiPostPolicyAdjRibInRpkiNotFound(at, v) => {
            (u64_to_i64_clamp(**v), Some(*at))
        }
        NumberOfRoutesInPerAfiSafiPrePolicyAdjRibOutRejected(at, v) => {
            (u64_to_i64_clamp(**v), Some(*at))
        }
        NumberOfRoutesInPrePolicyAdjRibOutFilteredDueToAsPathLength(v) => {
            (u64_to_i64_clamp(**v), None)
        }
        NumberOfRoutesInPerAfiSafiPrePolicyAdjRibOutFilteredDueToAsPathLength(at, v) => {
            (u64_to_i64_clamp(**v), Some(*at))
        }
        NumberOfRoutesInPerAfiSafiPostPolicyAdjRibOutInvalidatedByRpki(at, v) => {
            (u64_to_i64_clamp(**v), Some(*at))
        }
        NumberOfRoutesInPerAfiSafiPostPolicyAdjRibOutValidatedByRpki(at, v) => {
            (u64_to_i64_clamp(**v), Some(*at))
        }
        NumberOfRoutesInPerAfiSafiPostPolicyAdjRibOutRpkiNotFound(at, v) => {
            (u64_to_i64_clamp(**v), Some(*at))
        }
        Experimental65531(_) | Experimental65532(_) | Experimental65533(_)
        | Experimental65534(_) => (0, None),
        Unknown(_, _) => (0, None),
    }
}

// TODO: add this as getter in the native type
/// Compute the 20-bit MPLS label value from a 3-byte [`MplsLabel`].
fn mpls_label_value(label: &MplsLabel) -> u32 {
    let b = label.value();
    ((b[0] as u32) << 12) | ((b[1] as u32) << 4) | ((b[2] as u32) >> 4)
}

/// Count the number of AS numbers in an [`AsPath`].
/// - Each AS_SEQUENCE member counts as 1 per ASN.
/// - Each AS_SET counts as 1, regardless of the number of ASNs in the set.
fn count_as_path_asns(ap: &AsPath) -> usize {
    match ap {
        AsPath::As2PathSegments(segs) => segs
            .iter()
            .map(|s| match s.segment_type() {
                AsPathSegmentType::AsSequence => s.as_numbers().len(),
                AsPathSegmentType::AsSet => 1,
            })
            .sum(),
        AsPath::As4PathSegments(segs) => segs
            .iter()
            .map(|s| match s.segment_type() {
                AsPathSegmentType::AsSequence => s.as_numbers().len(),
                AsPathSegmentType::AsSet => 1,
            })
            .sum(),
    }
}

/// Count the number of AS numbers in an [`As4Path`].
/// - Each AS_SEQUENCE member counts as 1 per ASN.
/// - Each AS_SET counts as 1, regardless of the number of ASNs in the set.
fn count_as4_path_asns(ap: &As4Path) -> usize {
    ap.segments()
        .iter()
        .map(|s| match s.segment_type() {
            AsPathSegmentType::AsSequence => s.as_numbers().len(),
            AsPathSegmentType::AsSet => 1,
        })
        .sum()
}

/// Format an [`AsPath`] as a space-separated string of AS numbers.
/// `AsSet` segments are wrapped in braces: `{A B C}`
fn fmt_as_path(ap: &AsPath) -> String {
    match ap {
        AsPath::As2PathSegments(segs) => segs
            .iter()
            .map(|s| match s.segment_type() {
                AsPathSegmentType::AsSet => {
                    let inner = s
                        .as_numbers()
                        .iter()
                        .map(|n| n.to_string())
                        .collect::<Vec<_>>()
                        .join(" ");
                    format!("{{{inner}}}")
                }
                _ => s
                    .as_numbers()
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join(" "),
            })
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" "),
        AsPath::As4PathSegments(segs) => segs
            .iter()
            .map(|s| match s.segment_type() {
                AsPathSegmentType::AsSet => {
                    let inner = s
                        .as_numbers()
                        .iter()
                        .map(|n| n.to_string())
                        .collect::<Vec<_>>()
                        .join(" ");
                    format!("{{{inner}}}")
                }
                _ => s
                    .as_numbers()
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join(" "),
            })
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" "),
    }
}

/// Format an [`As4Path`] (the supplementary 4-byte AS_PATH attribute) the
/// same way as [`fmt_as_path`].
fn fmt_as4_path(ap: &As4Path) -> String {
    ap.segments()
        .iter()
        .map(|s| match s.segment_type() {
            AsPathSegmentType::AsSet => {
                let inner = s
                    .as_numbers()
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join(" ");
                format!("{{{inner}}}")
            }
            _ => s
                .as_numbers()
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(" "),
        })
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Format only the leading `n` AS numbers from an [`AsPath`] as a string,
/// preserving segment structure. AS_SET segments are counted as 1.
/// Used for merging AS_PATH and AS4_PATH per RFC 4893.
fn fmt_as_path_prefix(ap: &AsPath, mut n: usize) -> String {
    let mut parts = Vec::new();
    match ap {
        AsPath::As2PathSegments(segs) => {
            for seg in segs {
                if n == 0 {
                    break;
                }
                match seg.segment_type() {
                    AsPathSegmentType::AsSet => {
                        let inner = seg
                            .as_numbers()
                            .iter()
                            .map(|v| v.to_string())
                            .collect::<Vec<_>>()
                            .join(" ");
                        parts.push(format!("{{{inner}}}"));
                        n -= 1;
                    }
                    AsPathSegmentType::AsSequence => {
                        let take = n.min(seg.as_numbers().len());
                        let chunk = seg.as_numbers()[..take]
                            .iter()
                            .map(|v| v.to_string())
                            .collect::<Vec<_>>()
                            .join(" ");
                        if !chunk.is_empty() {
                            parts.push(chunk);
                        }
                        n -= take;
                    }
                }
            }
        }
        AsPath::As4PathSegments(segs) => {
            for seg in segs {
                if n == 0 {
                    break;
                }
                match seg.segment_type() {
                    AsPathSegmentType::AsSet => {
                        let inner = seg
                            .as_numbers()
                            .iter()
                            .map(|v| v.to_string())
                            .collect::<Vec<_>>()
                            .join(" ");
                        parts.push(format!("{{{inner}}}"));
                        n -= 1;
                    }
                    AsPathSegmentType::AsSequence => {
                        let take = n.min(seg.as_numbers().len());
                        let chunk = seg.as_numbers()[..take]
                            .iter()
                            .map(|v| v.to_string())
                            .collect::<Vec<_>>()
                            .join(" ");
                        if !chunk.is_empty() {
                            parts.push(chunk);
                        }
                        n -= take;
                    }
                }
            }
        }
    }
    parts
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

// TODO: this needs to be verified and tested
/// Merge [`AsPath`] and [`As4Path`] per RFC 4893.
/// - If only AS_PATH is present, formats and returns that one.
/// - If both are present, reconstructs the full path by taking the leading
///   (AS_PATH.len - AS4_PATH.len) ASNs from AS_PATH, then appending AS4_PATH.
/// - If AS_PATH is shorter than AS4_PATH, returns AS_PATH (cannot reconstruct).
/// - If only AS4_PATH is present (should not happen in valid BGP), returns it
///   defensively.
fn merge_as_path(as_path: Option<&AsPath>, as4_path: Option<&As4Path>) -> Option<String> {
    match (as_path, as4_path) {
        (None, None) => None,
        (Some(ap), None) => Some(fmt_as_path(ap)),
        (None, Some(a4p)) => Some(fmt_as4_path(a4p)),
        (Some(ap), Some(a4p)) => {
            let n_aspath = count_as_path_asns(ap);
            let n_as4path = count_as4_path_asns(a4p);
            if n_aspath < n_as4path {
                Some(fmt_as_path(ap))
            } else {
                let prefix_count = n_aspath - n_as4path;
                let prefix = fmt_as_path_prefix(ap, prefix_count);
                let tail = fmt_as4_path(a4p);
                match (prefix.is_empty(), tail.is_empty()) {
                    (true, _) => Some(tail),
                    (_, true) => Some(prefix),
                    _ => Some(format!("{prefix} {tail}")),
                }
            }
        }
    }
}

/// Format a [`Communities`] attribute as a space-separated `ASN:value` string.
fn fmt_comms(c: &Communities) -> String {
    c.communities()
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Format an [`ExtendedCommunities`] attribute as a space-separated uppercase
/// string (e.g. `RT:64497:1 RT:64498:2`).
fn fmt_ecomms(ec: &ExtendedCommunities) -> String {
    ec.communities()
        .iter()
        .map(|c| c.to_string().to_uppercase())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Format a [`LargeCommunities`] attribute as a space-separated
/// `GA:LD1:LD2` string.
fn fmt_lcomms(lc: &LargeCommunities) -> String {
    lc.communities()
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

// ----- Per-Type Converters -------------------------------------------------

/// Converts a BMP Initiation message into a [`PmacctBmpMessage::Initiation`].
fn convert_initiation(
    addr_info: &AddrInfo,
    msg: &v3::InitiationMessage,
    ctx: &PmacctConversionContext,
) -> Result<PmacctBmpMessage, PmacctBmpConversionError> {
    let bmp_router = addr_info.remote_socket().ip().to_string();
    let bmp_router_port = Some(addr_info.remote_socket().port());

    let mut bmp_init_info_string = None;
    let mut bmp_init_info_sysdescr = None;
    let mut bmp_init_info_sysname = None;
    let mut bmp_init_info_reserved: Option<String> = None;

    for info in msg.information() {
        match info {
            v3::InitiationInformation::String(s) => bmp_init_info_string = Some(s.clone()),
            v3::InitiationInformation::SystemDescription(s) => {
                bmp_init_info_sysdescr = Some(s.clone())
            }
            v3::InitiationInformation::SystemName(s) => bmp_init_info_sysname = Some(s.clone()),
            other => {
                let reserved = bmp_init_info_reserved.get_or_insert_with(String::new);
                if !reserved.is_empty() {
                    reserved.push(' ');
                }
                reserved.push_str(&format!("{other:?}"));
            }
        }
    }

    Ok(PmacctBmpMessage::Initiation(PmacctInitiationMessage {
        seq: 0,
        timestamp: ctx.timestamp_arrival.clone(), // fallback (since no timestamp in Init msg)
        timestamp_event: None,
        timestamp_arrival: Some(ctx.timestamp_arrival.clone()),
        event_type: ctx.event_type.clone(),
        bmp_router,
        bmp_router_port,
        bmp_msg_type: BmpMsgType::Init,
        writer_id: ctx.writer_id.clone(),
        tag: ctx.tag,
        label: ctx.label.clone(),
        bmp_init_info_string,
        bmp_init_info_sysdescr,
        bmp_init_info_sysname,
        bmp_init_info_reserved,
    }))
}

/// Converts a BMP Termination message into a [`PmacctBmpMessage::Termination`].
fn convert_termination(
    addr_info: &AddrInfo,
    msg: &v3::TerminationMessage,
    ctx: &PmacctConversionContext,
) -> Result<PmacctBmpMessage, PmacctBmpConversionError> {
    let bmp_router = addr_info.remote_socket().ip().to_string();
    let bmp_router_port = Some(addr_info.remote_socket().port());

    let mut bmp_term_info_string = None;
    let mut bmp_term_info_reason = None;

    for info in msg.information() {
        match info {
            v3::TerminationInformation::String(s) => bmp_term_info_string = Some(s.clone()),
            v3::TerminationInformation::Reason(code) => {
                bmp_term_info_reason = Some(code.to_string())
            }
            _ => {}
        }
    }

    Ok(PmacctBmpMessage::Termination(PmacctTerminationMessage {
        seq: 0,
        timestamp: ctx.timestamp_arrival.clone(), // fallback (since no timestamp in Term msg)
        timestamp_event: None,
        timestamp_arrival: Some(ctx.timestamp_arrival.clone()),
        event_type: ctx.event_type.clone(),
        bmp_router,
        bmp_router_port,
        bmp_msg_type: BmpMsgType::Term,
        writer_id: ctx.writer_id.clone(),
        tag: ctx.tag,
        label: ctx.label.clone(),
        bmp_term_info_string,
        bmp_term_info_reason,
    }))
}

/// Converts a BMP Peer Up message into a
/// [`PmacctBmpMessage::PeerUpNotification`].
fn convert_peer_up(
    addr_info: &AddrInfo,
    msg: &v3::PeerUpNotificationMessage,
    ctx: &PmacctConversionContext,
) -> Result<PmacctBmpMessage, PmacctBmpConversionError> {
    let ph = msg.peer_header();
    let timestamp = peer_header_ts(ph)?;
    let bmp_router = addr_info.remote_socket().ip().to_string();
    let bmp_router_port = Some(addr_info.remote_socket().port());

    let (peer_type, peer_type_str) = peer_type_fields(ph.peer_type());
    let (bmp_rib_type, is_filtered, is_in, is_loc, is_post, is_out) =
        rib_type_and_flags(ph.peer_type());
    let (rd, rd_origin) = rd_and_origin(ph.rd(), RdOrigin::Bmp);

    let mut bmp_peer_up_info_string = None;
    let mut bmp_peer_up_info_vrf_table_name = None;
    let mut bmp_peer_up_info_admin_label = None;
    let mut bmp_peer_up_info_reserved: Option<String> = None;

    for info in msg.information() {
        match info {
            v3::InitiationInformation::String(s) => bmp_peer_up_info_string = Some(s.clone()),
            v3::InitiationInformation::VrfTableName(s) => {
                bmp_peer_up_info_vrf_table_name = Some(s.clone())
            }
            v3::InitiationInformation::AdminLabel(s) => {
                bmp_peer_up_info_admin_label = Some(s.clone())
            }
            other => {
                let reserved = bmp_peer_up_info_reserved.get_or_insert_with(String::new);
                if !reserved.is_empty() {
                    reserved.push(' ');
                }
                reserved.push_str(&format!("{other:?}"));
            }
        }
    }

    Ok(PmacctBmpMessage::PeerUpNotification(
        PmacctPeerUpNotificationMessage {
            seq: 0,
            timestamp: timestamp.clone(),
            timestamp_event: Some(timestamp),
            timestamp_arrival: Some(ctx.timestamp_arrival.clone()),
            event_type: ctx.event_type.clone(),
            bmp_router,
            bmp_router_port,
            bmp_msg_type: BmpMsgType::PeerUp,
            writer_id: ctx.writer_id.clone(),
            tag: ctx.tag,
            label: ctx.label.clone(),
            peer_ip: ph
                .address()
                .map_or_else(|| "0.0.0.0".to_string(), |ip| ip.to_string()),
            peer_asn: ph.peer_as(),
            peer_type,
            peer_type_str: Some(peer_type_str),
            bmp_rib_type,
            is_filtered,
            is_in,
            is_loc,
            is_post,
            is_out,
            rd,
            rd_origin,
            bgp_id: ph.bgp_id().to_string(),
            local_port: msg.local_port().unwrap_or(0),
            remote_port: msg.remote_port().unwrap_or(0),
            local_ip: msg
                .local_address()
                .map_or_else(|| "0.0.0.0".to_string(), |ip| ip.to_string()),
            bmp_peer_up_info_string,
            bmp_peer_up_info_vrf_table_name,
            bmp_peer_up_info_admin_label,
            bmp_peer_up_info_reserved,
        },
    ))
}

/// Converts a BMP Peer Down message into a
/// [`PmacctBmpMessage::PeerDownNotification`].
fn convert_peer_down(
    addr_info: &AddrInfo,
    ph: &PeerHeader,
    reason: &v3::PeerDownNotificationReason,
    ctx: &PmacctConversionContext,
) -> Result<PmacctBmpMessage, PmacctBmpConversionError> {
    let timestamp = peer_header_ts(ph)?;
    let bmp_router = addr_info.remote_socket().ip().to_string();
    let bmp_router_port = Some(addr_info.remote_socket().port());

    let (peer_type, peer_type_str) = peer_type_fields(ph.peer_type());
    let (bmp_rib_type, is_filtered, is_in, is_loc, is_post, is_out) =
        rib_type_and_flags(ph.peer_type());
    let (rd, rd_origin) = rd_and_origin(ph.rd(), RdOrigin::Bmp);

    let reason_type = u8::from(reason.get_type());
    let reason_str = Some(reason.get_type().to_string());
    let reason_loc_code = match reason {
        v3::PeerDownNotificationReason::LocalSystemClosedFsmEventFollows(code) => Some(*code),
        _ => None,
    };

    Ok(PmacctBmpMessage::PeerDownNotification(
        PmacctPeerDownNotificationMessage {
            seq: 0,
            timestamp: timestamp.clone(),
            timestamp_event: Some(timestamp),
            timestamp_arrival: Some(ctx.timestamp_arrival.clone()),
            event_type: ctx.event_type.clone(),
            bmp_router,
            bmp_router_port,
            bmp_msg_type: BmpMsgType::PeerDown,
            writer_id: ctx.writer_id.clone(),
            tag: ctx.tag,
            label: ctx.label.clone(),
            peer_ip: ph
                .address()
                .map_or_else(|| "0.0.0.0".to_string(), |ip| ip.to_string()),
            peer_asn: ph.peer_as(),
            peer_type,
            peer_type_str: Some(peer_type_str),
            bmp_rib_type,
            is_filtered,
            is_in,
            is_loc,
            is_post,
            is_out,
            rd,
            rd_origin,
            bgp_id: ph.bgp_id().to_string(),
            reason_type,
            reason_str,
            reason_loc_code,
        },
    ))
}

/// Converts a BMP Statistics Report into multiple
/// [`PmacctBmpMessage::StatisticsReport`] messages, one per counter.
fn convert_statistics_report(
    addr_info: &AddrInfo,
    msg: &v3::StatisticsReportMessage,
    ctx: &PmacctConversionContext,
) -> Result<Vec<PmacctBmpMessage>, PmacctBmpConversionError> {
    let ph = msg.peer_header();
    let timestamp = peer_header_ts(ph)?;
    let bmp_router = addr_info.remote_socket().ip().to_string();
    let bmp_router_port = Some(addr_info.remote_socket().port());

    let (peer_type, peer_type_str) = peer_type_fields(ph.peer_type());
    let (bmp_rib_type, is_filtered, is_in, is_loc, is_post, is_out) =
        rib_type_and_flags(ph.peer_type());
    let (rd, rd_origin) = rd_and_origin(ph.rd(), RdOrigin::Bmp);

    let mut out = Vec::with_capacity(msg.counters().len());
    for counter in msg.counters() {
        let (counter_type, counter_type_str) = match counter.get_type() {
            Ok(t) => (u16::from(t), t.to_string()),
            Err(code) => (code, format!("Unknown({code})")),
        };
        let (counter_value, addr_type) = counter_value_and_addr_type(counter);
        let afi = addr_type.map(|at| u16::from(at.address_family()));
        let safi = addr_type.map(|at| u8::from(at.subsequent_address_family()));

        out.push(PmacctBmpMessage::StatisticsReport(
            PmacctStatisticsReportMessage {
                seq: 0,
                timestamp: timestamp.clone(),
                timestamp_event: Some(timestamp.clone()),
                timestamp_arrival: Some(ctx.timestamp_arrival.clone()),
                event_type: ctx.event_type.clone(),
                bmp_router: bmp_router.clone(),
                bmp_router_port,
                bmp_msg_type: BmpMsgType::Stats,
                writer_id: ctx.writer_id.clone(),
                tag: ctx.tag,
                label: ctx.label.clone(),
                peer_ip: ph
                    .address()
                    .map_or_else(|| "0.0.0.0".to_string(), |ip| ip.to_string()),
                peer_asn: ph.peer_as(),
                peer_type,
                peer_type_str: peer_type_str.clone(),
                bmp_rib_type: bmp_rib_type.clone(),
                is_filtered,
                is_in,
                is_loc,
                is_post,
                is_out,
                rd: rd.clone(),
                rd_origin: rd_origin.clone(),
                bgp_id: ph.bgp_id().to_string(),
                counter_type,
                counter_type_str,
                counter_value,
                afi,
                safi,
            },
        ));
    }
    Ok(out)
}

/// Converts a BMP Route Monitoring message into multiple
/// [`PmacctBmpMessage::RouteMonitoring`] messages.
///
/// This handles:
/// - Iterating over all NLRI (announced prefixes) and generating an "Update"
///   message for each.
/// - Iterating over all withdrawn routes and generating a "Withdraw" message
///   for each.
/// - Flattening path attributes (AS Path, Communities, etc.) into the struct
///   fields.
fn convert_route_monitoring(
    addr_info: &AddrInfo,
    ph: &PeerHeader,
    bgp_update: &BgpMessage,
    ctx: &PmacctConversionContext,
) -> Result<Vec<PmacctBmpMessage>, PmacctBmpConversionError> {
    // Only BGP Update messages are valid inside a Route Monitoring message.
    let update = match bgp_update {
        BgpMessage::Update(u) => u,
        _ => return Ok(vec![]),
    };

    let timestamp = peer_header_ts(ph)?;
    let bmp_router = addr_info.remote_socket().ip().to_string();
    let bmp_router_port = Some(addr_info.remote_socket().port());

    let (peer_type, peer_type_str) = peer_type_fields(ph.peer_type());
    let (bmp_rib_type, is_filtered, is_in, is_loc, is_post, is_out) =
        rib_type_and_flags(ph.peer_type());

    let peer_ip = ph
        .address()
        .map_or_else(|| "0.0.0.0".to_string(), |ip| ip.to_string());
    let peer_asn = ph.peer_as();
    let peer_tcp_port = None;
    let bgp_id = ph.bgp_id().to_string();

    // RD from peer header; for VPN NLRI variants this will be overridden
    // per-prefix.
    let (peer_rd, peer_rd_origin) = rd_and_origin(ph.rd(), RdOrigin::Bmp);

    // ---- Extract shared path attributes ------------------------------------
    let mut origin: Option<BgpOrigin> = None;
    let mut as_path_attr: Option<&AsPath> = None;
    let mut as4_path_attr: Option<&As4Path> = None;
    let mut next_hop_ipv4: Option<String> = None;
    let mut local_pref: Option<u32> = None;
    let mut med: Option<u32> = None;
    let mut comms: Option<String> = None;
    let mut ecomms: Option<String> = None;
    let mut lcomms: Option<String> = None;
    let mut aigp: Option<i64> = None;
    let mut otc: Option<u32> = None;
    let mut psid_li: Option<u32> = None;
    let mut mp_reach: Option<&MpReach> = None;
    let mut mp_unreach: Option<&MpUnreach> = None;

    for attr in update.path_attributes() {
        match attr.value() {
            PathAttributeValue::Origin(o) => {
                origin = Some(match o {
                    Origin::IGP => BgpOrigin::IGP,
                    Origin::EGP => BgpOrigin::EGP,
                    Origin::Incomplete => BgpOrigin::Unknown,
                });
            }
            PathAttributeValue::AsPath(ap) => {
                as_path_attr = Some(ap);
            }
            PathAttributeValue::As4Path(ap) => {
                as4_path_attr = Some(ap);
            }
            PathAttributeValue::NextHop(nh) => {
                next_hop_ipv4 = Some(nh.next_hop().to_string());
            }
            PathAttributeValue::LocalPreference(lp) => {
                local_pref = Some(lp.metric());
            }
            PathAttributeValue::MultiExitDiscriminator(m) => {
                med = Some(m.metric());
            }
            PathAttributeValue::Communities(c) => {
                comms = Some(fmt_comms(c));
            }
            PathAttributeValue::ExtendedCommunities(ec) => {
                ecomms = Some(fmt_ecomms(ec));
            }
            PathAttributeValue::LargeCommunities(lc) => {
                lcomms = Some(fmt_lcomms(lc));
            }
            PathAttributeValue::Aigp(Aigp::AccumulatedIgpMetric(v)) => {
                aigp = Some(u64_to_i64_clamp(*v));
            }
            PathAttributeValue::OnlyToCustomer(o) => {
                otc = Some(o.asn());
            }
            PathAttributeValue::PrefixSegmentIdentifier(p) => {
                for tlv in p.tlvs() {
                    if let BgpSidAttribute::LabelIndex { label_index, .. } = tlv {
                        psid_li = Some(*label_index);
                        break;
                    }
                }
            }
            PathAttributeValue::MpReach(mr) => {
                mp_reach = Some(mr);
            }
            PathAttributeValue::MpUnreach(mu) => {
                mp_unreach = Some(mu);
            }
            _ => {}
        }
    }

    let as_path_str = merge_as_path(as_path_attr, as4_path_attr);

    // ---- Per-prefix closure ------------------------------------------------
    // Captures the shared fields; per-NLRI parameters are passed as arguments.
    let build_msg = |log_type: LogType,
                     afi: u16,
                     safi: u8,
                     ip_prefix: Option<String>,
                     rd: Option<String>,
                     rd_origin: Option<RdOrigin>,
                     bgp_nexthop: Option<String>,
                     as_path_id: Option<u32>,
                     mpls_label: Option<String>| {
        PmacctBmpMessage::RouteMonitoring(PmacctRouteMonitoringMessage {
            log_type,
            seq: 0,
            timestamp: timestamp.clone(),
            event_type: ctx.event_type.clone(),
            writer_id: ctx.writer_id.clone(),
            tag: ctx.tag,
            label: ctx.label.clone(),
            afi,
            safi,
            ip_prefix,
            rd,
            rd_origin,
            bgp_nexthop,
            as_path: as_path_str.clone(),
            as_path_id,
            comms: comms.clone(),
            ecomms: ecomms.clone(),
            lcomms: lcomms.clone(),
            origin: origin.clone(),
            local_pref,
            med,
            aigp,
            psid_li,
            otc,
            mpls_label,
            peer_ip: peer_ip.clone(),
            peer_asn,
            peer_type,
            peer_type_str: Some(peer_type_str.clone()),
            peer_tcp_port,
            timestamp_arrival: Some(ctx.timestamp_arrival.clone()),
            bmp_router: bmp_router.clone(),
            bmp_router_port,
            bmp_msg_type: BmpMsgType::RouteMonitor,
            bmp_rib_type: bmp_rib_type.clone(),
            bgp_id: bgp_id.clone(),
            is_filtered,
            is_in,
            is_loc,
            is_post,
            is_out,
        })
    };

    // ---- End-of-RIB shortcut -----------------------------------------------
    if let Some(addr_type) = update.end_of_rib() {
        let afi = u16::from(addr_type.address_family());
        let safi = u8::from(addr_type.subsequent_address_family());
        return Ok(vec![build_msg(
            LogType::EndOfRib,
            afi,
            safi,
            None,
            peer_rd,
            peer_rd_origin,
            None,
            None,
            None,
        )]);
    }

    let mut out: Vec<PmacctBmpMessage> = Vec::new();

    // ---- IPv4 unicast body withdrawals ------------------------------------
    for e in update.withdraw_routes() {
        let afi = u16::from(AddressType::Ipv4Unicast.address_family());
        let safi = u8::from(AddressType::Ipv4Unicast.subsequent_address_family());
        out.push(build_msg(
            LogType::Withdraw,
            afi,
            safi,
            Some(e.network().to_string()),
            peer_rd.clone(),
            peer_rd_origin.clone(),
            None,
            e.path_id(),
            None,
        ));
    }

    // ---- IPv4 unicast body NLRI (reachable) --------------------------------
    for e in update.nlri() {
        let afi = u16::from(AddressType::Ipv4Unicast.address_family());
        let safi = u8::from(AddressType::Ipv4Unicast.subsequent_address_family());
        out.push(build_msg(
            LogType::Update,
            afi,
            safi,
            Some(e.network().to_string()),
            peer_rd.clone(),
            peer_rd_origin.clone(),
            next_hop_ipv4.clone(),
            e.path_id(),
            None,
        ));
    }

    // ---- MP_REACH_NLRI -----------------------------------------------------
    if let Some(mr) = mp_reach {
        let afi = u16::from(mr.afi());
        let safi = u8::from(mr.safi());
        match mr {
            MpReach::Ipv4Unicast { next_hop, nlri, .. } => {
                let nh = Some(next_hop.to_string());
                for e in nlri {
                    out.push(build_msg(
                        LogType::Update,
                        afi,
                        safi,
                        Some(e.network().to_string()),
                        peer_rd.clone(),
                        peer_rd_origin.clone(),
                        nh.clone(),
                        e.path_id(),
                        None,
                    ));
                }
            }
            MpReach::Ipv4Multicast { next_hop, nlri, .. } => {
                let nh = Some(next_hop.to_string());
                for e in nlri {
                    out.push(build_msg(
                        LogType::Update,
                        afi,
                        safi,
                        Some(e.network().to_string()),
                        peer_rd.clone(),
                        peer_rd_origin.clone(),
                        nh.clone(),
                        e.path_id(),
                        None,
                    ));
                }
            }
            MpReach::Ipv4NlriMplsLabels { next_hop, nlri, .. } => {
                let nh = Some(next_hop.to_string());
                for e in nlri {
                    let label = e.labels().first().map(|l| mpls_label_value(l).to_string());
                    out.push(build_msg(
                        LogType::Update,
                        afi,
                        safi,
                        Some(e.prefix().to_string()),
                        peer_rd.clone(),
                        peer_rd_origin.clone(),
                        nh.clone(),
                        e.path_id(),
                        label,
                    ));
                }
            }
            MpReach::Ipv4MplsVpnUnicast { next_hop, nlri } => {
                let nh = Some(next_hop.next_hop().to_string());
                for e in nlri {
                    let (nlri_rd, nlri_rd_origin) = rd_and_origin(Some(e.rd()), RdOrigin::Bgp);
                    let label = e
                        .label_stack()
                        .first()
                        .map(|l| mpls_label_value(l).to_string());
                    out.push(build_msg(
                        LogType::Update,
                        afi,
                        safi,
                        Some(e.network().to_string()),
                        nlri_rd,
                        nlri_rd_origin,
                        nh.clone(),
                        e.path_id(),
                        label,
                    ));
                }
            }
            MpReach::Ipv6Unicast {
                next_hop_global,
                nlri,
                ..
            } => {
                let nh = Some(next_hop_global.to_string());
                for e in nlri {
                    out.push(build_msg(
                        LogType::Update,
                        afi,
                        safi,
                        Some(e.network().to_string()),
                        peer_rd.clone(),
                        peer_rd_origin.clone(),
                        nh.clone(),
                        e.path_id(),
                        None,
                    ));
                }
            }
            MpReach::Ipv6Multicast {
                next_hop_global,
                nlri,
                ..
            } => {
                let nh = Some(next_hop_global.to_string());
                for e in nlri {
                    out.push(build_msg(
                        LogType::Update,
                        afi,
                        safi,
                        Some(e.network().to_string()),
                        peer_rd.clone(),
                        peer_rd_origin.clone(),
                        nh.clone(),
                        e.path_id(),
                        None,
                    ));
                }
            }
            MpReach::Ipv6NlriMplsLabels { next_hop, nlri, .. } => {
                let nh = Some(next_hop.to_string());
                for e in nlri {
                    let label = e.labels().first().map(|l| mpls_label_value(l).to_string());
                    out.push(build_msg(
                        LogType::Update,
                        afi,
                        safi,
                        Some(e.prefix().to_string()),
                        peer_rd.clone(),
                        peer_rd_origin.clone(),
                        nh.clone(),
                        e.path_id(),
                        label,
                    ));
                }
            }
            MpReach::Ipv6MplsVpnUnicast { next_hop, nlri } => {
                let nh = Some(next_hop.next_hop().to_string());
                for e in nlri {
                    let (nlri_rd, nlri_rd_origin) = rd_and_origin(Some(e.rd()), RdOrigin::Bgp);
                    let label = e
                        .label_stack()
                        .first()
                        .map(|l| mpls_label_value(l).to_string());
                    out.push(build_msg(
                        LogType::Update,
                        afi,
                        safi,
                        Some(e.network().to_string()),
                        nlri_rd,
                        nlri_rd_origin,
                        nh.clone(),
                        e.path_id(),
                        label,
                    ));
                }
            }
            _ => {
                // L2Evpn, RouteTargetMembership, BgpLs, BgpLsVpn, Unknown –
                // emit a single placeholder without per-prefix detail
                out.push(build_msg(
                    LogType::Update,
                    afi,
                    safi,
                    None,
                    peer_rd.clone(),
                    peer_rd_origin.clone(),
                    None,
                    None,
                    None,
                ));
            }
        }
    }

    // ---- MP_UNREACH_NLRI ---------------------------------------------------
    if let Some(mu) = mp_unreach {
        let afi = u16::from(mu.afi());
        let safi = u8::from(mu.safi());
        match mu {
            MpUnreach::Ipv4Unicast { nlri } => {
                for e in nlri {
                    out.push(build_msg(
                        LogType::Withdraw,
                        afi,
                        safi,
                        Some(e.network().to_string()),
                        peer_rd.clone(),
                        peer_rd_origin.clone(),
                        None,
                        e.path_id(),
                        None,
                    ));
                }
            }
            MpUnreach::Ipv4Multicast { nlri } => {
                for e in nlri {
                    out.push(build_msg(
                        LogType::Withdraw,
                        afi,
                        safi,
                        Some(e.network().to_string()),
                        peer_rd.clone(),
                        peer_rd_origin.clone(),
                        None,
                        e.path_id(),
                        None,
                    ));
                }
            }
            MpUnreach::Ipv4NlriMplsLabels { nlri } => {
                for e in nlri {
                    let label = e.labels().first().map(|l| mpls_label_value(l).to_string());
                    out.push(build_msg(
                        LogType::Withdraw,
                        afi,
                        safi,
                        Some(e.prefix().to_string()),
                        peer_rd.clone(),
                        peer_rd_origin.clone(),
                        None,
                        e.path_id(),
                        label,
                    ));
                }
            }
            MpUnreach::Ipv4MplsVpnUnicast { nlri } => {
                for e in nlri {
                    let (nlri_rd, nlri_rd_origin) = rd_and_origin(Some(e.rd()), RdOrigin::Bgp);
                    let label = e
                        .label_stack()
                        .first()
                        .map(|l| mpls_label_value(l).to_string());
                    out.push(build_msg(
                        LogType::Withdraw,
                        afi,
                        safi,
                        Some(e.network().to_string()),
                        nlri_rd,
                        nlri_rd_origin,
                        None,
                        e.path_id(),
                        label,
                    ));
                }
            }
            MpUnreach::Ipv6Unicast { nlri } => {
                for e in nlri {
                    out.push(build_msg(
                        LogType::Withdraw,
                        afi,
                        safi,
                        Some(e.network().to_string()),
                        peer_rd.clone(),
                        peer_rd_origin.clone(),
                        None,
                        e.path_id(),
                        None,
                    ));
                }
            }
            MpUnreach::Ipv6Multicast { nlri } => {
                for e in nlri {
                    out.push(build_msg(
                        LogType::Withdraw,
                        afi,
                        safi,
                        Some(e.network().to_string()),
                        peer_rd.clone(),
                        peer_rd_origin.clone(),
                        None,
                        e.path_id(),
                        None,
                    ));
                }
            }
            MpUnreach::Ipv6NlriMplsLabels { nlri } => {
                for e in nlri {
                    let label = e.labels().first().map(|l| mpls_label_value(l).to_string());
                    out.push(build_msg(
                        LogType::Withdraw,
                        afi,
                        safi,
                        Some(e.prefix().to_string()),
                        peer_rd.clone(),
                        peer_rd_origin.clone(),
                        None,
                        e.path_id(),
                        label,
                    ));
                }
            }
            MpUnreach::Ipv6MplsVpnUnicast { nlri } => {
                for e in nlri {
                    let (nlri_rd, nlri_rd_origin) = rd_and_origin(Some(e.rd()), RdOrigin::Bgp);
                    let label = e
                        .label_stack()
                        .first()
                        .map(|l| mpls_label_value(l).to_string());
                    out.push(build_msg(
                        LogType::Withdraw,
                        afi,
                        safi,
                        Some(e.network().to_string()),
                        nlri_rd,
                        nlri_rd_origin,
                        None,
                        e.path_id(),
                        label,
                    ));
                }
            }
            _ => {
                // L2Evpn, RouteTargetMembership, BgpLs, BgpLsVpn, Unknown.
                out.push(build_msg(
                    LogType::Withdraw,
                    afi,
                    safi,
                    None,
                    peer_rd.clone(),
                    peer_rd_origin.clone(),
                    None,
                    None,
                    None,
                ));
            }
        }
    }

    Ok(out)
}

impl PmacctBmpMessage {
    /// Convert a [`BmpRequest`] into one or more [`PmacctBmpMessage`]s using
    /// the supplied [`PmacctConversionContext`].
    ///
    /// Returns a [`Vec`] because:
    /// - A Statistics Report with *N* counters produces *N* messages.
    /// - A Route Monitoring message covering *K* NLRI prefixes produces *K*
    ///   messages
    ///
    /// Fails with [`PmacctBmpConversionError::UnsupportedMessageType`] for
    /// BMP message types that are not yet supported (RouteMirroring,
    /// Experimental251–254).
    pub fn try_from_bmp_request(
        request: &BmpRequest,
        ctx: &PmacctConversionContext,
    ) -> Result<Vec<Self>, PmacctBmpConversionError> {
        let (addr_info, message) = request;
        match message {
            BmpMessage::V3(v3_msg) => match v3_msg {
                v3::BmpMessageValue::RouteMonitoring(rm) => {
                    convert_route_monitoring(addr_info, rm.peer_header(), rm.update_message(), ctx)
                }
                v3::BmpMessageValue::StatisticsReport(stats) => {
                    convert_statistics_report(addr_info, stats, ctx)
                }
                v3::BmpMessageValue::PeerDownNotification(pd) => {
                    convert_peer_down(addr_info, pd.peer_header(), pd.reason(), ctx)
                        .map(|m| vec![m])
                }
                v3::BmpMessageValue::PeerUpNotification(pu) => {
                    convert_peer_up(addr_info, pu, ctx).map(|m| vec![m])
                }
                v3::BmpMessageValue::Initiation(init) => {
                    convert_initiation(addr_info, init, ctx).map(|m| vec![m])
                }
                v3::BmpMessageValue::Termination(term) => {
                    convert_termination(addr_info, term, ctx).map(|m| vec![m])
                }
                v3::BmpMessageValue::RouteMirroring(_) => Err(
                    PmacctBmpConversionError::UnsupportedMessageType("RouteMirroring".to_string()),
                ),
                v3::BmpMessageValue::Experimental251(_)
                | v3::BmpMessageValue::Experimental252(_)
                | v3::BmpMessageValue::Experimental253(_)
                | v3::BmpMessageValue::Experimental254(_) => Err(
                    PmacctBmpConversionError::UnsupportedMessageType("Experimental".to_string()),
                ),
            },
            BmpMessage::V4(v4_msg) => match v4_msg {
                v4::BmpMessageValue::RouteMonitoring(rm) => {
                    convert_route_monitoring(addr_info, rm.peer_header(), rm.update_message(), ctx)
                }
                v4::BmpMessageValue::StatisticsReport(stats) => {
                    convert_statistics_report(addr_info, stats, ctx)
                }
                v4::BmpMessageValue::PeerDownNotification(pd) => {
                    convert_peer_down(addr_info, pd.peer_header(), pd.reason(), ctx)
                        .map(|m| vec![m])
                }
                v4::BmpMessageValue::PeerUpNotification(pu) => {
                    convert_peer_up(addr_info, pu, ctx).map(|m| vec![m])
                }
                v4::BmpMessageValue::Initiation(init) => {
                    convert_initiation(addr_info, init, ctx).map(|m| vec![m])
                }
                v4::BmpMessageValue::Termination(term) => {
                    convert_termination(addr_info, term, ctx).map(|m| vec![m])
                }
                v4::BmpMessageValue::RouteMirroring(_) => Err(
                    PmacctBmpConversionError::UnsupportedMessageType("RouteMirroring".to_string()),
                ),
                v4::BmpMessageValue::Experimental251(_)
                | v4::BmpMessageValue::Experimental252(_)
                | v4::BmpMessageValue::Experimental253(_)
                | v4::BmpMessageValue::Experimental254(_) => Err(
                    PmacctBmpConversionError::UnsupportedMessageType("Experimental".to_string()),
                ),
            },
        }
    }
}

#[cfg(test)]
mod tests;
