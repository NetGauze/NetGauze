use crate::{
    iana::BgpSidAttributeType, nlri::MplsLabel, path_attribute::PathAttributeValueProperties,
};
use serde::{Deserialize, Serialize};

/// SR Global Block (SRGB): the set of global segments in the SR domain.
/// If a node participates in multiple SR domains, there is one SRGB for
/// each SR domain.  In SR-MPLS, SRGB is a local property of a node and
/// identifies the set of local labels reserved for global segments.  In
/// SR-MPLS, using identical SRGBs on all nodes within the SR domain is
/// strongly recommended.  Doing so eases operations and troubleshooting
/// as the same label represents the same global segment at each node.
/// In SRv6, the SRGB is the set of global SRv6 SIDs in the SR domain.
///
/// 3 bytes for the MPLS Label of the range
/// followed by
/// 3 bytes for range size
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct SegmentRoutingGlobalBlock {
    pub first_label: MplsLabel,
    pub range_size: [u8; 3],
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum BgpSidAttribute {
    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |       Type    |             Length            |   RESERVED    |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |            Flags              |       Label Index             |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |          Label Index          |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///
    /// where:
    ///
    /// Type: 1
    /// Length: 7, the total length in octets of the value portion of the TLV.
    /// RESERVED: 8-bit field. It MUST be clear on transmission and MUST be ignored on reception.
    /// Flags: 16 bits of flags. None are defined by this document.
    /// The Flags field MUST be clear on transmission and MUST be ignored on reception.
    /// Label Index: 32-bit value representing the index value in the SRGB space.
    /// ```
    LabelIndex {
        /// None defined in RFC8669
        flags: u16,
        label_index: u32,
    },

    /// ```text
    ///   0                   1                   2                   3
    ///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  |     Type      |          Length               |    Flags      |
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  |     Flags     |
    ///  +-+-+-+-+-+-+-+-+
    ///
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  |         SRGB 1 (6 octets)                                     |
    ///  |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  |                               |
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  |         SRGB n (6 octets)                                     |
    ///  |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  |                               |
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// where:
    ///
    /// Type: 3
    /// Length: The total length in octets of the value portion of the TLV: 2 + (non-zero multiple of 6).
    /// Flags: 16 bits of flags. None are defined in this document.
    /// The Flags field MUST be clear on transmission and MUST be ignored on reception.
    /// SRGB: 3 octets specifying the first label in the range followed by 3 octets specifying
    /// the number of labels in the range. Note that the SRGB field MAY appear multiple times.
    /// If the SRGB field appears multiple times, the SRGB consists of multiple ranges that are concatenated.
    /// ```
    Originator {
        /// None defined in RFC8669
        flags: u16,
        srgbs: Vec<SegmentRoutingGlobalBlock>,
    },
    Unknown {
        code: u8,
        value: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct SegmentIdentifier {
    tlvs: Vec<BgpSidAttribute>,
}

impl SegmentIdentifier {
    pub fn new(tlvs: Vec<BgpSidAttribute>) -> Self {
        Self { tlvs }
    }

    pub fn tlvs(&self) -> &[BgpSidAttribute] {
        &self.tlvs
    }
}

impl PathAttributeValueProperties for SegmentIdentifier {
    fn can_be_optional() -> Option<bool> {
        Some(true)
    }

    fn can_be_transitive() -> Option<bool> {
        Some(true)
    }

    fn can_be_partial() -> Option<bool> {
        None // TODO i'm not sure about this
    }
}

impl BgpSidAttribute {
    pub const fn code(&self) -> Result<BgpSidAttributeType, u8> {
        match self {
            BgpSidAttribute::LabelIndex { .. } => Ok(BgpSidAttributeType::LabelIndex),
            BgpSidAttribute::Originator { .. } => Ok(BgpSidAttributeType::Originator),
            BgpSidAttribute::Unknown { code, .. } => Err(*code),
        }
    }

    pub const fn raw_code(&self) -> u8 {
        match self.code() {
            Ok(code) => code as u8,
            Err(code) => code,
        }
    }
}
