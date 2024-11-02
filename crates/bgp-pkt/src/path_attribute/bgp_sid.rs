use crate::{
    iana::{BgpSidAttributeType, BgpSrv6ServiceSubSubTlvType, BgpSrv6ServiceSubTlvType},
    nlri::MplsLabel,
    path_attribute::PathAttributeValueProperties,
};
use serde::{Deserialize, Serialize};
use strum_macros::Display;

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
        /// Flags for the SR Label Index are not yet defined (RFC8669).
        /// The Flags field MUST be clear on transmission and MUST be ignored on
        /// reception.
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
    /// ```text
    ///     0                   1                   2                   3
    ///     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///    |   TLV Type    |         TLV Length            |   RESERVED    |
    ///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///    |   SRv6 Service Sub-TLVs                                      //
    ///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///
    ///                         Figure 1: SRv6 Service TLVs
    /// ```
    ///
    ///    TLV Type (1 octet):
    ///       This field is assigned a value from IANA's "BGP Prefix-SID TLV
    ///       Types" subregistry.  It is set to 5 for the SRv6 L3 Service TLV.
    ///       It is set to 6 for the SRv6 L2 Service TLV.
    ///
    ///    TLV Length (2 octets):
    ///       This field specifies the total length, in octets, of the TLV
    ///       Value.
    ///
    ///    RESERVED (1 octet):
    ///       This field is reserved; it MUST be set to 0 by the sender and
    ///       ignored by the receiver.
    ///
    ///    SRv6 Service Sub-TLVs (variable):
    ///       This field contains SRv6 service-related information and is
    ///       encoded as an unordered list of Sub-TLVs whose format is described
    ///       below.
    SRv6ServiceL3 {
        reserved: u8,
        subtlvs: Vec<SRv6ServiceSubTlv>,
    },
    /// ```text
    ///     0                   1                   2                   3
    ///     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///    |   TLV Type    |         TLV Length            |   RESERVED    |
    ///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///    |   SRv6 Service Sub-TLVs                                      //
    ///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///
    ///                         Figure 1: SRv6 Service TLVs
    /// ```
    ///
    ///    TLV Type (1 octet):
    ///       This field is assigned a value from IANA's "BGP Prefix-SID TLV
    ///       Types" subregistry.  It is set to 5 for the SRv6 L3 Service TLV.
    ///       It is set to 6 for the SRv6 L2 Service TLV.
    ///
    ///    TLV Length (2 octets):
    ///       This field specifies the total length, in octets, of the TLV
    ///       Value.
    ///
    ///    RESERVED (1 octet):
    ///       This field is reserved; it MUST be set to 0 by the sender and
    ///       ignored by the receiver.
    ///
    ///    SRv6 Service Sub-TLVs (variable):
    ///       This field contains SRv6 service-related information and is
    ///       encoded as an unordered list of Sub-TLVs whose format is described
    ///       below.
    SRv6ServiceL2 {
        reserved: u8,
        subtlvs: Vec<SRv6ServiceSubTlv>,
    },
    Unknown {
        code: u8,
        value: Vec<u8>,
    },
}
/// ```text
///     0                   1                   2                   3
///     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    | SRv6 Service  |    SRv6 Service               | SRv6 Service //
///    | Sub-TLV       |    Sub-TLV                    | Sub-TLV      //
///    | Type          |    Length                     | Value        //
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
///                       Figure 2: SRv6 Service Sub-TLVs
/// ```
///    SRv6 Service Sub-TLV Type (1 octet):
///       This field identifies the type of SRv6 service information.  It is
///       assigned a value from IANA's "SRv6 Service Sub-TLV Types"
///       subregistry.
///
///    SRv6 Service Sub-TLV Length (2 octets):
///       This field specifies the total length, in octets, of the Sub-TLV
///       Value field.
///
///    SRv6 Service Sub-TLV Value (variable):
///       This field contains data specific to the Sub-TLV Type.  In
///       addition to fixed-length data, it contains other properties of the
///       SRv6 service encoded as a set of SRv6 Service Data Sub-Sub-TLVs
///       whose format is described in Section 3.2 below.
#[derive(Display, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum SRv6ServiceSubTlv {
    /// ```text
    ///     0                   1                   2                   3
    ///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///   | SRv6 Service  |    SRv6 Service               |               |
    ///   | Sub-TLV       |    Sub-TLV                    |               |
    ///   | Type=1        |    Length                     |  RESERVED1    |
    ///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///   |  SRv6 SID Value (16 octets)                                  //
    ///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///   | Svc SID Flags |   SRv6 Endpoint Behavior      |   RESERVED2   |
    ///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///   |  SRv6 Service Data Sub-Sub-TLVs                              //
    ///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///
    ///                   Figure 3: SRv6 SID Information Sub-TLV
    /// ```
    ///   SRv6 Service Sub-TLV Type (1 octet):
    ///      This field is set to 1 to represent the SRv6 SID Information Sub-
    ///      TLV.
    ///
    ///   SRv6 Service Sub-TLV Length (2 octets):
    ///      This field contains the total length, in octets, of the Value
    ///      field of the Sub-TLV.
    ///
    ///   RESERVED1 (1 octet):
    ///      This field MUST be set to 0 by the sender and ignored by the
    ///      receiver.
    ///
    ///   SRv6 SID Value (16 octets):
    ///      This field encodes an SRv6 SID, as defined in [RFC8986](https://datatracker.ietf.org/doc/rfc8986).
    ///
    ///   SRv6 Service SID Flags (1 octet):
    ///      This field encodes SRv6 Service SID Flags -- none are currently
    ///      defined.  It MUST be set to 0 by the sender and any unknown flags
    ///      MUST be ignored by the receiver.
    ///
    ///   SRv6 Endpoint Behavior (2 octets):
    ///      This field encodes the SRv6 Endpoint Behavior codepoint value that
    ///      is associated with the SRv6 SID.  The codepoints used are from
    ///      IANA's "SRv6 Endpoint Behaviors" subregistry under the "Segment
    ///      Routing" registry that was introduced by [RFC8986](https://datatracker.ietf.org/doc/rfc8986).
    ///     The opaque SRv6 Endpoint Behavior (i.e., value 0xFFFF) MAY be used
    /// when the      advertising router wishes to abstract the actual
    /// behavior of its      locally instantiated SRv6 SID.
    ///
    ///   RESERVED2 (1 octet):
    ///      This field MUST be set to 0 by the sender and ignored by the
    ///      receiver.
    ///
    ///   SRv6 Service Data Sub-Sub-TLV Value (variable):
    ///      This field is used to advertise properties of the SRv6 SID.  It is
    ///      encoded as a set of SRv6 Service Data Sub-Sub-TLVs.
    SRv6SIDInformation {
        reserved1: u8,
        sid: u128,
        service_sid_flags: u8,
        endpoint_behaviour: u16,
        reserved2: u8,
        subsubtlvs: Vec<SRv6ServiceSubSubTlv>,
    },
    Unknown {
        code: u8,
        value: Vec<u8>,
    },
}

impl SRv6ServiceSubTlv {
    pub fn code(&self) -> Result<BgpSrv6ServiceSubTlvType, u8> {
        match self {
            SRv6ServiceSubTlv::SRv6SIDInformation { .. } => {
                Ok(BgpSrv6ServiceSubTlvType::SRv6SIDInformation)
            }
            SRv6ServiceSubTlv::Unknown { code, .. } => Err(*code),
        }
    }

    pub fn raw_code(&self) -> u8 {
        match self.code() {
            Ok(value) => value as u8,
            Err(value) => value,
        }
    }
}

/// ```text
///     0                   1                   2                   3
///     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    | Service Data |  Sub-Sub-TLV Length               |Sub-Sub TLV //
///    | Sub-Sub-TLV  |                                   |  Value     //
///    | Type         |                                   |            //
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
///                   Figure 4: SRv6 Service Data Sub-Sub-TLVs
/// ```
///
///    SRv6 Service Data Sub-Sub-TLV Type (1 octet):
///       This field identifies the type of Sub-Sub-TLV.  It is assigned a
///       value from IANA's "SRv6 Service Data Sub-Sub-TLV Types"
///       subregistry.
///
///    SRv6 Service Data Sub-Sub-TLV Length (2 octets):
///       This field specifies the total length, in octets, of the Sub-Sub-
///       TLV Value field.
///
///    SRv6 Service Data Sub-Sub-TLV Value (variable):
///       This field contains data specific to the Sub-Sub-TLV Type.

#[derive(Display, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum SRv6ServiceSubSubTlv {
    /// ```text
    ///     0                   1                   2                   3
    ///     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///    | SRv6 Service  |    SRv6 Service               | Locator Block |
    ///    | Data Sub-Sub  |    Data Sub-Sub-TLV           | Length        |
    ///    | -TLV Type=1   |    Length                     |               |
    ///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///    | Locator Node  | Function      | Argument      | Transposition |
    ///    | Length        | Length        | Length        | Length        |
    ///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///    | Transposition |
    ///    | Offset        |
    ///    +-+-+-+-+-+-+-+-+
    ///                   Figure 5: SRv6 SID Structure Sub-Sub-TLV
    /// ```
    ///
    ///    SRv6 Service Data Sub-Sub-TLV Type (1 octet):
    ///       This field is set to 1 to represent the SRv6 SID Structure Sub-
    ///       Sub-TLV.
    ///
    ///    SRv6 Service Data Sub-Sub-TLV Length (2 octets):
    ///       This field contains a total length of 6 octets.
    ///
    ///    Locator Block Length (1 octet):
    ///       This field contains the length of the SRv6 SID Locator Block in
    ///       bits.
    ///
    ///    Locator Node Length (1 octet):
    ///       This field contains the length of the SRv6 SID Locator Node in
    ///       bits.
    ///
    ///    Function Length (1 octet):
    ///       This field contains the length of the SRv6 SID Function in bits.
    ///
    ///    Argument Length (1 octet):
    ///       This field contains the length of the SRv6 SID Argument in bits.
    ///
    ///    Transposition Length (1 octet):
    ///       This field is the size in bits for the part of the SID that has
    ///       been transposed (or shifted) into an MPLS Label field.
    ///
    ///    Transposition Offset (1 octet):
    ///       This field is the offset position in bits for the part of the SID
    ///       that has been transposed (or shifted) into an MPLS Label field.
    SRv6SIDStructure {
        locator_block_len: u8,
        locator_node_len: u8,
        function_len: u8,
        arg_len: u8,
        transposition_len: u8,
        transposition_offset: u8,
    },
    Unknown {
        code: u8,
        value: Vec<u8>,
    },
}

impl SRv6ServiceSubSubTlv {
    pub fn code(&self) -> Result<BgpSrv6ServiceSubSubTlvType, u8> {
        match self {
            SRv6ServiceSubSubTlv::SRv6SIDStructure { .. } => {
                Ok(BgpSrv6ServiceSubSubTlvType::SRv6SIDStructure)
            }
            SRv6ServiceSubSubTlv::Unknown { code, .. } => Err(*code),
        }
    }

    pub fn raw_code(&self) -> u8 {
        match self.code() {
            Ok(value) => value as u8,
            Err(value) => value,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct PrefixSegmentIdentifier {
    tlvs: Vec<BgpSidAttribute>,
}

impl PrefixSegmentIdentifier {
    pub fn new(tlvs: Vec<BgpSidAttribute>) -> Self {
        Self { tlvs }
    }

    pub fn tlvs(&self) -> &[BgpSidAttribute] {
        &self.tlvs
    }
}

impl PathAttributeValueProperties for PrefixSegmentIdentifier {
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
            BgpSidAttribute::SRv6ServiceL3 { .. } => Ok(BgpSidAttributeType::SRv6ServiceL3),
            BgpSidAttribute::SRv6ServiceL2 { .. } => Ok(BgpSidAttributeType::SRv6ServiceL2),
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
