use serde::{Deserialize, Serialize};
use std::net::Ipv6Addr;

use netgauze_parse_utils::error::ParseError;
use netgauze_parse_utils::reader::SliceReader;
use netgauze_parse_utils::traits::{ParseFrom, ParseFromWithOneInput};

use crate::iana::{
    BgpSidAttributeType, BgpSidAttributeTypeError, BgpSrv6ServiceSubSubTlvType,
    BgpSrv6ServiceSubSubTlvTypeError, BgpSrv6ServiceSubTlvType, BgpSrv6ServiceSubTlvTypeError,
    IanaValueError,
};
use crate::nlri::MplsLabel;
use crate::path_attribute::{
    BgpSidAttribute, PrefixSegmentIdentifier, SRv6ServiceSubSubTlv, SRv6ServiceSubTlv,
    SegmentRoutingGlobalBlock,
};
use crate::wire::deserializer::nlri::MplsLabelParsingError;
use crate::wire::deserializer::read_tlv_header_t8_l16;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum SegmentIdentifierParsingError {
    #[error("Segment Identifier parsing error: {0}")]
    Parse(#[from] ParseError),

    #[error("Segment Identifier error: {0}")]
    BgpPrefixSidTlvError(#[from] BgpPrefixSidTlvParsingError),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum BgpPrefixSidTlvParsingError {
    #[error("BGP Prefix SID TLV parsing error: {0}")]
    Parse(#[from] ParseError),

    #[error("BGP Prefix SID TLV error: {error} at offset {offset}")]
    BadBgpPrefixSidTlvType {
        offset: usize,
        error: BgpSidAttributeTypeError,
    },

    #[error("BGP Prefix SID TLV error: {0}")]
    BgpSRv6SRGBError(#[from] BgpSRv6SRGBParsingError),

    #[error("BGP Prefix SID TLV error: {0}")]
    SRv6ServiceSubTlvError(#[from] BgpPrefixSidSubTlvParsingError),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum BgpPrefixSidSubTlvParsingError {
    #[error("BGP Prefix SID Sub TLV parsing error: {0}")]
    Parse(#[from] ParseError),
    #[error("BGP Prefix SID Sub TLV error: {error} at offset {offset}")]
    BadBgpPrefixSidSubTlvType {
        offset: usize,
        error: BgpSrv6ServiceSubTlvTypeError,
    },
    #[error("BGP Prefix SID Sub TLV error: {0}")]
    SRv6ServiceSubTlvError(#[from] BgpPrefixSidSubSubTlvParsingError),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum BgpPrefixSidSubSubTlvParsingError {
    #[error("BGP Prefix SID Sub Sub TLV parsing error: {0}")]
    Parse(#[from] ParseError),

    #[error("BGP Prefix SID Sub Sub TLV error: {error} at offset {offset}")]
    BadBgpPrefixSidSubSubTlvType {
        offset: usize,
        error: BgpSrv6ServiceSubSubTlvTypeError,
    },
}

impl<'a> ParseFromWithOneInput<'a, bool> for PrefixSegmentIdentifier {
    type Error = SegmentIdentifierParsingError;
    fn parse(cur: &mut SliceReader<'a>, extended_length: bool) -> Result<Self, Self::Error> {
        let segment_id_len = if extended_length {
            cur.read_u16_be()? as usize
        } else {
            cur.read_u8()? as usize
        };
        let mut segment_id_buf = cur.take_slice(segment_id_len)?;
        let mut tlvs = Vec::new();
        while !segment_id_buf.is_empty() {
            let tlv = BgpSidAttribute::parse(&mut segment_id_buf)?;
            tlvs.push(tlv);
        }
        Ok(PrefixSegmentIdentifier::new(tlvs))
    }
}

impl<'a> ParseFrom<'a> for BgpSidAttribute {
    type Error = BgpPrefixSidTlvParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let (tlv_type, _tlv_length, mut data) =
            read_tlv_header_t8_l16::<BgpPrefixSidTlvParsingError>(cur)?;

        let tlv_type = match BgpSidAttributeType::try_from(tlv_type) {
            Ok(value) => value,
            Err(BgpSidAttributeTypeError(IanaValueError::Unknown(code))) => {
                return Ok(BgpSidAttribute::Unknown {
                    code,
                    value: data.read_bytes(data.remaining())?.to_vec(),
                });
            }
            Err(error) => {
                return Err(BgpPrefixSidTlvParsingError::BadBgpPrefixSidTlvType { offset, error });
            }
        };

        let attribute = match tlv_type {
            BgpSidAttributeType::LabelIndex => {
                let _reserved = data.read_u8()?;
                let flags = data.read_u16_be()?;
                let label_index = data.read_u32_be()?;
                BgpSidAttribute::LabelIndex { flags, label_index }
            }
            BgpSidAttributeType::Originator => {
                let flags = data.read_u16_be()?;
                let mut srgbs = Vec::new();
                while !data.is_empty() {
                    let v = SegmentRoutingGlobalBlock::parse(&mut data)?;
                    srgbs.push(v);
                }
                BgpSidAttribute::Originator { flags, srgbs }
            }
            BgpSidAttributeType::SRv6ServiceL3 => {
                let reserved = data.read_u8()?;
                let mut subtlvs = Vec::new();
                while !data.is_empty() {
                    let v = SRv6ServiceSubTlv::parse(&mut data)?;
                    subtlvs.push(v);
                }
                BgpSidAttribute::SRv6ServiceL3 { reserved, subtlvs }
            }
            BgpSidAttributeType::SRv6ServiceL2 => {
                let reserved = data.read_u8()?;
                let mut subtlvs = Vec::new();
                while !data.is_empty() {
                    let v = SRv6ServiceSubTlv::parse(&mut data)?;
                    subtlvs.push(v);
                }
                BgpSidAttribute::SRv6ServiceL2 { reserved, subtlvs }
            }
        };

        Ok(attribute)
    }
}
impl<'a> ParseFrom<'a> for SRv6ServiceSubTlv {
    type Error = BgpPrefixSidSubTlvParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let (tlv_type, _tlv_length, mut data) =
            read_tlv_header_t8_l16::<BgpPrefixSidSubTlvParsingError>(cur)?;

        let tlv_type = match BgpSrv6ServiceSubTlvType::try_from(tlv_type) {
            Ok(value) => value,
            Err(BgpSrv6ServiceSubTlvTypeError(IanaValueError::Unknown(code))) => {
                return Ok(SRv6ServiceSubTlv::Unknown {
                    code,
                    value: data.read_bytes(data.remaining())?.to_vec(),
                });
            }
            Err(error) => {
                return Err(BgpPrefixSidSubTlvParsingError::BadBgpPrefixSidSubTlvType {
                    offset,
                    error,
                });
            }
        };

        let subtlv = match tlv_type {
            BgpSrv6ServiceSubTlvType::SRv6SIDInformation => {
                let reserved1 = data.read_u8()?;
                let sid = data.read_u128_be()?;
                let service_sid_flags = data.read_u8()?;
                let endpoint_behaviour = data.read_u16_be()?;
                let reserved2 = data.read_u8()?;
                let mut subsubtlvs = Vec::new();
                while !data.is_empty() {
                    let subsubtlv = SRv6ServiceSubSubTlv::parse(&mut data)?;
                    subsubtlvs.push(subsubtlv);
                }

                SRv6ServiceSubTlv::SRv6SIDInformation {
                    reserved1,
                    sid: Ipv6Addr::from(sid),
                    service_sid_flags,
                    endpoint_behaviour,
                    reserved2,
                    subsubtlvs,
                }
            }
        };

        Ok(subtlv)
    }
}

impl<'a> ParseFrom<'a> for SRv6ServiceSubSubTlv {
    type Error = BgpPrefixSidSubSubTlvParsingError;

    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let (tlv_type, _tlv_length, mut data) =
            read_tlv_header_t8_l16::<BgpPrefixSidSubSubTlvParsingError>(cur)?;

        let tlv_type = match BgpSrv6ServiceSubSubTlvType::try_from(tlv_type) {
            Ok(value) => value,
            Err(BgpSrv6ServiceSubSubTlvTypeError(IanaValueError::Unknown(code))) => {
                return Ok(SRv6ServiceSubSubTlv::Unknown {
                    code,
                    value: data.read_bytes(data.offset())?.to_vec(),
                });
            }
            Err(error) => {
                return Err(
                    BgpPrefixSidSubSubTlvParsingError::BadBgpPrefixSidSubSubTlvType {
                        offset,
                        error,
                    },
                );
            }
        };

        let subsubtlv = match tlv_type {
            BgpSrv6ServiceSubSubTlvType::SRv6SIDStructure => {
                let locator_block_len = data.read_u8()?;
                let locator_node_len = data.read_u8()?;
                let function_len = data.read_u8()?;
                let arg_len = data.read_u8()?;
                let transposition_len = data.read_u8()?;
                let transposition_offset = data.read_u8()?;

                SRv6ServiceSubSubTlv::SRv6SIDStructure {
                    locator_block_len,
                    locator_node_len,
                    function_len,
                    arg_len,
                    transposition_len,
                    transposition_offset,
                }
            }
        };

        Ok(subsubtlv)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum BgpSRv6SRGBParsingError {
    #[error("BGP SRv6 SRGB parsing error: {0}")]
    Parse(#[from] ParseError),
    #[error("BGP SRv6 SRGB error: {0}")]
    MplsLabelParsingError(#[from] MplsLabelParsingError),
}

impl<'a> ParseFrom<'a> for SegmentRoutingGlobalBlock {
    type Error = BgpSRv6SRGBParsingError;
    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let first_label = MplsLabel::parse(cur)?;
        let range_size = cur.read_array()?;

        Ok(SegmentRoutingGlobalBlock {
            first_label,
            range_size,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use ipnet::Ipv4Net;

    use netgauze_parse_utils::test_helpers::{
        test_parsed_completely_with_one_input_bytes_reader, test_write,
    };

    use crate::community::{
        Community, ExtendedCommunity, LargeCommunity, TransitiveTwoOctetExtendedCommunity,
    };
    use crate::nlri::{
        Ipv4MplsVpnUnicastAddress, Ipv4Unicast, Ipv4UnicastAddress, LabeledIpv6NextHop,
        LabeledNextHop, MplsLabel, RouteDistinguisher,
    };
    use crate::path_attribute::SRv6ServiceSubSubTlv::SRv6SIDStructure;
    use crate::path_attribute::SRv6ServiceSubTlv::SRv6SIDInformation;
    use crate::path_attribute::{
        Aigp, As4PathSegment, AsPath, AsPathSegmentType, BgpSidAttribute, Communities,
        ExtendedCommunities, LargeCommunities, LocalPreference, MpReach, MultiExitDiscriminator,
        Origin, PathAttribute, PathAttributeValue, PrefixSegmentIdentifier,
    };
    use crate::wire::deserializer::BgpParsingContext;
    use crate::wire::serializer::BgpMessageWritingError;
    use crate::*;

    #[test]
    pub fn test_bgp_sid_l3_service_tlv() -> Result<(), BgpMessageWritingError> {
        let good_wire: [u8; 206] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0x00, 0xce, 0x02, 0x00, 0x00, 0x00, 0xb7, 0x90, 0x0e, 0x00, 0x2d, 0x00,
            0x01, 0x80, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d,
            0xb8, 0x00, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x78, 0xe0, 0x02, 0x01, 0x00, 0x02, 0xfb, 0xf0, 0x00, 0x5a, 0x00, 0x0c, 0xc0, 0x00,
            0x02, 0x0c, 0x40, 0x01, 0x01, 0x00, 0x40, 0x02, 0x0e, 0x02, 0x03, 0x00, 0x00, 0xfb,
            0xf0, 0xfb, 0xf0, 0x00, 0x5a, 0x00, 0x00, 0xfd, 0xe8, 0xc0, 0x08, 0x14, 0xfb, 0xf0,
            0x01, 0x2b, 0xfb, 0xf0, 0x03, 0xe9, 0xfb, 0xf0, 0x04, 0x09, 0xfb, 0xf1, 0x00, 0x01,
            0xfb, 0xf3, 0x00, 0x0c, 0xc0, 0x20, 0x24, 0x00, 0x00, 0xfb, 0xf0, 0x00, 0x00, 0x00,
            0x7b, 0x00, 0x00, 0x01, 0x41, 0x00, 0x00, 0xfb, 0xf0, 0x00, 0x00, 0x01, 0x39, 0x00,
            0x00, 0x01, 0x39, 0x00, 0x00, 0xfb, 0xf0, 0x00, 0x00, 0x04, 0x09, 0x00, 0x00, 0x00,
            0x5a, 0xc0, 0x10, 0x08, 0x00, 0x02, 0xfb, 0xf1, 0x00, 0x00, 0x00, 0x01, 0xc0, 0x28,
            0x25, 0x05, 0x00, 0x22, 0x00, 0x01, 0x00, 0x1e, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00,
            0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f,
            0x00, 0x01, 0x00, 0x06, 0x20, 0x10, 0x10, 0x00, 0x10, 0x30,
        ];
        let good = BgpMessage::Update(BgpUpdateMessage::new(
            vec![],
            vec![
                PathAttribute::from(
                    true,
                    false,
                    false,
                    true,
                    PathAttributeValue::MpReach(MpReach::Ipv4MplsVpnUnicast {
                        next_hop: LabeledNextHop::Ipv6(LabeledIpv6NextHop::new(
                            RouteDistinguisher::As2Administrator { asn2: 0, number: 0 },
                            Ipv6Addr::new(0x2001, 0xdb8, 0x90, 0, 0, 0, 0, 1),
                            None,
                        )),
                        nlri: vec![Ipv4MplsVpnUnicastAddress::new(
                            None,
                            RouteDistinguisher::As4Administrator {
                                asn4: 4226809946,
                                number: 12,
                            },
                            vec![MplsLabel::new([0xe0, 0x02, 0x01])],
                            Ipv4Unicast::from_net(
                                Ipv4Net::new(Ipv4Addr::new(192, 0, 2, 12), 32).unwrap(),
                            )
                            .unwrap(),
                        )],
                    }),
                )
                .unwrap(),
                PathAttribute::from(
                    false,
                    true,
                    false,
                    false,
                    PathAttributeValue::Origin(Origin::IGP),
                )
                .unwrap(),
                PathAttribute::from(
                    false,
                    true,
                    false,
                    false,
                    PathAttributeValue::AsPath(AsPath::As4PathSegments(vec![As4PathSegment::new(
                        AsPathSegmentType::AsSequence,
                        vec![64496, 4226809946, 65000],
                    )])),
                )
                .unwrap(),
                PathAttribute::from(
                    true,
                    true,
                    false,
                    false,
                    PathAttributeValue::Communities(Communities::new(vec![
                        Community::new(4226810155),
                        Community::new(4226810857),
                        Community::new(4226810889),
                        Community::new(4226875393),
                        Community::new(4227006476),
                    ])),
                )
                .unwrap(),
                PathAttribute::from(
                    true,
                    true,
                    false,
                    false,
                    PathAttributeValue::LargeCommunities(LargeCommunities::new(vec![
                        LargeCommunity::new(64496, 123, 321),
                        LargeCommunity::new(64496, 313, 313),
                        LargeCommunity::new(64496, 1033, 90),
                    ])),
                )
                .unwrap(),
                PathAttribute::from(
                    true,
                    true,
                    false,
                    false,
                    PathAttributeValue::ExtendedCommunities(ExtendedCommunities::new(vec![
                        ExtendedCommunity::TransitiveTwoOctet(
                            TransitiveTwoOctetExtendedCommunity::RouteTarget {
                                global_admin: 64497,
                                local_admin: 1,
                            },
                        ),
                    ])),
                )
                .unwrap(),
                PathAttribute::from(
                    true,
                    true,
                    false,
                    false,
                    PathAttributeValue::PrefixSegmentIdentifier(PrefixSegmentIdentifier::new(
                        vec![BgpSidAttribute::SRv6ServiceL3 {
                            reserved: 0,
                            subtlvs: vec![SRv6SIDInformation {
                                reserved1: 0,
                                sid: Ipv6Addr::from(42540766411456678174928491552811515904),
                                service_sid_flags: 0,
                                endpoint_behaviour: 63,
                                reserved2: 0,
                                subsubtlvs: vec![SRv6SIDStructure {
                                    locator_block_len: 32,
                                    locator_node_len: 16,
                                    function_len: 16,
                                    arg_len: 0,
                                    transposition_len: 16,
                                    transposition_offset: 48,
                                }],
                            }],
                        }],
                    )),
                )
                .unwrap(),
            ],
            vec![],
        ));

        test_parsed_completely_with_one_input_bytes_reader(
            &good_wire,
            &mut BgpParsingContext::default(),
            &good,
        );
        test_write(&good, &good_wire)?;

        Ok(())
    }

    #[test]
    pub fn test_bgp_sid_label_index() -> Result<(), BgpMessageWritingError> {
        let good_wire: [u8; 89] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0x00, 0x59, 0x02, 0x00, 0x00, 0x00, 0x42, 0x90, 0x0e, 0x00, 0x0e, 0x00,
            0x01, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0xcb, 0x00, 0x71, 0x35, 0x40,
            0x01, 0x01, 0x00, 0x40, 0x02, 0x00, 0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x40,
            0x05, 0x04, 0x00, 0x00, 0x00, 0x64, 0x80, 0x1a, 0x0b, 0x01, 0x00, 0x0b, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x28, 0x0a, 0x01, 0x00, 0x07, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x35,
        ];

        let good = BgpMessage::Update(BgpUpdateMessage::new(
            vec![],
            vec![
                PathAttribute::from(
                    true,
                    false,
                    false,
                    true,
                    PathAttributeValue::MpReach(MpReach::Ipv4Unicast {
                        next_hop: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                        next_hop_local: None,
                        nlri: vec![Ipv4UnicastAddress::new(
                            None,
                            Ipv4Unicast::from_net(
                                Ipv4Net::new(Ipv4Addr::new(203, 0, 113, 53), 32).unwrap(),
                            )
                            .unwrap(),
                        )],
                    }),
                )
                .unwrap(),
                PathAttribute::from(
                    false,
                    true,
                    false,
                    false,
                    PathAttributeValue::Origin(Origin::IGP),
                )
                .unwrap(),
                PathAttribute::from(
                    false,
                    true,
                    false,
                    false,
                    PathAttributeValue::AsPath(AsPath::As4PathSegments(vec![])),
                )
                .unwrap(),
                PathAttribute::from(
                    true,
                    false,
                    false,
                    false,
                    PathAttributeValue::MultiExitDiscriminator(MultiExitDiscriminator::new(0)),
                )
                .unwrap(),
                PathAttribute::from(
                    false,
                    true,
                    false,
                    false,
                    PathAttributeValue::LocalPreference(LocalPreference::new(100)),
                )
                .unwrap(),
                PathAttribute::from(
                    true,
                    false,
                    false,
                    false,
                    PathAttributeValue::Aigp(Aigp::AccumulatedIgpMetric(0)),
                )
                .unwrap(),
                PathAttribute::from(
                    true,
                    true,
                    false,
                    false,
                    PathAttributeValue::PrefixSegmentIdentifier(PrefixSegmentIdentifier::new(
                        vec![BgpSidAttribute::LabelIndex {
                            flags: 0,
                            label_index: 53,
                        }],
                    )),
                )
                .unwrap(),
            ],
            vec![],
        ));

        test_write(&good, &good_wire)?;
        test_parsed_completely_with_one_input_bytes_reader(
            &good_wire,
            &mut BgpParsingContext::default(),
            &good,
        );

        Ok(())
    }
}
