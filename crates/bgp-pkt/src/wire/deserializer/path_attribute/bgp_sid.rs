use nom::IResult;
use nom::number::complete::{be_u8, be_u16, be_u32, be_u128};
use serde::{Deserialize, Serialize};
use std::net::Ipv6Addr;

use netgauze_parse_utils::{
    ErrorKindSerdeDeref, ReadablePdu, ReadablePduWithOneInput, Span, parse_into_located,
    parse_till_empty_into_located,
};
use netgauze_serde_macros::LocatedError;

use crate::iana::{
    BgpSidAttributeType, BgpSidAttributeTypeError, BgpSrv6ServiceSubSubTlvType,
    BgpSrv6ServiceSubSubTlvTypeError, BgpSrv6ServiceSubTlvType, BgpSrv6ServiceSubTlvTypeError,
    IanaValueError,
};
use crate::path_attribute::{
    BgpSidAttribute, PrefixSegmentIdentifier, SRv6ServiceSubSubTlv, SRv6ServiceSubTlv,
    SegmentRoutingGlobalBlock,
};
use crate::wire::deserializer::nlri::MplsLabelParsingError;
use crate::wire::deserializer::read_tlv_header_t8_l16;

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum SegmentIdentifierParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] nom::error::ErrorKind),
    BgpPrefixSidTlvError(#[from_located(module = "self")] BgpPrefixSidTlvParsingError),
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum BgpPrefixSidTlvParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] nom::error::ErrorKind),
    BadBgpPrefixSidTlvType(#[from_external] BgpSidAttributeTypeError),
    BgpSRv6SRGBError(#[from_located(module = "self")] BgpSRv6SRGBParsingError),
    SRv6ServiceSubTlvError(#[from_located(module = "self")] BgpPrefixSidSubTlvParsingError),
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum BgpPrefixSidSubTlvParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] nom::error::ErrorKind),
    BadBgpPrefixSidSubTlvType(#[from_external] BgpSrv6ServiceSubTlvTypeError),
    SRv6ServiceSubTlvError(#[from_located(module = "self")] BgpPrefixSidSubSubTlvParsingError),
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum BgpPrefixSidSubSubTlvParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] nom::error::ErrorKind),
    BadBgpPrefixSidSubSubTlvType(#[from_external] BgpSrv6ServiceSubSubTlvTypeError),
}

impl<'a> ReadablePduWithOneInput<'a, bool, LocatedSegmentIdentifierParsingError<'a>>
    for PrefixSegmentIdentifier
{
    fn from_wire(
        buf: Span<'a>,
        extended_length: bool,
    ) -> IResult<Span<'a>, Self, LocatedSegmentIdentifierParsingError<'a>> {
        let (buf, segment_id_buf) = if extended_length {
            nom::multi::length_data(be_u16)(buf)?
        } else {
            nom::multi::length_data(be_u8)(buf)?
        };

        let (_, tlvs) = parse_till_empty_into_located(segment_id_buf)?;

        Ok((buf, PrefixSegmentIdentifier::new(tlvs)))
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpPrefixSidTlvParsingError<'a>> for BgpSidAttribute {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpPrefixSidTlvParsingError<'a>> {
        let (tlv_type, _tlv_length, data, remainder) = read_tlv_header_t8_l16(buf)?;

        let tlv_type = match BgpSidAttributeType::try_from(tlv_type) {
            Ok(value) => value,
            Err(BgpSidAttributeTypeError(IanaValueError::Unknown(code))) => {
                return Ok((
                    remainder,
                    BgpSidAttribute::Unknown {
                        code,
                        value: data.to_vec(),
                    },
                ));
            }
            Err(error) => {
                return Err(nom::Err::Error(LocatedBgpPrefixSidTlvParsingError::new(
                    buf,
                    BgpPrefixSidTlvParsingError::BadBgpPrefixSidTlvType(error),
                )));
            }
        };

        let attribute = match tlv_type {
            BgpSidAttributeType::LabelIndex => {
                let (data, _reserved) = be_u8(data)?;
                let (data, flags) = be_u16(data)?;
                let (_data, label_index) = be_u32(data)?;

                BgpSidAttribute::LabelIndex { flags, label_index }
            }
            BgpSidAttributeType::Originator => {
                let (data, flags) = be_u16(data)?;
                let (_data, srgbs) = parse_till_empty_into_located(data)?;
                BgpSidAttribute::Originator { flags, srgbs }
            }
            BgpSidAttributeType::SRv6ServiceL3 => {
                let (data, reserved) = be_u8(data)?;
                let (_data, subtlvs) = parse_till_empty_into_located(data)?;

                BgpSidAttribute::SRv6ServiceL3 { reserved, subtlvs }
            }
            BgpSidAttributeType::SRv6ServiceL2 => {
                let (data, reserved) = be_u8(data)?;
                let (_data, subtlvs) = parse_till_empty_into_located(data)?;

                BgpSidAttribute::SRv6ServiceL2 { reserved, subtlvs }
            }
        };

        Ok((remainder, attribute))
    }
}
impl<'a> ReadablePdu<'a, LocatedBgpPrefixSidSubTlvParsingError<'a>> for SRv6ServiceSubTlv {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedBgpPrefixSidSubTlvParsingError<'a>> {
        let (tlv_type, _tlv_length, data, remainder) = read_tlv_header_t8_l16(buf)?;

        let tlv_type = match BgpSrv6ServiceSubTlvType::try_from(tlv_type) {
            Ok(value) => value,
            Err(BgpSrv6ServiceSubTlvTypeError(IanaValueError::Unknown(code))) => {
                return Ok((
                    remainder,
                    SRv6ServiceSubTlv::Unknown {
                        code,
                        value: data.to_vec(),
                    },
                ));
            }
            Err(error) => {
                return Err(nom::Err::Error(LocatedBgpPrefixSidSubTlvParsingError::new(
                    buf,
                    BgpPrefixSidSubTlvParsingError::BadBgpPrefixSidSubTlvType(error),
                )));
            }
        };

        let subtlv = match tlv_type {
            BgpSrv6ServiceSubTlvType::SRv6SIDInformation => {
                let (data, reserved1) = be_u8(data)?;
                let (data, sid) = be_u128(data)?;
                let (data, service_sid_flags) = be_u8(data)?;
                let (data, endpoint_behaviour) = be_u16(data)?;
                let (data, reserved2) = be_u8(data)?;
                let (_data, subsubtlvs) = parse_till_empty_into_located(data)?;

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

        Ok((remainder, subtlv))
    }
}

impl<'a> ReadablePdu<'a, LocatedBgpPrefixSidSubSubTlvParsingError<'a>> for SRv6ServiceSubSubTlv {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedBgpPrefixSidSubSubTlvParsingError<'a>> {
        let (tlv_type, _tlv_length, data, remainder) = read_tlv_header_t8_l16(buf)?;

        let tlv_type = match BgpSrv6ServiceSubSubTlvType::try_from(tlv_type) {
            Ok(value) => value,
            Err(BgpSrv6ServiceSubSubTlvTypeError(IanaValueError::Unknown(code))) => {
                return Ok((
                    remainder,
                    SRv6ServiceSubSubTlv::Unknown {
                        code,
                        value: data.to_vec(),
                    },
                ));
            }
            Err(error) => {
                return Err(nom::Err::Error(
                    LocatedBgpPrefixSidSubSubTlvParsingError::new(
                        buf,
                        BgpPrefixSidSubSubTlvParsingError::BadBgpPrefixSidSubSubTlvType(error),
                    ),
                ));
            }
        };

        let subsubtlv = match tlv_type {
            BgpSrv6ServiceSubSubTlvType::SRv6SIDStructure => {
                let (data, locator_block_len) = be_u8(data)?;
                let (data, locator_node_len) = be_u8(data)?;
                let (data, function_len) = be_u8(data)?;
                let (data, arg_len) = be_u8(data)?;
                let (data, transposition_len) = be_u8(data)?;
                let (_data, transposition_offset) = be_u8(data)?;

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

        Ok((remainder, subsubtlv))
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum BgpSRv6SRGBParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] nom::error::ErrorKind),
    MplsLabelParsingError(
        #[from_located(module = "crate::wire::deserializer::nlri")] MplsLabelParsingError,
    ),
}

impl<'a> ReadablePdu<'a, LocatedBgpSRv6SRGBParsingError<'a>> for SegmentRoutingGlobalBlock {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBgpSRv6SRGBParsingError<'a>> {
        let (span, first_label) = parse_into_located(buf)?;
        let (span, range_size_0) = be_u8(span)?;
        let (span, range_size_1) = be_u8(span)?;
        let (span, range_size_2) = be_u8(span)?;

        Ok((
            span,
            SegmentRoutingGlobalBlock {
                first_label,
                range_size: [range_size_0, range_size_1, range_size_2],
            },
        ))
    }
}

#[cfg(test)]
pub mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use ipnet::Ipv4Net;

    use netgauze_parse_utils::test_helpers::{test_parsed_completely_with_one_input, test_write};

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

        test_parsed_completely_with_one_input(&good_wire, &mut BgpParsingContext::default(), &good);
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
        test_parsed_completely_with_one_input(&good_wire, &mut BgpParsingContext::default(), &good);

        Ok(())
    }
}
