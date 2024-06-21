use nom::{
    number::complete::{be_u128, be_u16, be_u32, be_u8},
    IResult,
};
use serde::{Deserialize, Serialize};

use netgauze_parse_utils::{
    parse_into_located, parse_till_empty_into_located, ErrorKindSerdeDeref, ReadablePdu,
    ReadablePduWithOneInput, Span,
};
use netgauze_serde_macros::LocatedError;

use crate::{
    iana::{
    BgpSidAttributeType, BgpSidAttributeTypeError, BgpSrv6ServiceSubSubTlvType,
    BgpSrv6ServiceSubSubTlvTypeError, BgpSrv6ServiceSubTlvType, BgpSrv6ServiceSubTlvTypeError,
    IanaValueError,
},
    path_attribute::{
    BgpSidAttribute, SRv6ServiceSubSubTlv, SRv6ServiceSubTlv, SegmentIdentifier, SRGB,
},
    iana::{BgpSidAttributeType, BgpSidAttributeTypeError, IanaValueError},
    path_attribute::{BgpSidAttribute, SegmentIdentifier, SegmentRoutingGlobalBlock},
    wire::deserializer::nlri::MplsLabelParsingError,
};
use crate::wire::deserializer::read_tlv_header_t8_l16;

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum SegmentIdentifierParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] nom::error::ErrorKind),
    MplsLabelParsingError(
        #[from_located(module = "crate::wire::deserializer::nlri")] MplsLabelParsingError,
    ),
    BadBgpPrefixSidTlvType(#[from_external] BgpSidAttributeTypeError),
    BadSRv6ServiceSubTlvType(#[from_external] BgpSrv6ServiceSubTlvTypeError),
    BadSRv6ServiceSubSubTlvType(#[from_external] BgpSrv6ServiceSubSubTlvTypeError),
}

impl<'a> ReadablePduWithOneInput<'a, bool, LocatedSegmentIdentifierParsingError<'a>>
    for SegmentIdentifier
{
    fn from_wire(
        buf: Span<'a>,
        extended_length: bool,
    ) -> IResult<Span<'a>, Self, LocatedSegmentIdentifierParsingError<'a>>
    where
        Self: Sized,
    {
        let (buf, segment_id_buf) = if extended_length {
            nom::multi::length_data(be_u16)(buf)?
        } else {
            nom::multi::length_data(be_u8)(buf)?
        };

        let (_, tlvs) = parse_till_empty_into_located(segment_id_buf)?;

        Ok((buf, SegmentIdentifier::new(tlvs)))
    }
}

impl<'a> ReadablePdu<'a, LocatedSegmentIdentifierParsingError<'a>> for BgpSidAttribute {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedSegmentIdentifierParsingError<'a>> {
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
                ))
            }
            Err(error) => {
                return Err(nom::Err::Error(LocatedSegmentIdentifierParsingError::new(
                    buf,
                    SegmentIdentifierParsingError::BadBgpPrefixSidTlvType(error),
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
impl<'a> ReadablePdu<'a, LocatedSegmentIdentifierParsingError<'a>> for SRv6ServiceSubTlv {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedSegmentIdentifierParsingError<'a>>
    where
        Self: Sized,
    {
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
                ))
            }
            Err(error) => {
                return Err(nom::Err::Error(LocatedSegmentIdentifierParsingError::new(
                    buf,
                    SegmentIdentifierParsingError::BadSRv6ServiceSubTlvType(error),
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
                    sid,
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

impl<'a> ReadablePdu<'a, LocatedSegmentIdentifierParsingError<'a>> for SRv6ServiceSubSubTlv {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedSegmentIdentifierParsingError<'a>>
    where
        Self: Sized,
    {
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
                ))
            }
            Err(error) => {
                return Err(nom::Err::Error(LocatedSegmentIdentifierParsingError::new(
                    buf,
                    SegmentIdentifierParsingError::BadSRv6ServiceSubSubTlvType(error),
                )));
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

impl<'a> ReadablePdu<'a, LocatedSegmentIdentifierParsingError<'a>> for SegmentRoutingGlobalBlock {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedSegmentIdentifierParsingError<'a>>
    where
        Self: Sized,
    {
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
