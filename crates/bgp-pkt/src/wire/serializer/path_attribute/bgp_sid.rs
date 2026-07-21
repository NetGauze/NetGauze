use std::io::Write;

use netgauze_parse_utils::{WritablePdu, WritablePduWithOneInput, impl_from_io_error};

use crate::path_attribute::{
    BgpSidAttribute, PrefixSegmentIdentifier, SRv6ServiceSubSubTlv, SRv6ServiceSubTlv,
    SegmentRoutingGlobalBlock,
};
use crate::wire::serializer::nlri::MplsLabelWritingError;
use crate::wire::serializer::path_attribute::write_length;
use crate::wire::serializer::write_tlv_header_t8_l16;

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum SegmentIdentifierWritingError {
    #[error("IO error while writing segment identifier: {0}")]
    StdIOError(Box<str>),

    #[error("in BGP SID attribute: {0}")]
    BgpSidAttributeWritingError(#[from] BgpSidAttributeWritingError),
}
impl_from_io_error!(SegmentIdentifierWritingError);

impl WritablePduWithOneInput<bool, SegmentIdentifierWritingError> for PrefixSegmentIdentifier {
    // One is extended length is not enabled, the rest is variable
    const BASE_LENGTH: usize = 1;

    fn len(&self, extended_length: bool) -> usize {
        let len = Self::BASE_LENGTH;

        len + usize::from(extended_length) + self.tlvs().iter().map(|tlv| tlv.len()).sum::<usize>()
    }

    fn write<T: Write>(
        &self,
        writer: &mut T,
        extended_length: bool,
    ) -> Result<(), SegmentIdentifierWritingError> {
        write_length(self, extended_length, writer)?;

        for tlv in self.tlvs() {
            tlv.write(writer)?;
        }

        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum BgpSidAttributeWritingError {
    #[error("IO error while writing BGP SID attribute: {0}")]
    StdIOError(Box<str>),

    #[error("in BGP SID SRGB: {0}")]
    BgpSidSrgb(#[from] SrgbWritingError),

    #[error("in SRv6 service sub-TLV: {0}")]
    BgpSRv6SubTlvService(#[from] SRv6ServiceSubTlvWritingError),
}
impl_from_io_error!(BgpSidAttributeWritingError);

impl WritablePdu<BgpSidAttributeWritingError> for BgpSidAttribute {
    const BASE_LENGTH: usize = 3; /* type u8 + length u16 */

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + match self {
                BgpSidAttribute::LabelIndex { .. } => 7,
                BgpSidAttribute::Originator { srgbs, .. } => 2 + 6 * srgbs.len(),
                BgpSidAttribute::SRv6ServiceL2 { subtlvs, .. }
                | BgpSidAttribute::SRv6ServiceL3 { subtlvs, .. } => {
                    1 + subtlvs.iter().map(|subtlv| subtlv.len()).sum::<usize>()
                }
                BgpSidAttribute::Unknown { value, .. } => value.len(),
            }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpSidAttributeWritingError> {
        write_tlv_header_t8_l16(writer, self.raw_code(), self.len() as u16)?;

        match self {
            BgpSidAttribute::LabelIndex { label_index, flags } => {
                writer.write_all(&[0])?; // reserved 8 bits
                writer.write_all(&(*flags).to_be_bytes())?;
                writer.write_all(&(*label_index).to_be_bytes())?;
            }
            BgpSidAttribute::Originator { flags, srgbs } => {
                writer.write_all(&(*flags).to_be_bytes())?;
                for srgb in srgbs {
                    srgb.write(writer)?;
                }
            }
            BgpSidAttribute::SRv6ServiceL3 { reserved, subtlvs } => {
                writer.write_all(&[*reserved])?;
                for subtlv in subtlvs {
                    subtlv.write(writer)?;
                }
            }
            BgpSidAttribute::SRv6ServiceL2 { reserved, subtlvs } => {
                writer.write_all(&[*reserved])?;
                for subtlv in subtlvs {
                    subtlv.write(writer)?;
                }
            }
            // `code` is already emitted as the TLV type by the header above, so only
            // the raw value belongs here (same as the sub-TLV and sub-sub-TLV cases).
            BgpSidAttribute::Unknown { value, .. } => writer.write_all(value)?,
        }
        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum SrgbWritingError {
    #[error("IO error while writing SRGB: {0}")]
    StdIOError(Box<str>),

    #[error("in MPLS label: {0}")]
    MplsLabelError(#[from] MplsLabelWritingError),
}
impl_from_io_error!(SrgbWritingError);

impl WritablePdu<SrgbWritingError> for SegmentRoutingGlobalBlock {
    const BASE_LENGTH: usize = 6; /* 3 bytes MPLS Label + 3 bytes range size */

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), SrgbWritingError> {
        self.first_label().write(writer)?;
        writer.write_all(self.range_size())?;

        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum SRv6ServiceSubTlvWritingError {
    #[error("IO error while writing SRv6 service sub-TLV: {0}")]
    StdIOError(Box<str>),

    #[error("in SRv6 service sub-sub-TLV: {0}")]
    SRv6ServiceSubSubTlvError(#[from] SRv6ServiceSubSubTlvWritingError),
}
impl_from_io_error!(SRv6ServiceSubTlvWritingError);

impl WritablePdu<SRv6ServiceSubTlvWritingError> for SRv6ServiceSubTlv {
    const BASE_LENGTH: usize = 3;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + match self {
                SRv6ServiceSubTlv::SRv6SIDInformation { subsubtlvs, .. } => {
                    1 + 16
                        + 1
                        + 2
                        + 1
                        + subsubtlvs
                            .iter()
                            .map(|subsubtlv| subsubtlv.len())
                            .sum::<usize>()
                }
                SRv6ServiceSubTlv::Unknown { value, .. } => value.len(),
            }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), SRv6ServiceSubTlvWritingError> {
        write_tlv_header_t8_l16(writer, self.raw_code(), self.len() as u16)?;

        match self {
            SRv6ServiceSubTlv::SRv6SIDInformation {
                reserved1,
                sid,
                service_sid_flags,
                endpoint_behaviour,
                reserved2,
                subsubtlvs,
            } => {
                writer.write_all(&[*reserved1])?; // reserved1
                writer.write_all(&sid.octets())?;
                writer.write_all(&[*service_sid_flags])?;
                writer.write_all(&(*endpoint_behaviour).to_be_bytes())?;
                writer.write_all(&[*reserved2])?; // reserved2

                for subsubtlv in subsubtlvs {
                    subsubtlv.write(writer)?;
                }
            }
            SRv6ServiceSubTlv::Unknown { value, .. } => writer.write_all(value)?,
        }

        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum SRv6ServiceSubSubTlvWritingError {
    #[error("IO error while writing SRv6 service sub-sub-TLV: {0}")]
    StdIOError(Box<str>),
}
impl_from_io_error!(SRv6ServiceSubSubTlvWritingError);

impl WritablePdu<SRv6ServiceSubSubTlvWritingError> for SRv6ServiceSubSubTlv {
    const BASE_LENGTH: usize = 3;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + match self {
                SRv6ServiceSubSubTlv::SRv6SIDStructure { .. } => 6,
                SRv6ServiceSubSubTlv::Unknown { value, .. } => value.len(),
            }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), SRv6ServiceSubSubTlvWritingError> {
        write_tlv_header_t8_l16(writer, self.raw_code(), self.len() as u16)?;

        match self {
            SRv6ServiceSubSubTlv::SRv6SIDStructure {
                locator_block_len,
                locator_node_len,
                function_len,
                arg_len,
                transposition_len,
                transposition_offset,
            } => {
                writer.write_all(&[*locator_block_len])?;
                writer.write_all(&[*locator_node_len])?;
                writer.write_all(&[*function_len])?;
                writer.write_all(&[*arg_len])?;
                writer.write_all(&[*transposition_len])?;
                writer.write_all(&[*transposition_offset])?;
            }
            SRv6ServiceSubSubTlv::Unknown { value, .. } => {
                writer.write_all(value)?;
            }
        }

        Ok(())
    }
}
