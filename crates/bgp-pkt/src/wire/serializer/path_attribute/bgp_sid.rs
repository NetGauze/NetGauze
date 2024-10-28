use std::io::Write;

use byteorder::{NetworkEndian, WriteBytesExt};

use netgauze_parse_utils::{WritablePdu, WritablePduWithOneInput};
use netgauze_serde_macros::WritingError;

use crate::{
    path_attribute::{
        BgpSidAttribute, PrefixSegmentIdentifier, SRv6ServiceSubSubTlv, SRv6ServiceSubTlv,
        SegmentRoutingGlobalBlock,
    },
    wire::serializer::{
        nlri::MplsLabelWritingError, path_attribute::write_length, write_tlv_header_t8_l16,
    },
};

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum SegmentIdentifierWritingError {
    StdIOError(#[from_std_io_error] String),
    BgpSidAttributeWritingError(#[from] BgpSidAttributeWritingError),
}

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
    ) -> Result<(), SegmentIdentifierWritingError>
    where
        Self: Sized,
    {
        write_length(self, extended_length, writer)?;

        for tlv in self.tlvs() {
            tlv.write(writer)?;
        }

        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum BgpSidAttributeWritingError {
    StdIOError(#[from_std_io_error] String),
    BgpSidSrgb(#[from] SrgbWritingError),
    BgpSRv6SubTlvService(#[from] SRv6ServiceSubTlvWritingError),
}

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

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpSidAttributeWritingError>
    where
        Self: Sized,
    {
        write_tlv_header_t8_l16(writer, self.raw_code(), self.len() as u16)?;

        match self {
            BgpSidAttribute::LabelIndex { label_index, flags } => {
                writer.write_u8(0)?; // reserved 8 bits
                writer.write_u16::<NetworkEndian>(*flags)?;
                writer.write_u32::<NetworkEndian>(*label_index)?;
            }
            BgpSidAttribute::Originator { flags, srgbs } => {
                writer.write_u16::<NetworkEndian>(*flags)?;
                for srgb in srgbs {
                    srgb.write(writer)?;
                }
            }
            BgpSidAttribute::SRv6ServiceL3 { reserved, subtlvs } => {
                writer.write_u8(*reserved)?;
                for subtlv in subtlvs {
                    subtlv.write(writer)?;
                }
            }
            BgpSidAttribute::SRv6ServiceL2 { reserved, subtlvs } => {
                writer.write_u8(*reserved)?;
                for subtlv in subtlvs {
                    subtlv.write(writer)?;
                }
            }
            BgpSidAttribute::Unknown { code, value } => {
                writer.write_u8(*code)?;
                writer.write_all(value)?;
            }
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum SrgbWritingError {
    StdIOError(#[from_std_io_error] String),
    MplsLabelError(#[from] MplsLabelWritingError),
}

impl WritablePdu<SrgbWritingError> for SegmentRoutingGlobalBlock {
    const BASE_LENGTH: usize = 6; /* 3 bytes MPLS Label + 3 bytes range size */

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), SrgbWritingError>
    where
        Self: Sized,
    {
        self.first_label.write(writer)?;
        writer.write_all(&self.range_size)?;

        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum SRv6ServiceSubTlvWritingError {
    StdIOError(#[from_std_io_error] String),
    SRv6ServiceSubSubTlvError(#[from] SRv6ServiceSubSubTlvWritingError),
}

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

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), SRv6ServiceSubTlvWritingError>
    where
        Self: Sized,
    {
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
                writer.write_u8(*reserved1)?; // reserved1
                writer.write_u128::<NetworkEndian>(*sid)?;
                writer.write_u8(*service_sid_flags)?;
                writer.write_u16::<NetworkEndian>(*endpoint_behaviour)?;
                writer.write_u8(*reserved2)?; // reserved2

                for subsubtlv in subsubtlvs {
                    subsubtlv.write(writer)?;
                }
            }
            SRv6ServiceSubTlv::Unknown { value, .. } => writer.write_all(value)?,
        }

        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum SRv6ServiceSubSubTlvWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePdu<SRv6ServiceSubSubTlvWritingError> for SRv6ServiceSubSubTlv {
    const BASE_LENGTH: usize = 3;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + match self {
                SRv6ServiceSubSubTlv::SRv6SIDStructure { .. } => 6,
                SRv6ServiceSubSubTlv::Unknown { value, .. } => value.len(),
            }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), SRv6ServiceSubSubTlvWritingError>
    where
        Self: Sized,
    {
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
                writer.write_u8(*locator_block_len)?;
                writer.write_u8(*locator_node_len)?;
                writer.write_u8(*function_len)?;
                writer.write_u8(*arg_len)?;
                writer.write_u8(*transposition_len)?;
                writer.write_u8(*transposition_offset)?;
            }
            SRv6ServiceSubSubTlv::Unknown { value, .. } => {
                writer.write_all(value)?;
            }
        }

        Ok(())
    }
}
