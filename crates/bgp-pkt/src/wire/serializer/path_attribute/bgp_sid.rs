use std::io::Write;

use byteorder::{NetworkEndian, WriteBytesExt};

use netgauze_parse_utils::{WritablePdu, WritablePduWithOneInput};
use netgauze_serde_macros::WritingError;

use crate::{
    path_attribute::{BgpSidAttribute, SegmentIdentifier, SRGB},
    wire::serializer::{nlri::MplsLabelWritingError, path_attribute::write_length},
};

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum SegmentIdentifierWritingError {
    StdIOError(#[from_std_io_error] String),
    BgpSidAttributeWritingError(#[from] BgpSidAttributeWritingError),
}

impl WritablePduWithOneInput<bool, SegmentIdentifierWritingError> for SegmentIdentifier {
    // One is extended length is not enabled, the rest is variable
    const BASE_LENGTH: usize = 1;

    fn len(&self, extended_length: bool) -> usize {
        let len = Self::BASE_LENGTH;

        len + usize::from(extended_length) + self.tlvs.iter().map(|tlv| tlv.len()).sum::<usize>()
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

        for tlv in &self.tlvs {
            tlv.write(writer)?;
        }

        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum BgpSidAttributeWritingError {
    StdIOError(#[from_std_io_error] String),
    BgpSidSrgbError(#[from] SrgbWritingError),
}

impl WritablePdu<BgpSidAttributeWritingError> for BgpSidAttribute {
    const BASE_LENGTH: usize = 3; /* type u8 + length u16 */

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + match self {
                BgpSidAttribute::LabelIndex { .. } => 7,
                BgpSidAttribute::Originator { srgbs, .. } => 2 + 6 * srgbs.len(),
                BgpSidAttribute::Unknown { value, .. } => value.len(),
            }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), BgpSidAttributeWritingError>
    where
        Self: Sized,
    {
        writer.write_u8(self.raw_code())?;
        writer.write_u16::<NetworkEndian>((self.len() - Self::BASE_LENGTH) as u16)?;

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

impl WritablePdu<SrgbWritingError> for SRGB {
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
