// Copyright (C) 2022-present The NetGauze Authors.
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

pub mod ie;
use crate::{
    ie::InformationElementTemplate, wire::serializer::ie::RecordWritingError, DataRecord,
    FieldSpecifier, Flow, IpfixHeader, IpfixPacket, OptionsTemplateRecord, Set, SetPayload,
    TemplateRecord,
};
use byteorder::{NetworkEndian, WriteBytesExt};
use netgauze_parse_utils::{WritablePDU, WritablePDUWithOneInput};
use netgauze_serde_macros::WritingError;
use std::io::Write;

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum IpfixPacketWritingError {
    StdIOError(#[from_std_io_error] String),
    IpfixHeaderError(#[from] IpfixHeaderWritingError),
    SetError(#[from] SetWritingError),
}

impl WritablePDUWithOneInput<Option<&[Option<u16>]>, IpfixPacketWritingError> for IpfixPacket {
    /// 2-octets version, 2-octets length, 4-octets * 3 (export time, seq no,
    /// observation domain id)
    const BASE_LENGTH: usize = 16;

    fn len(&self, lengths: Option<&[Option<u16>]>) -> usize {
        Self::BASE_LENGTH + self.payload.iter().map(|x| x.len(lengths)).sum::<usize>()
    }

    fn write<T: Write>(
        &self,
        writer: &mut T,
        lengths: Option<&[Option<u16>]>,
    ) -> Result<(), IpfixPacketWritingError> {
        writer.write_u16::<NetworkEndian>(self.header.version)?;
        writer.write_u16::<NetworkEndian>(self.len(lengths) as u16)?;
        writer.write_u32::<NetworkEndian>(self.header.export_time.timestamp() as u32)?;
        writer.write_u32::<NetworkEndian>(self.header.sequence_number)?;
        writer.write_u32::<NetworkEndian>(self.header.observation_domain_id)?;
        for set in &self.payload {
            set.write(writer, lengths)?;
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum IpfixHeaderWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePDU<IpfixHeaderWritingError> for IpfixHeader {
    /// 2-octets version, 2-octets length, 4-octets * 3 (export time, seq no,
    /// observation domain id)
    const BASE_LENGTH: usize = 16;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), IpfixHeaderWritingError> {
        writer.write_u16::<NetworkEndian>(self.version)?;
        writer.write_u16::<NetworkEndian>(self.len() as u16)?;
        writer.write_u32::<NetworkEndian>(self.export_time.timestamp() as u32)?;
        writer.write_u32::<NetworkEndian>(self.sequence_number)?;
        writer.write_u32::<NetworkEndian>(self.observation_domain_id)?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum FieldSpecifierWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePDU<FieldSpecifierWritingError> for FieldSpecifier {
    /// 2-octets field id, 2-octets length
    const BASE_LENGTH: usize = 4;

    fn len(&self) -> usize {
        Self::BASE_LENGTH + if self.element_id.pen() == 0 { 0 } else { 4 }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), FieldSpecifierWritingError> {
        writer.write_u16::<NetworkEndian>(self.element_id.id())?;
        writer.write_u16::<NetworkEndian>(self.length)?;
        let pen = self.element_id.pen();
        if pen != 0 {
            writer.write_u32::<NetworkEndian>(pen)?;
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum TemplateRecordWritingError {
    StdIOError(#[from_std_io_error] String),
    FieldSpecifierError(#[from] FieldSpecifierWritingError),
}

impl WritablePDU<TemplateRecordWritingError> for TemplateRecord {
    /// 2-octets template_id, 2-octets field count
    const BASE_LENGTH: usize = 4;

    fn len(&self) -> usize {
        Self::BASE_LENGTH + self.field_specifiers.iter().map(|x| x.len()).sum::<usize>()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), TemplateRecordWritingError> {
        writer.write_u16::<NetworkEndian>(self.id)?;
        writer.write_u16::<NetworkEndian>(self.field_specifiers.len() as u16)?;
        for field in &self.field_specifiers {
            field.write(writer)?;
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum OptionsTemplateRecordWritingError {
    StdIOError(#[from_std_io_error] String),
    FieldSpecifierError(#[from] FieldSpecifierWritingError),
}

impl WritablePDU<OptionsTemplateRecordWritingError> for OptionsTemplateRecord {
    /// 2-octets template_id, 2-octets fields count, 2-octet scope fields count
    const BASE_LENGTH: usize = 6;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
            + self
                .scope_field_specifiers
                .iter()
                .map(|x| x.len())
                .sum::<usize>()
            + self.field_specifiers.iter().map(|x| x.len()).sum::<usize>()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), OptionsTemplateRecordWritingError> {
        writer.write_u16::<NetworkEndian>(self.id)?;
        writer.write_u16::<NetworkEndian>(
            (self.scope_field_specifiers.len() + self.field_specifiers.len()) as u16,
        )?;
        writer.write_u16::<NetworkEndian>(self.scope_field_specifiers.len() as u16)?;
        for field in &self.scope_field_specifiers {
            field.write(writer)?;
        }
        for field in &self.field_specifiers {
            field.write(writer)?;
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum DataRecordWritingError {
    StdIOError(#[from_std_io_error] String),
    FlowError(#[from] FlowWritingError),
}

impl WritablePDUWithOneInput<Option<&[Option<u16>]>, DataRecordWritingError> for DataRecord {
    const BASE_LENGTH: usize = 0;

    fn len(&self, lengths: Option<&[Option<u16>]>) -> usize {
        Self::BASE_LENGTH + self.flows.iter().map(|x| x.len(lengths)).sum::<usize>()
    }

    fn write<T: Write>(
        &self,
        writer: &mut T,
        lengths: Option<&[Option<u16>]>,
    ) -> Result<(), DataRecordWritingError> {
        for flow in &self.flows {
            flow.write(writer, lengths)?;
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum FlowWritingError {
    StdIOError(#[from_std_io_error] String),
    RecordError(#[from] RecordWritingError),
}

impl WritablePDUWithOneInput<Option<&[Option<u16>]>, FlowWritingError> for Flow {
    const BASE_LENGTH: usize = 0;

    fn len(&self, lengths: Option<&[Option<u16>]>) -> usize {
        Self::BASE_LENGTH
            + match lengths {
                None => self.records.iter().map(|x| x.len(None)).sum::<usize>(),
                Some(lengths) => self
                    .records
                    .iter()
                    .enumerate()
                    .map(|(i, x)| x.len(*lengths.get(i).unwrap_or(&None)))
                    .sum::<usize>(),
            }
    }

    fn write<T: Write>(
        &self,
        writer: &mut T,
        lengths: Option<&[Option<u16>]>,
    ) -> Result<(), FlowWritingError> {
        match lengths {
            None => {
                for record in self.records.iter() {
                    record.write(writer, None)?;
                }
            }
            Some(lengths) => {
                for (index, record) in self.records.iter().enumerate() {
                    record.write(writer, *lengths.get(index).unwrap_or(&None))?;
                }
            }
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum SetWritingError {
    StdIOError(#[from_std_io_error] String),
    SetPayloadError(#[from] SetPayloadWritingError),
}

impl WritablePDUWithOneInput<Option<&[Option<u16>]>, SetWritingError> for Set {
    /// 2-octets set id + 2-octet set length
    const BASE_LENGTH: usize = 4;

    fn len(&self, lengths: Option<&[Option<u16>]>) -> usize {
        Self::BASE_LENGTH + self.payload.len(lengths)
    }

    fn write<T: Write>(
        &self,
        writer: &mut T,
        lengths: Option<&[Option<u16>]>,
    ) -> Result<(), SetWritingError> {
        writer.write_u16::<NetworkEndian>(self.id)?;
        writer.write_u16::<NetworkEndian>(self.len(lengths) as u16)?;
        self.payload.write(writer, lengths)?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum SetPayloadWritingError {
    StdIOError(#[from_std_io_error] String),
    DataRecordError(#[from] DataRecordWritingError),
    TemplateRecordError(#[from] TemplateRecordWritingError),
    OptionsTemplateRecordError(#[from] OptionsTemplateRecordWritingError),
}

impl WritablePDUWithOneInput<Option<&[Option<u16>]>, SetPayloadWritingError> for SetPayload {
    const BASE_LENGTH: usize = 0;

    fn len(&self, lengths: Option<&[Option<u16>]>) -> usize {
        Self::BASE_LENGTH
            + match self {
                SetPayload::Data(value) => value.iter().map(|x| x.len(lengths)).sum::<usize>(),
                SetPayload::Template(value) => value.iter().map(|x| x.len()).sum::<usize>(),
                SetPayload::OptionsTemplate(value) => value.iter().map(|x| x.len()).sum::<usize>(),
            }
    }

    fn write<T: Write>(
        &self,
        writer: &mut T,
        lengths: Option<&[Option<u16>]>,
    ) -> Result<(), SetPayloadWritingError> {
        match self {
            SetPayload::Data(value) => {
                for record in value {
                    record.write(writer, lengths)?;
                }
            }
            SetPayload::Template(value) => {
                for record in value {
                    record.write(writer)?;
                }
            }
            SetPayload::OptionsTemplate(value) => {
                for record in value {
                    record.write(writer)?;
                }
            }
        }
        Ok(())
    }
}
