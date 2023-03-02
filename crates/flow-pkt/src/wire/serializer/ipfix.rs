// Copyright (C) 2023-present The NetGauze Authors.
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

use byteorder::{NetworkEndian, WriteBytesExt};
use netgauze_parse_utils::{WritablePDU, WritablePDUWithOneInput};
use netgauze_serde_macros::WritingError;
use std::{io::Write, rc::Rc};

use crate::{
    ipfix::*,
    wire::serializer::{ie::FieldWritingError, FieldSpecifierWritingError},
};

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum IpfixPacketWritingError {
    StdIOError(#[from_std_io_error] String),
    SetError(#[from] SetWritingError),
}

impl WritablePDUWithOneInput<Option<TemplatesMap>, IpfixPacketWritingError> for IpfixPacket {
    /// 2-octets version, 2-octets length, 4-octets * 3 (export time, seq no,
    /// observation domain id)
    const BASE_LENGTH: usize = 16;

    fn len(&self, templates_map: Option<TemplatesMap>) -> usize {
        Self::BASE_LENGTH
            + self
                .sets()
                .iter()
                .map(|x| x.len(templates_map.clone()))
                .sum::<usize>()
    }

    fn write<T: Write>(
        &self,
        writer: &mut T,
        templates_map: Option<TemplatesMap>,
    ) -> Result<(), IpfixPacketWritingError> {
        writer.write_u16::<NetworkEndian>(self.version())?;
        writer.write_u16::<NetworkEndian>(self.len(templates_map.clone()) as u16)?;
        writer.write_u32::<NetworkEndian>(self.export_time().timestamp() as u32)?;
        writer.write_u32::<NetworkEndian>(self.sequence_number())?;
        writer.write_u32::<NetworkEndian>(self.observation_domain_id())?;
        for set in self.sets() {
            set.write(writer, templates_map.clone())?;
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
        Self::BASE_LENGTH
            + self
                .field_specifiers()
                .iter()
                .map(|x| x.len())
                .sum::<usize>()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), TemplateRecordWritingError> {
        writer.write_u16::<NetworkEndian>(self.id())?;
        writer.write_u16::<NetworkEndian>(self.field_specifiers().len() as u16)?;
        for field in self.field_specifiers() {
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
                .scope_field_specifiers()
                .iter()
                .map(|x| x.len())
                .sum::<usize>()
            + self
                .field_specifiers()
                .iter()
                .map(|x| x.len())
                .sum::<usize>()
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), OptionsTemplateRecordWritingError> {
        writer.write_u16::<NetworkEndian>(self.id())?;
        writer.write_u16::<NetworkEndian>(
            (self.scope_field_specifiers().len() + self.field_specifiers().len()) as u16,
        )?;
        writer.write_u16::<NetworkEndian>(self.scope_field_specifiers().len() as u16)?;
        for field in self.scope_field_specifiers() {
            field.write(writer)?;
        }
        for field in self.field_specifiers() {
            field.write(writer)?;
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum DataRecordWritingError {
    StdIOError(#[from_std_io_error] String),
    FieldError(#[from] FieldWritingError),
}

impl WritablePDUWithOneInput<Option<Rc<DecodingTemplate>>, DataRecordWritingError> for DataRecord {
    const BASE_LENGTH: usize = 0;

    fn len(&self, decoding_template: Option<Rc<DecodingTemplate>>) -> usize {
        let (scope_lens, field_lens) = match decoding_template {
            None => (None, None),
            Some(template) => {
                let (scope_fields_spec, fields_spec) = template.as_ref();
                let scope_lens = scope_fields_spec.iter().map(|x| x.length()).sum::<u16>();
                let fields_lens = fields_spec.iter().map(|x| x.length()).sum::<u16>();
                (Some(scope_lens), Some(fields_lens))
            }
        };
        let scope_fields_len = match scope_lens {
            Some(len) => len as usize,
            None => self
                .scope_fields()
                .iter()
                .map(|x| x.len(None))
                .sum::<usize>(),
        };
        let fields_len = match field_lens {
            Some(len) => len as usize,
            None => self.fields().iter().map(|x| x.len(None)).sum::<usize>(),
        };
        Self::BASE_LENGTH + scope_fields_len + fields_len
    }

    fn write<T: Write>(
        &self,
        writer: &mut T,
        decoding_template: Option<Rc<DecodingTemplate>>,
    ) -> Result<(), DataRecordWritingError> {
        let written = match decoding_template {
            None => None,
            Some(template) => {
                let (scope_fields_spec, fields_spec) = template.as_ref();
                for (index, record) in self.scope_fields().iter().enumerate() {
                    let field_length = scope_fields_spec.get(index).map(|x| x.length());
                    record.write(writer, field_length)?;
                }
                for (index, record) in self.fields().iter().enumerate() {
                    let field_length = fields_spec.get(index).map(|x| x.length());
                    record.write(writer, field_length)?;
                }
                Some(())
            }
        };
        match written {
            Some(_) => {}
            None => {
                for record in self.scope_fields() {
                    record.write(writer, None)?;
                }
                for record in self.fields() {
                    record.write(writer, None)?;
                }
            }
        };
        Ok(())
    }
}

/// Calculate padding such that next set starts at a 4-byte aligned boundary
#[inline]
fn calculate_set_size_with_padding(
    templates_map: Option<TemplatesMap>,
    set: &Set,
) -> (usize, usize) {
    let length = Set::BASE_LENGTH
        + match set {
            Set::Template(records) => records.iter().map(|x| x.len()).sum::<usize>(),
            Set::OptionsTemplate(records) => records.iter().map(|x| x.len()).sum::<usize>(),
            Set::Data { id: _, records } => {
                let decoding_template =
                    templates_map.and_then(|x| x.as_ref().borrow().get(&set.id()).cloned());
                records
                    .iter()
                    .map(|x| x.len(decoding_template.clone()))
                    .sum::<usize>()
            }
        };
    (length, length % 4)
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum SetWritingError {
    StdIOError(#[from_std_io_error] String),
    FlowError(#[from] DataRecordWritingError),
    TemplateRecordError(#[from] TemplateRecordWritingError),
    OptionsTemplateRecordError(#[from] OptionsTemplateRecordWritingError),
}

impl WritablePDUWithOneInput<Option<TemplatesMap>, SetWritingError> for Set {
    /// 2-octets set id + 2-octet set length
    const BASE_LENGTH: usize = 4;

    fn len(&self, templates_map: Option<TemplatesMap>) -> usize {
        let (length, padding) = calculate_set_size_with_padding(templates_map, self);
        length + padding
    }

    fn write<T: Write>(
        &self,
        writer: &mut T,
        templates_map: Option<TemplatesMap>,
    ) -> Result<(), SetWritingError> {
        let (length, padding) = calculate_set_size_with_padding(templates_map.clone(), self);
        let length = (length + padding) as u16;
        match self {
            Self::Template(records) => {
                writer.write_u16::<NetworkEndian>(IPFIX_TEMPLATE_SET_ID)?;
                writer.write_u16::<NetworkEndian>(length)?;
                for record in records {
                    record.write(writer)?;
                }
            }
            Self::OptionsTemplate(records) => {
                writer.write_u16::<NetworkEndian>(IPFIX_OPTIONS_TEMPLATE_SET_ID)?;
                writer.write_u16::<NetworkEndian>(length)?;
                for record in records {
                    record.write(writer)?;
                }
            }
            Self::Data { id, records } => {
                writer.write_u16::<NetworkEndian>(id.id())?;
                writer.write_u16::<NetworkEndian>(length)?;
                let decoding_template =
                    templates_map.and_then(|x| x.as_ref().borrow().get(&self.id()).cloned());
                for record in records {
                    record.write(writer, decoding_template.clone())?;
                }
            }
        }
        for _ in 0..padding {
            writer.write_u8(0x00)?;
        }
        Ok(())
    }
}
