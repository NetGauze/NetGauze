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

use crate::{
    ie::InformationElementTemplate,
    netflow::*,
    wire::{
        deserializer::netflow::NETFLOW_V9_HEADER_LENGTH,
        serializer::{ie::FieldWritingError, FieldSpecifierWritingError},
    },
};
use byteorder::{NetworkEndian, WriteBytesExt};
use netgauze_parse_utils::{WritablePDU, WritablePDUWithOneInput};
use netgauze_serde_macros::WritingError;
use std::{io::Write, rc::Rc};

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum NetFlowV9WritingError {
    StdIOError(#[from_std_io_error] String),
    SetError(#[from] SetWritingError),
}

impl WritablePDUWithOneInput<Option<TemplatesMap>, NetFlowV9WritingError> for NetFlowV9Packet {
    /// 2-octets version, 2-octets count, 4-octets * 4 for meta data
    const BASE_LENGTH: usize = NETFLOW_V9_HEADER_LENGTH as usize;

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
    ) -> Result<(), NetFlowV9WritingError> {
        let count = self
            .sets()
            .iter()
            .map(|x| match &x {
                Set::Data { id: _, records } => records.len(),
                Set::Template(records) => records.len(),
                Set::OptionsTemplate(records) => records.len(),
            })
            .sum::<usize>() as u16;
        writer.write_u16::<NetworkEndian>(self.version())?;
        writer.write_u16::<NetworkEndian>(count)?;
        writer.write_u32::<NetworkEndian>(self.sys_up_time())?;
        writer.write_u32::<NetworkEndian>(self.unix_time().timestamp() as u32)?;
        writer.write_u32::<NetworkEndian>(self.sequence_number())?;
        writer.write_u32::<NetworkEndian>(self.source_id())?;
        for set in self.sets() {
            set.write(writer, templates_map.clone())?;
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum SetWritingError {
    StdIOError(#[from_std_io_error] String),
    DataRecordError(#[from] DataRecordWritingError),
    TemplateRecordError(#[from] TemplateRecordWritingError),
    OptionsTemplateRecordError(#[from] OptionsTemplateRecordWritingError),
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

impl WritablePDUWithOneInput<Option<TemplatesMap>, SetWritingError> for Set {
    /// 2-octets set id + 2-octet set length
    const BASE_LENGTH: usize = 4;

    fn len(&self, template_map: Option<TemplatesMap>) -> usize {
        let (length, padding) = calculate_set_size_with_padding(template_map, self);
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
                writer.write_u16::<NetworkEndian>(NETFLOW_TEMPLATE_SET_ID)?;
                writer.write_u16::<NetworkEndian>(length)?;
                for record in records {
                    record.write(writer)?;
                }
            }
            Self::OptionsTemplate(records) => {
                writer.write_u16::<NetworkEndian>(NETFLOW_OPTIONS_TEMPLATE_SET_ID)?;
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
    ScopeFieldSpecifierError(#[from] ScopeFieldSpecifierWritingError),
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
            self.scope_field_specifiers()
                .iter()
                .map(|x| x.len())
                .sum::<usize>() as u16,
        )?;
        writer.write_u16::<NetworkEndian>(
            self.field_specifiers()
                .iter()
                .map(|x| x.len())
                .sum::<usize>() as u16,
        )?;
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
    ScopeFieldError(#[from] ScopeFieldWritingError),
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
                for record in self.scope_fields().iter() {
                    record.write(writer, None)?;
                }
                for record in self.fields().iter() {
                    record.write(writer, None)?;
                }
            }
        };
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ScopeFieldSpecifierWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePDU<ScopeFieldSpecifierWritingError> for ScopeFieldSpecifier {
    /// 2-octets field id, 2-octets length
    const BASE_LENGTH: usize = 4;

    fn len(&self) -> usize {
        Self::BASE_LENGTH + if self.element_id().pen() == 0 { 0 } else { 4 }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), ScopeFieldSpecifierWritingError> {
        writer.write_u16::<NetworkEndian>(self.element_id().id())?;
        writer.write_u16::<NetworkEndian>(self.length())?;
        let pen = self.element_id().pen();
        if pen != 0 {
            writer.write_u32::<NetworkEndian>(pen)?;
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ScopeFieldWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePDUWithOneInput<Option<u16>, ScopeFieldWritingError> for ScopeField {
    /// 2-octets field id, 2-octets length
    const BASE_LENGTH: usize = 0;

    fn len(&self, length: Option<u16>) -> usize {
        match self {
            ScopeField::Unknown { value, .. } => value.len(),
            ScopeField::System(System(value)) => value.len(),
            ScopeField::Interface(_) => match length {
                None => 4,
                Some(len) => len as usize,
            },
            ScopeField::LineCard(_) => match length {
                None => 4,
                Some(len) => len as usize,
            },
            ScopeField::Cache(Cache(value)) => value.len(),
            ScopeField::Template(Template(value)) => value.len(),
        }
    }

    fn write<T: Write>(
        &self,
        writer: &mut T,
        length: Option<u16>,
    ) -> Result<(), ScopeFieldWritingError> {
        match self {
            ScopeField::Unknown { value, .. } => {
                writer.write_all(value)?;
            }
            ScopeField::System(System(value)) => {
                writer.write_all(value.as_bytes())?;
                match length {
                    None => {}
                    Some(length) => {
                        for _ in value.as_bytes().len()..(length as usize) {
                            writer.write_u8(0)?;
                        }
                    }
                }
            }
            ScopeField::Interface(Interface(value)) => match length {
                None => writer.write_u32::<NetworkEndian>(*value)?,
                Some(len) => {
                    let be_bytes = value.to_be_bytes();
                    let begin_offset = be_bytes.len() - len as usize;
                    writer.write_all(&be_bytes[begin_offset..])?;
                }
            },
            ScopeField::LineCard(LineCard(value)) => match length {
                None => writer.write_u32::<NetworkEndian>(*value)?,
                Some(len) => {
                    let be_bytes = value.to_be_bytes();
                    let begin_offset = be_bytes.len() - len as usize;
                    writer.write_all(&be_bytes[begin_offset..])?;
                }
            },
            ScopeField::Cache(Cache(value)) => {
                writer.write_all(value)?;
            }
            ScopeField::Template(Template(value)) => {
                writer.write_all(value)?;
            }
        }
        Ok(())
    }
}
