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
use netgauze_parse_utils::{WritablePdu, WritablePduWithOneInput};
use netgauze_serde_macros::WritingError;
use std::io::Write;

use crate::ipfix::*;
use crate::wire::serializer::FieldSpecifierWritingError;
use crate::wire::serializer::ie::FieldWritingError;

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum IpfixPacketWritingError {
    StdIOError(#[from_std_io_error] String),
    SetError(#[from] SetWritingError),
}

impl std::fmt::Display for IpfixPacketWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::SetError(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for IpfixPacketWritingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::StdIOError(_) => None,
            Self::SetError(err) => Some(err),
        }
    }
}

impl WritablePduWithOneInput<Option<&TemplatesMap>, IpfixPacketWritingError> for IpfixPacket {
    /// 2-octets version, 2-octets length, 4-octets * 3 (export time, seq no,
    /// observation domain id)
    const BASE_LENGTH: usize = 16;

    fn len(&self, templates_map: Option<&TemplatesMap>) -> usize {
        Self::BASE_LENGTH
            + self
                .sets()
                .iter()
                .map(|x| x.len(templates_map))
                .sum::<usize>()
    }

    fn write<T: Write>(
        &self,
        writer: &mut T,
        templates_map: Option<&TemplatesMap>,
    ) -> Result<(), IpfixPacketWritingError> {
        writer.write_u16::<NetworkEndian>(self.version())?;
        writer.write_u16::<NetworkEndian>(self.len(templates_map) as u16)?;
        writer.write_u32::<NetworkEndian>(self.export_time().timestamp() as u32)?;
        writer.write_u32::<NetworkEndian>(self.sequence_number())?;
        writer.write_u32::<NetworkEndian>(self.observation_domain_id())?;
        for set in self.sets() {
            set.write(writer, templates_map)?;
        }
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum TemplateRecordWritingError {
    StdIOError(#[from_std_io_error] String),
    FieldSpecifierError(#[from] FieldSpecifierWritingError),
}

impl std::fmt::Display for TemplateRecordWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::FieldSpecifierError(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for TemplateRecordWritingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::StdIOError(_) => None,
            Self::FieldSpecifierError(err) => Some(err),
        }
    }
}

impl WritablePdu<TemplateRecordWritingError> for TemplateRecord {
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

impl std::fmt::Display for OptionsTemplateRecordWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::FieldSpecifierError(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for OptionsTemplateRecordWritingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::StdIOError(_) => None,
            Self::FieldSpecifierError(err) => Some(err),
        }
    }
}

impl WritablePdu<OptionsTemplateRecordWritingError> for OptionsTemplateRecord {
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

impl std::fmt::Display for DataRecordWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::FieldError(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for DataRecordWritingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::StdIOError(_) => None,
            Self::FieldError(err) => Some(err),
        }
    }
}

impl WritablePduWithOneInput<Option<&DecodingTemplate>, DataRecordWritingError> for DataRecord {
    const BASE_LENGTH: usize = 0;

    fn len(&self, decoding_template: Option<&DecodingTemplate>) -> usize {
        let (scope_fields_len, fields_len) = match decoding_template {
            None => {
                let scope_fields = self
                    .scope_fields()
                    .iter()
                    .map(|x| x.len(None))
                    .sum::<usize>();
                let data_fields = self.fields().iter().map(|x| x.len(None)).sum::<usize>();
                (scope_fields, data_fields)
            }
            Some(template) => {
                let scope_lens = self
                    .scope_fields()
                    .iter()
                    .enumerate()
                    .map(|(index, record)| {
                        {
                            template.scope_fields_specs.get(index).map(|x| {
                                if x.length() == u16::MAX {
                                    record.len(Some(x.length()))
                                } else {
                                    x.length() as usize
                                }
                            })
                        }
                        .unwrap_or(record.len(None))
                    })
                    .sum::<usize>();
                let fields_lens = self
                    .fields()
                    .iter()
                    .enumerate()
                    .map(|(index, record)| {
                        {
                            template.fields_specs.get(index).map(|x| {
                                if x.length() == u16::MAX {
                                    record.len(Some(x.length()))
                                } else {
                                    x.length() as usize
                                }
                            })
                        }
                        .unwrap_or(record.len(None))
                    })
                    .sum::<usize>();
                (scope_lens, fields_lens)
            }
        };
        Self::BASE_LENGTH + scope_fields_len + fields_len
    }

    fn write<T: Write>(
        &self,
        writer: &mut T,
        decoding_template: Option<&DecodingTemplate>,
    ) -> Result<(), DataRecordWritingError> {
        match decoding_template {
            None => {
                for record in self.scope_fields() {
                    record.write(writer, None)?;
                }
                for record in self.fields() {
                    record.write(writer, None)?;
                }
            }
            Some(template) => {
                for (index, record) in self.scope_fields().iter().enumerate() {
                    record.write(
                        writer,
                        template.scope_fields_specs.get(index).map(|x| x.length),
                    )?;
                }
                for (index, record) in self.fields().iter().enumerate() {
                    record.write(writer, template.fields_specs.get(index).map(|x| x.length))?;
                }
            }
        };
        Ok(())
    }
}

/// Calculate Set size
#[inline]
fn calculate_set_size(templates_map: Option<&TemplatesMap>, set: &Set) -> usize {
    let base_length = Set::BASE_LENGTH;
    let length = match set {
        Set::Template(records) => records.iter().map(|x| x.len()).sum::<usize>(),
        Set::OptionsTemplate(records) => records.iter().map(|x| x.len()).sum::<usize>(),
        Set::Data { id: _, records } => {
            let decoding_template = templates_map.and_then(|x| x.get(&set.id()));
            records
                .iter()
                .map(|x| x.len(decoding_template))
                .sum::<usize>()
        }
    };
    length + base_length
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum SetWritingError {
    StdIOError(#[from_std_io_error] String),
    FlowError(#[from] DataRecordWritingError),
    TemplateRecordError(#[from] TemplateRecordWritingError),
    OptionsTemplateRecordError(#[from] OptionsTemplateRecordWritingError),
}

impl std::fmt::Display for SetWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::FlowError(err) => write!(f, "{err}"),
            Self::TemplateRecordError(err) => write!(f, "{err}"),
            Self::OptionsTemplateRecordError(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for SetWritingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::StdIOError(_) => None,
            Self::FlowError(err) => Some(err),
            Self::TemplateRecordError(err) => Some(err),
            Self::OptionsTemplateRecordError(err) => Some(err),
        }
    }
}

impl WritablePduWithOneInput<Option<&TemplatesMap>, SetWritingError> for Set {
    /// 2-octets set id + 2-octet set length
    const BASE_LENGTH: usize = 4;

    fn len(&self, templates_map: Option<&TemplatesMap>) -> usize {
        calculate_set_size(templates_map, self)
    }

    fn write<T: Write>(
        &self,
        writer: &mut T,
        templates_map: Option<&TemplatesMap>,
    ) -> Result<(), SetWritingError> {
        let length = calculate_set_size(templates_map, self) as u16;
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
                let decoding_template = templates_map.and_then(|x| x.get(&self.id()));
                for record in records {
                    record.write(writer, decoding_template)?;
                }
            }
        }
        Ok(())
    }
}
