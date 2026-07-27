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

use netgauze_parse_utils::{WritablePdu, WritablePduWithOneInput, impl_from_io_error};
use std::io::Write;

use crate::ipfix::*;
use crate::wire::serializer::FieldSpecifierWritingError;
use crate::wire::serializer::ie::FieldWritingError;

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum IpfixPacketWritingError {
    #[error("IO error while writing IPFIX packet: {0}")]
    StdIOError(Box<str>),

    #[error("in set: {0}")]
    SetError(#[from] SetWritingError),
}
impl_from_io_error!(IpfixPacketWritingError);

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
        // Every set's length is needed twice: once to make up the message
        // length in the header, and once as the set's own length field.
        // Computing it walks every field in the set, so compute it once here
        // and hand it down rather than letting `Set::write` recompute it.
        let set_lengths = self
            .sets()
            .iter()
            .map(|x| x.len(templates_map))
            .collect::<Vec<_>>();
        let length = Self::BASE_LENGTH + set_lengths.iter().sum::<usize>();
        writer.write_all(&self.version().to_be_bytes())?;
        writer.write_all(&(length as u16).to_be_bytes())?;
        writer.write_all(&(self.export_time().timestamp() as u32).to_be_bytes())?;
        writer.write_all(&self.sequence_number().to_be_bytes())?;
        writer.write_all(&self.observation_domain_id().to_be_bytes())?;
        for (set, len) in self.sets().iter().zip(set_lengths) {
            set.write_with_len(writer, templates_map, len)?;
        }
        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum TemplateRecordWritingError {
    #[error("IO error while writing template record: {0}")]
    StdIOError(Box<str>),

    #[error("in field specifier: {0}")]
    FieldSpecifierError(#[from] FieldSpecifierWritingError),
}
impl_from_io_error!(TemplateRecordWritingError);

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
        writer.write_all(&self.id().to_be_bytes())?;
        writer.write_all(&(self.field_specifiers().len() as u16).to_be_bytes())?;
        for field in self.field_specifiers() {
            field.write(writer)?;
        }
        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum OptionsTemplateRecordWritingError {
    #[error("IO error while writing options template record: {0}")]
    StdIOError(Box<str>),

    #[error("in field specifier: {0}")]
    FieldSpecifierError(#[from] FieldSpecifierWritingError),
}
impl_from_io_error!(OptionsTemplateRecordWritingError);

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
        writer.write_all(&self.id().to_be_bytes())?;
        writer.write_all(
            &((self.scope_field_specifiers().len() + self.field_specifiers().len()) as u16)
                .to_be_bytes(),
        )?;
        writer.write_all(&(self.scope_field_specifiers().len() as u16).to_be_bytes())?;
        for field in self.scope_field_specifiers() {
            field.write(writer)?;
        }
        for field in self.field_specifiers() {
            field.write(writer)?;
        }
        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum DataRecordWritingError {
    #[error("IO error while writing data record: {0}")]
    StdIOError(Box<str>),

    #[error("in field: {0}")]
    FieldError(#[from] FieldWritingError),
}
impl_from_io_error!(DataRecordWritingError);

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

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum SetWritingError {
    #[error("IO error while writing set: {0}")]
    StdIOError(Box<str>),

    #[error("in data record: {0}")]
    FlowError(#[from] DataRecordWritingError),

    #[error("in template record: {0}")]
    TemplateRecordError(#[from] TemplateRecordWritingError),

    #[error("in options template record: {0}")]
    OptionsTemplateRecordError(#[from] OptionsTemplateRecordWritingError),
}
impl_from_io_error!(SetWritingError);

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
        self.write_with_len(
            writer,
            templates_map,
            calculate_set_size(templates_map, self),
        )
    }
}

impl Set {
    /// Same as [`WritablePduWithOneInput::write`], but takes an already
    /// computed length so callers that need it anyway do not pay for a second
    /// walk over every field.
    fn write_with_len<T: Write>(
        &self,
        writer: &mut T,
        templates_map: Option<&TemplatesMap>,
        length: usize,
    ) -> Result<(), SetWritingError> {
        let length = length as u16;
        match self {
            Self::Template(records) => {
                writer.write_all(&IPFIX_TEMPLATE_SET_ID.to_be_bytes())?;
                writer.write_all(&length.to_be_bytes())?;
                for record in records {
                    record.write(writer)?;
                }
            }
            Self::OptionsTemplate(records) => {
                writer.write_all(&IPFIX_OPTIONS_TEMPLATE_SET_ID.to_be_bytes())?;
                writer.write_all(&length.to_be_bytes())?;
                for record in records {
                    record.write(writer)?;
                }
            }
            Self::Data { id, records } => {
                writer.write_all(&id.id().to_be_bytes())?;
                writer.write_all(&length.to_be_bytes())?;
                let decoding_template = templates_map.and_then(|x| x.get(&self.id()));
                for record in records {
                    record.write(writer, decoding_template)?;
                }
            }
        }
        Ok(())
    }
}
