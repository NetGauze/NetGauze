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

use crate::ie::InformationElementTemplate;
use crate::netflow::*;
use crate::wire::deserializer::netflow::NETFLOW_V9_HEADER_LENGTH;
use crate::wire::serializer::FieldSpecifierWritingError;
use crate::wire::serializer::ie::FieldWritingError;
use netgauze_parse_utils::{
    WritablePdu, WritablePduWithOneInput, WritablePduWithTwoInputs, impl_from_io_error,
};
use std::io::Write;

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum NetFlowV9WritingError {
    #[error("IO error while writing NetFlow V9 packet: {0}")]
    StdIOError(Box<str>),

    #[error("in set: {0}")]
    SetError(#[from] SetWritingError),
}
impl_from_io_error!(NetFlowV9WritingError);

/// [RFC 3954](https://www.rfc-editor.org/rfc/rfc3954) defines padding to 4-bytes start as
/// SHOULD (optional). The second option is a boolean to indicate if padding
/// should be included in the output.
impl WritablePduWithTwoInputs<Option<&TemplatesMap>, bool, NetFlowV9WritingError>
    for NetFlowV9Packet
{
    /// 2-octets version, 2-octets count, 4-octets * 4 for metadata
    const BASE_LENGTH: usize = NETFLOW_V9_HEADER_LENGTH as usize;

    fn len(&self, templates_map: Option<&TemplatesMap>, align_to_4_bytes: bool) -> usize {
        <Self as WritablePduWithTwoInputs<_, _, _>>::BASE_LENGTH
            + self
                .sets()
                .iter()
                .map(|x| x.len(templates_map, align_to_4_bytes))
                .sum::<usize>()
    }

    fn write<T: Write>(
        &self,
        writer: &mut T,
        templates_map: Option<&TemplatesMap>,
        align_to_4_bytes: bool,
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
        writer.write_all(&self.version().to_be_bytes())?;
        writer.write_all(&count.to_be_bytes())?;
        writer.write_all(&self.sys_up_time().to_be_bytes())?;
        writer.write_all(&(self.unix_time().timestamp() as u32).to_be_bytes())?;
        writer.write_all(&self.sequence_number().to_be_bytes())?;
        writer.write_all(&self.source_id().to_be_bytes())?;
        for set in self.sets() {
            set.write(writer, templates_map, align_to_4_bytes)?;
        }
        Ok(())
    }
}

impl WritablePduWithOneInput<Option<&TemplatesMap>, NetFlowV9WritingError> for NetFlowV9Packet {
    const BASE_LENGTH: usize = 0;

    fn len(&self, templates_map: Option<&TemplatesMap>) -> usize {
        <Self as WritablePduWithTwoInputs<_, _, _>>::len(self, templates_map, false)
    }

    fn write<T: Write>(
        &self,
        writer: &mut T,
        templates_map: Option<&TemplatesMap>,
    ) -> Result<(), NetFlowV9WritingError> {
        <Self as WritablePduWithTwoInputs<_, _, _>>::write(self, writer, templates_map, false)
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum SetWritingError {
    #[error("IO error while writing set: {0}")]
    StdIOError(Box<str>),

    #[error("in data record: {0}")]
    DataRecordError(#[from] DataRecordWritingError),

    #[error("in template record: {0}")]
    TemplateRecordError(#[from] TemplateRecordWritingError),

    #[error("in options template record: {0}")]
    OptionsTemplateRecordError(#[from] OptionsTemplateRecordWritingError),
}
impl_from_io_error!(SetWritingError);

/// Calculate padding such that next set starts at a 4-byte aligned boundary
#[inline]
fn calculate_set_size_with_padding(
    templates_map: Option<&TemplatesMap>,
    align_to_4_bytes: bool,
    set: &Set,
) -> (usize, usize) {
    let length = Set::BASE_LENGTH
        + match set {
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
    if align_to_4_bytes {
        (length, length % 4)
    } else {
        (length, 0)
    }
}

impl WritablePduWithTwoInputs<Option<&TemplatesMap>, bool, SetWritingError> for Set {
    /// 2-octets set id + 2-octet set length
    const BASE_LENGTH: usize = 4;

    fn len(&self, template_map: Option<&TemplatesMap>, align_to_4_bytes: bool) -> usize {
        let (length, padding) =
            calculate_set_size_with_padding(template_map, align_to_4_bytes, self);
        length + padding
    }

    fn write<T: Write>(
        &self,
        writer: &mut T,
        templates_map: Option<&TemplatesMap>,
        align_to_4_bytes: bool,
    ) -> Result<(), SetWritingError> {
        let (length, padding) =
            calculate_set_size_with_padding(templates_map, align_to_4_bytes, self);
        let length = (length + padding) as u16;
        match self {
            Self::Template(records) => {
                writer.write_all(&NETFLOW_TEMPLATE_SET_ID.to_be_bytes())?;
                writer.write_all(&length.to_be_bytes())?;
                for record in records {
                    record.write(writer)?;
                }
            }
            Self::OptionsTemplate(records) => {
                writer.write_all(&NETFLOW_OPTIONS_TEMPLATE_SET_ID.to_be_bytes())?;
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
        for _ in 0..padding {
            writer.write_all(&[0x00])?;
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

    #[error("in scope field specifier: {0}")]
    ScopeFieldSpecifierError(#[from] ScopeFieldSpecifierWritingError),

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
            &(self
                .scope_field_specifiers()
                .iter()
                .map(|x| x.len())
                .sum::<usize>() as u16)
                .to_be_bytes(),
        )?;
        writer.write_all(
            &(self
                .field_specifiers()
                .iter()
                .map(|x| x.len())
                .sum::<usize>() as u16)
                .to_be_bytes(),
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

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum DataRecordWritingError {
    #[error("IO error while writing data record: {0}")]
    StdIOError(Box<str>),

    #[error("in scope field: {0}")]
    ScopeFieldError(#[from] ScopeFieldWritingError),

    #[error("in field: {0}")]
    FieldError(#[from] FieldWritingError),
}
impl_from_io_error!(DataRecordWritingError);

impl WritablePduWithOneInput<Option<&DecodingTemplate>, DataRecordWritingError> for DataRecord {
    const BASE_LENGTH: usize = 0;

    fn len(&self, decoding_template: Option<&DecodingTemplate>) -> usize {
        let (scope_lens, field_lens) = match decoding_template {
            None => (None, None),
            Some(template) => {
                let scope_lens = template
                    .scope_fields_specs
                    .iter()
                    .map(|x| x.length() as usize)
                    .sum::<usize>();
                let fields_lens = template
                    .fields_specs
                    .iter()
                    .map(|x| x.length() as usize)
                    .sum::<usize>();
                (Some(scope_lens), Some(fields_lens))
            }
        };
        let scope_fields_len = match scope_lens {
            Some(len) => len,
            None => self
                .scope_fields()
                .iter()
                .map(|x| x.len(None))
                .sum::<usize>(),
        };
        let fields_len = match field_lens {
            Some(len) => len,
            None => self.fields().iter().map(|x| x.len(None)).sum::<usize>(),
        };
        Self::BASE_LENGTH + scope_fields_len + fields_len
    }

    fn write<T: Write>(
        &self,
        writer: &mut T,
        decoding_template: Option<&DecodingTemplate>,
    ) -> Result<(), DataRecordWritingError> {
        let written = match decoding_template {
            None => None,
            Some(template) => {
                for (index, record) in self.scope_fields().iter().enumerate() {
                    let field_length = template.scope_fields_specs.get(index).map(|x| x.length());
                    record.write(writer, field_length)?;
                }
                for (index, record) in self.fields().iter().enumerate() {
                    let field_length = template.fields_specs.get(index).map(|x| x.length());
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

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum ScopeFieldSpecifierWritingError {
    #[error("IO error while writing scope field specifier: {0}")]
    StdIOError(Box<str>),
}
impl_from_io_error!(ScopeFieldSpecifierWritingError);

impl WritablePdu<ScopeFieldSpecifierWritingError> for ScopeFieldSpecifier {
    /// 2-octets field id, 2-octets length
    const BASE_LENGTH: usize = 4;

    fn len(&self) -> usize {
        Self::BASE_LENGTH + if self.element_id().pen() == 0 { 0 } else { 4 }
    }

    fn write<T: Write>(&self, writer: &mut T) -> Result<(), ScopeFieldSpecifierWritingError> {
        writer.write_all(&self.element_id().id().to_be_bytes())?;
        writer.write_all(&self.length().to_be_bytes())?;
        let pen = self.element_id().pen();
        if pen != 0 {
            writer.write_all(&pen.to_be_bytes())?;
        }
        Ok(())
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum ScopeFieldWritingError {
    #[error("IO error while writing scope field: {0}")]
    StdIOError(Box<str>),

    /// The template asked for more octets than the value's own type can
    /// supply — the reverse of IPFIX reduced-size encoding, which may only
    /// ever shorten a value, never widen it.
    #[error(
        "invalid length {length} for scope field {scope_field} (value is only {width} octets wide)"
    )]
    InvalidLength {
        scope_field: &'static str,
        length: u16,
        width: usize,
    },
}
impl_from_io_error!(ScopeFieldWritingError);

impl WritablePduWithOneInput<Option<u16>, ScopeFieldWritingError> for ScopeField {
    /// 2-octets field id, 2-octets length
    const BASE_LENGTH: usize = 0;

    fn len(&self, length: Option<u16>) -> usize {
        match self {
            ScopeField::Unknown { value, .. } => value.len(),
            ScopeField::System(System(_)) => match length {
                None => 4,
                Some(len) => len as usize,
            },
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
            ScopeField::System(System(value)) => match length {
                None => writer.write_all(&(*value).to_be_bytes())?,
                Some(len) => {
                    let be_bytes = value.to_be_bytes();
                    if be_bytes.len() < len as usize {
                        return Err(ScopeFieldWritingError::InvalidLength {
                            scope_field: "system",
                            length: len,
                            width: be_bytes.len(),
                        });
                    }
                    let begin_offset = be_bytes.len() - len as usize;
                    writer.write_all(&be_bytes[begin_offset..])?;
                }
            },
            ScopeField::Interface(Interface(value)) => match length {
                None => writer.write_all(&(*value).to_be_bytes())?,
                Some(len) => {
                    let be_bytes = value.to_be_bytes();
                    if be_bytes.len() < len as usize {
                        return Err(ScopeFieldWritingError::InvalidLength {
                            scope_field: "interface",
                            length: len,
                            width: be_bytes.len(),
                        });
                    }
                    let begin_offset = be_bytes.len() - len as usize;
                    writer.write_all(&be_bytes[begin_offset..])?;
                }
            },
            ScopeField::LineCard(LineCard(value)) => match length {
                None => writer.write_all(&(*value).to_be_bytes())?,
                Some(len) => {
                    let be_bytes = value.to_be_bytes();
                    if be_bytes.len() < len as usize {
                        return Err(ScopeFieldWritingError::InvalidLength {
                            scope_field: "linecard",
                            length: len,
                            width: be_bytes.len(),
                        });
                    }
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
