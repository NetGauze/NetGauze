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

use chrono::{LocalResult, TimeZone, Utc};
use serde::{Deserialize, Serialize};

use crate::ipfix::*;
use crate::wire::deserializer::{FieldSpecifierParsingError, ie};
use crate::{DATA_SET_MIN_ID, DataSetId, FieldSpecifier};
use netgauze_parse_utils::error::ParseError;
use netgauze_parse_utils::reader::SliceReader;
use netgauze_parse_utils::traits::{ParseFrom, ParseFromWithOneInput, ParseFromWithTwoInputs};

/// 2-octets version, 2-octets length, 4-octets * 3 (export time, seq no,
/// observation domain id)
pub const IPFIX_HEADER_LENGTH: u16 = 16;

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum IpfixPacketParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error(
        "unsupported IPFIX version {version} at byte offset {offset} (expected {})",
        IPFIX_VERSION
    )]
    UnsupportedVersion { offset: usize, version: u16 },

    #[error(
        "invalid IPFIX packet length {length} at byte offset {offset} (must be at least {})",
        IPFIX_HEADER_LENGTH
    )]
    InvalidLength { offset: usize, length: u16 },

    #[error("invalid IPFIX export time {export_time} at byte offset {offset}")]
    InvalidExportTime { offset: usize, export_time: u32 },

    #[error("in set: {0}")]
    SetParsingError(#[from] SetParsingError),
}

impl<'a> ParseFromWithOneInput<'a, &mut TemplatesMap> for IpfixPacket {
    type Error = IpfixPacketParsingError;

    fn parse(
        cur: &mut SliceReader<'a>,
        templates_map: &mut TemplatesMap,
    ) -> Result<Self, Self::Error> {
        let version = cur.peek_u16_be()?;
        if version != IPFIX_VERSION {
            return Err(IpfixPacketParsingError::UnsupportedVersion {
                offset: cur.offset(),
                version,
            });
        }
        let _ = cur.read_u16_be()?;
        let length = cur.peek_u16_be()?;
        if length < IPFIX_HEADER_LENGTH {
            return Err(IpfixPacketParsingError::InvalidLength {
                offset: cur.offset(),
                length,
            });
        }
        let _ = cur.read_u16_be()?;
        // `length` covers the whole message including the version and length
        // fields just read, so the body is what is left of it.
        let mut buf = cur.take_slice(length as usize - 4)?;
        let export_time = buf.peek_u32_be()?;
        let export_time = match Utc.timestamp_opt(export_time as i64, 0) {
            LocalResult::Single(time) => time,
            _ => {
                return Err(IpfixPacketParsingError::InvalidExportTime {
                    offset: buf.offset(),
                    export_time,
                });
            }
        };
        let _export_time = buf.read_u32_be()?;
        let sequence_number = buf.read_u32_be()?;
        let observation_domain_id = buf.read_u32_be()?;
        let mut payload = Vec::new();
        while !buf.is_empty() {
            payload.push(Set::parse(&mut buf, templates_map)?);
        }
        Ok(IpfixPacket::new(
            export_time,
            sequence_number,
            observation_domain_id,
            payload.into_boxed_slice(),
        ))
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum SetParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error("invalid Set length {length} at byte offset {offset} (must be at least 4)")]
    InvalidLength { offset: usize, length: u16 },

    #[error("invalid Set id {id} at byte offset {offset}")]
    InvalidSetId { offset: usize, id: u16 },

    #[error("no template defined for Set id {id} at byte offset {offset}")]
    NoTemplateDefinedFor { offset: usize, id: u16 },

    #[error("invalid padding value {value} at byte offset {offset} (must be zero)")]
    InvalidPaddingValue { offset: usize, value: u8 },

    #[error("in template record: {0}")]
    TemplateRecordError(#[from] TemplateRecordParsingError),

    #[error("in options template record: {0}")]
    OptionsTemplateRecordError(#[from] OptionsTemplateRecordParsingError),

    #[error("in data record: {0}")]
    DataRecordError(#[from] DataRecordParsingError),
}

impl<'a> ParseFromWithOneInput<'a, &mut TemplatesMap> for Set {
    type Error = SetParsingError;

    fn parse(
        cur: &mut SliceReader<'a>,
        templates_map: &mut TemplatesMap,
    ) -> Result<Self, Self::Error> {
        let id_offset = cur.offset();
        let id = cur.peek_u16_be()?;
        if id != IPFIX_TEMPLATE_SET_ID
            && id != IPFIX_OPTIONS_TEMPLATE_SET_ID
            && id < DATA_SET_MIN_ID
        {
            return Err(SetParsingError::InvalidSetId {
                offset: id_offset,
                id,
            });
        }
        let _id = cur.read_u16_be()?;
        let length = cur.peek_u16_be()?;
        if length < 4 {
            return Err(SetParsingError::InvalidLength {
                offset: cur.offset(),
                length,
            });
        }
        let _length = cur.read_u16_be()?;
        let mut buf = cur.take_slice(length as usize - 4)?;
        let set = match id {
            IPFIX_TEMPLATE_SET_ID => {
                let mut templates = Vec::new();
                while !buf.is_empty() {
                    templates.push(TemplateRecord::parse(&mut buf, templates_map)?);
                }
                Set::Template(templates.into_boxed_slice())
            }
            IPFIX_OPTIONS_TEMPLATE_SET_ID => {
                let mut option_templates = vec![];
                // THE RFC is not super clear about
                // length allowed in the Options
                // Template set. Like Wireshark implementation, we assume anything
                // less than 4-octets (min field size) is padding
                while buf.remaining() > 3 {
                    option_templates.push(OptionsTemplateRecord::parse(&mut buf, templates_map)?);
                }
                // buf could be a non zero value for padding
                check_padding_value(&mut buf)?;
                Set::OptionsTemplate(option_templates.into_boxed_slice())
            }
            // We don't need to check for valid Set ID again, since we already checked
            id => {
                let template = if let Some(fields) = templates_map.get_mut(&id) {
                    fields
                } else {
                    return Err(SetParsingError::NoTemplateDefinedFor {
                        offset: id_offset,
                        id,
                    });
                };
                // since we could have vlen fields, we can only state a min_record_len here
                let min_record_length = template
                    .scope_fields_specs
                    .iter()
                    .map(|x| {
                        if x.length() == 65535 {
                            1
                        } else {
                            x.length() as usize
                        }
                    })
                    .sum::<usize>()
                    + template
                        .fields_specs
                        .iter()
                        .map(|x| {
                            if x.length() == 65535 {
                                1
                            } else {
                                x.length() as usize
                            }
                        })
                        .sum::<usize>();

                let mut records =
                    Vec::with_capacity(buf.remaining().checked_div(min_record_length).unwrap_or(0));

                while buf.remaining() >= min_record_length && min_record_length > 0 {
                    let read_template: &DecodingTemplate = template;
                    records.push(DataRecord::parse(&mut buf, read_template)?);
                }
                template.increment_processed_count();
                // buf could be a non zero value for padding
                while buf.peek_u8() == Ok(0) {
                    let _ = buf.read_u8()?;
                }

                // We can safely unwrap DataSetId here since we already checked the range
                Set::Data {
                    id: DataSetId::new(id).unwrap(),
                    records: records.into_boxed_slice(),
                }
            }
        };
        Ok(set)
    }
}

#[inline]
fn check_padding_value(buf: &mut SliceReader<'_>) -> Result<(), SetParsingError> {
    while !buf.is_empty() {
        let offset = buf.offset();
        let value = buf.peek_u8()?;
        if value != 0 {
            return Err(SetParsingError::InvalidPaddingValue { offset, value });
        }
        let _value = buf.read_u8()?;
    }
    Ok(())
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum OptionsTemplateRecordParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error("invalid template ID {template_id} at byte offset {offset} (must be >= 256)")]
    InvalidTemplateId { offset: usize, template_id: u16 },

    /// Scope fields count must be less than the total fields count
    #[error(
        "invalid scope fields count {scope_fields_count} at byte offset {offset} \
        (must be <= total fields count {total_fields_count})"
    )]
    InvalidScopeFieldsCount {
        offset: usize,
        scope_fields_count: u16,
        total_fields_count: u16,
    },

    #[error("in field specifier: {0}")]
    FieldError(#[from] FieldSpecifierParsingError),
}

impl<'a> ParseFromWithOneInput<'a, &mut TemplatesMap> for OptionsTemplateRecord {
    type Error = OptionsTemplateRecordParsingError;

    fn parse(
        cur: &mut SliceReader<'a>,
        templates_map: &mut TemplatesMap,
    ) -> Result<Self, Self::Error> {
        let template_id_offset = cur.offset();
        let template_id = cur.peek_u16_be()?;
        // from RFC7011: Each Template Record is given a unique Template ID in the range
        // 256 to 65535.
        if template_id < 256 {
            return Err(OptionsTemplateRecordParsingError::InvalidTemplateId {
                offset: template_id_offset,
                template_id,
            });
        }
        let _template_id = cur.read_u16_be()?;
        let total_fields_count = cur.read_u16_be()?;
        let scope_fields_count_offset = cur.offset();
        let scope_fields_count = cur.peek_u16_be()?;
        if scope_fields_count > total_fields_count {
            return Err(OptionsTemplateRecordParsingError::InvalidScopeFieldsCount {
                offset: scope_fields_count_offset,
                scope_fields_count,
                total_fields_count,
            });
        }
        let _scope_fields_count = cur.read_u16_be()?;
        let mut scope_fields = Vec::with_capacity(scope_fields_count as usize);
        for _ in 0..scope_fields_count {
            scope_fields.push(FieldSpecifier::parse(cur)?);
        }
        let fields_count = total_fields_count - scope_fields_count;
        let mut fields = Vec::with_capacity(fields_count as usize);
        for _ in 0..fields_count {
            fields.push(FieldSpecifier::parse(cur)?);
        }
        templates_map.insert(
            template_id,
            DecodingTemplate::new(
                scope_fields.clone().into_boxed_slice(),
                fields.clone().into_boxed_slice(),
            ),
        );
        Ok(OptionsTemplateRecord::new(
            template_id,
            scope_fields.into_boxed_slice(),
            fields.into_boxed_slice(),
        ))
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum DataRecordParsingError {
    #[error("in field: {0}")]
    FieldError(#[from] ie::FieldParsingError),
}

impl<'a> ParseFromWithOneInput<'a, &DecodingTemplate> for DataRecord {
    type Error = DataRecordParsingError;

    fn parse(
        cur: &mut SliceReader<'a>,
        field_specifiers: &DecodingTemplate,
    ) -> Result<Self, Self::Error> {
        let mut scope_fields =
            Vec::<crate::ie::Field>::with_capacity(field_specifiers.scope_fields_specs.len());
        for spec in &field_specifiers.scope_fields_specs {
            scope_fields.push(
                <crate::ie::Field as ParseFromWithTwoInputs<'a, _, _>>::parse(
                    cur,
                    &spec.element_id(),
                    spec.length,
                )?,
            );
        }

        let mut fields =
            Vec::<crate::ie::Field>::with_capacity(field_specifiers.fields_specs.len());
        for spec in &field_specifiers.fields_specs {
            fields.push(
                <crate::ie::Field as ParseFromWithTwoInputs<'a, _, _>>::parse(
                    cur,
                    &spec.element_id(),
                    spec.length,
                )?,
            );
        }
        Ok(DataRecord::new(
            scope_fields.into_boxed_slice(),
            fields.into_boxed_slice(),
        ))
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum TemplateRecordParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error("invalid template ID {template_id} at byte offset {offset} (must be >= 256)")]
    InvalidTemplateId { offset: usize, template_id: u16 },

    #[error("in field specifier: {0}")]
    FieldSpecifierError(#[from] FieldSpecifierParsingError),
}

impl<'a> ParseFromWithOneInput<'a, &mut TemplatesMap> for TemplateRecord {
    type Error = TemplateRecordParsingError;

    fn parse(
        cur: &mut SliceReader<'a>,
        templates_map: &mut TemplatesMap,
    ) -> Result<Self, Self::Error> {
        let template_id_offset = cur.offset();
        let template_id = cur.peek_u16_be()?;
        // from RFC7011: Each Template Record is given a unique Template ID in the range
        // 256 to 65535.
        if template_id < 256 {
            return Err(TemplateRecordParsingError::InvalidTemplateId {
                offset: template_id_offset,
                template_id,
            });
        }
        let _template_id = cur.read_u16_be()?;
        let field_count = cur.read_u16_be()?;
        let mut fields = Vec::with_capacity(field_count as usize);
        for _ in 0..field_count {
            fields.push(FieldSpecifier::parse(cur)?);
        }
        templates_map.insert(
            template_id,
            DecodingTemplate::new(Box::new([]), fields.clone().into_boxed_slice()),
        );
        Ok(TemplateRecord::new(template_id, fields.into_boxed_slice()))
    }
}
