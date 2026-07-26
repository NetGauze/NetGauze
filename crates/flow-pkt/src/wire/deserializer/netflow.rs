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

use netgauze_parse_utils::error::ParseError;
use netgauze_parse_utils::reader::SliceReader;
use netgauze_parse_utils::traits::{ParseFrom, ParseFromWithOneInput, ParseFromWithTwoInputs};

use crate::ie::InformationElementTemplate;
use crate::netflow::*;
use crate::wire::deserializer::FieldSpecifierParsingError;
use crate::{DATA_SET_MIN_ID, DataSetId, FieldSpecifier};

/// 2-octets version, 2-octets count, 4-octets * 4 (sysUpTime, UNIX time, seq
/// no, source id)
pub const NETFLOW_V9_HEADER_LENGTH: u16 = 20;

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum NetFlowV9PacketParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error(
        "unsupported NetFlow V9 version {version} at byte offset {offset} (expected {})",
        NETFLOW_V9_VERSION
    )]
    UnsupportedVersion { offset: usize, version: u16 },

    #[error(
        "invalid records count {count} at byte offset {offset} \
        (more records were parsed than the header declared)"
    )]
    InvalidCount { offset: usize, count: u16 },

    #[error("invalid NetFlow export time {unix_time} at byte offset {offset}")]
    InvalidUnixTime { offset: usize, unix_time: u32 },

    #[error("in set: {0}")]
    SetError(#[from] SetParsingError),
}

impl<'a> ParseFromWithOneInput<'a, &mut TemplatesMap> for NetFlowV9Packet {
    type Error = NetFlowV9PacketParsingError;

    fn parse(
        cur: &mut SliceReader<'a>,
        templates_map: &mut TemplatesMap,
    ) -> Result<Self, Self::Error> {
        let version = cur.peek_u16_be()?;
        if version != NETFLOW_V9_VERSION {
            return Err(NetFlowV9PacketParsingError::UnsupportedVersion {
                offset: cur.offset(),
                version,
            });
        }
        let _version = cur.read_u16_be()?;
        let count_offset = cur.offset();
        let count = cur.read_u16_be()?;
        let sys_up_time = cur.read_u32_be()?;
        let unix_time = cur.peek_u32_be()?;
        let unix_time = match Utc.timestamp_opt(unix_time as i64, 0) {
            LocalResult::Single(time) => time,
            _ => {
                return Err(NetFlowV9PacketParsingError::InvalidUnixTime {
                    offset: cur.offset(),
                    unix_time,
                });
            }
        };
        let _unix_time = cur.read_u32_be()?;
        let sequence_number = cur.read_u32_be()?;
        let source_id = cur.read_u32_be()?;
        let mut payload = Vec::with_capacity(count as usize);
        let mut i = count as usize;
        while i > 0 && cur.remaining() > 3 {
            let set = Set::parse(cur, templates_map)?;
            match set {
                Set::Template(_) => i -= 1,
                Set::OptionsTemplate(_) => i -= 1,
                Set::Data { id: _, ref records } => {
                    if records.len() > i {
                        return Err(NetFlowV9PacketParsingError::InvalidCount {
                            offset: count_offset,
                            count,
                        });
                    }
                    i -= records.len()
                }
            }
            payload.push(set);
        }
        Ok(NetFlowV9Packet::new(
            sys_up_time,
            unix_time,
            sequence_number,
            source_id,
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
        if id != NETFLOW_TEMPLATE_SET_ID
            && id != NETFLOW_OPTIONS_TEMPLATE_SET_ID
            && id < DATA_SET_MIN_ID
        {
            return Err(SetParsingError::InvalidSetId {
                offset: id_offset,
                id,
            });
        }
        let _ = cur.read_u16_be()?;
        let length = cur.peek_u16_be()?;
        if length < 4 {
            return Err(SetParsingError::InvalidLength {
                offset: cur.offset(),
                length,
            });
        }
        let _ = cur.read_u16_be()?;
        let mut buf = cur.take_slice(length as usize - 4)?;
        let set = match id {
            NETFLOW_TEMPLATE_SET_ID => {
                let mut templates = Vec::new();
                while !buf.is_empty() {
                    templates.push(TemplateRecord::parse(&mut buf, templates_map)?);
                }
                Set::Template(templates.into_boxed_slice())
            }
            NETFLOW_OPTIONS_TEMPLATE_SET_ID => {
                let mut option_templates = vec![];
                // THE RFC is not super clear about padding length allowed in the Options
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
                let record_length = template
                    .scope_fields_specs
                    .iter()
                    .map(|x| x.length() as usize)
                    .sum::<usize>()
                    + template
                        .fields_specs
                        .iter()
                        .map(|x| x.length() as usize)
                        .sum::<usize>();

                let check_count = buf.remaining().checked_div(record_length);
                let records = if let Some(count) = check_count {
                    let mut records = Vec::with_capacity(count);
                    while buf.remaining() >= record_length {
                        let read_template: &DecodingTemplate = template;
                        records.push(DataRecord::parse(&mut buf, read_template)?);
                        template.increment_processed_count();
                    }
                    records
                } else {
                    vec![]
                };
                // buf could be a non zero value for padding
                check_padding_value(&mut buf)?;
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
        let _ = buf.read_u8()?;
    }
    Ok(())
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum OptionsTemplateRecordParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error("invalid template ID {template_id} at byte offset {offset} (must be >= 256)")]
    InvalidTemplateId { offset: usize, template_id: u16 },

    #[error("in field specifier: {0}")]
    FieldSpecifierError(#[from] FieldSpecifierParsingError),

    #[error("in scope field specifier: {0}")]
    ScopeFieldSpecifierError(#[from] ScopeFieldSpecifierParsingError),
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
        let _ = cur.read_u16_be()?;
        let options_scope_length = cur.read_u16_be()?;
        let options_length = cur.read_u16_be()?;
        let mut options_scope_buf = cur.take_slice(options_scope_length as usize)?;
        let mut options_buf = cur.take_slice(options_length as usize)?;

        let mut scope_fields = Vec::new();
        while !options_scope_buf.is_empty() {
            scope_fields.push(ScopeFieldSpecifier::parse(&mut options_scope_buf)?);
        }
        let mut fields = Vec::new();
        while !options_buf.is_empty() {
            fields.push(FieldSpecifier::parse(&mut options_buf)?);
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
        let _ = cur.read_u16_be()?;
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

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum ScopeFieldSpecifierParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error("invalid length {length} for scope field {ie:?} at byte offset {offset}")]
    InvalidLength {
        offset: usize,
        ie: ScopeIE,
        length: u16,
    },
}

impl<'a> ParseFrom<'a> for ScopeFieldSpecifier {
    type Error = ScopeFieldSpecifierParsingError;

    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        let offset = cur.offset();
        let code = cur.read_u16_be()?;
        let is_enterprise = code & 0x8000u16 != 0;
        let length = cur.read_u16_be()?;
        let pen = if is_enterprise { cur.read_u32_be()? } else { 0 };
        let ie = ScopeIE::from((pen, code));
        if !ie
            .length_range()
            .as_ref()
            .map(|x| x.contains(&length))
            .unwrap_or(true)
        {
            return Err(ScopeFieldSpecifierParsingError::InvalidLength { offset, ie, length });
        }
        Ok(ScopeFieldSpecifier::new(ie, length))
    }
}

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum DataRecordParsingError {
    #[error("in field: {0}")]
    FieldError(#[from] crate::wire::deserializer::ie::FieldParsingError),

    #[error("in scope field: {0}")]
    ScopeFieldError(#[from] ScopeFieldParsingError),
}

impl<'a> ParseFromWithOneInput<'a, &DecodingTemplate> for DataRecord {
    type Error = DataRecordParsingError;

    fn parse(
        cur: &mut SliceReader<'a>,
        decoding_template: &DecodingTemplate,
    ) -> Result<Self, Self::Error> {
        let mut scope_fields =
            Vec::<ScopeField>::with_capacity(decoding_template.scope_fields_specs.len());
        for spec in &decoding_template.scope_fields_specs {
            scope_fields.push(<ScopeField as ParseFromWithTwoInputs<'a, _, _>>::parse(
                cur,
                &spec.element_id(),
                spec.length(),
            )?);
        }

        let mut fields =
            Vec::<crate::ie::Field>::with_capacity(decoding_template.fields_specs.len());
        for spec in &decoding_template.fields_specs {
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

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum ScopeFieldParsingError {
    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error("invalid length {length} at byte offset {offset}")]
    InvalidLength { offset: usize, length: u16 },
}

impl<'a> ParseFromWithTwoInputs<'a, &ScopeIE, u16> for ScopeField {
    type Error = ScopeFieldParsingError;

    fn parse(cur: &mut SliceReader<'a>, ie: &ScopeIE, length: u16) -> Result<Self, Self::Error> {
        // The three scoped identifiers below are counters that may travel in
        // fewer than four octets, as with IPFIX reduced-size encoding.
        let mut reduced_u32 = |length: u16| -> Result<u32, ScopeFieldParsingError> {
            if length > 4 {
                return Err(ScopeFieldParsingError::InvalidLength {
                    offset: cur.offset(),
                    length,
                });
            }
            Ok(cur.read_unsigned64_be(length as usize)? as u32)
        };
        match ie {
            ScopeIE::Unknown { .. } => Ok(ScopeField::Unknown {
                pen: ie.pen(),
                id: ie.id(),
                value: cur.read_bytes(length as usize)?.into(),
            }),
            ScopeIE::System => Ok(ScopeField::System(System(reduced_u32(length)?))),
            ScopeIE::Interface => Ok(ScopeField::Interface(Interface(reduced_u32(length)?))),
            ScopeIE::LineCard => Ok(ScopeField::LineCard(LineCard(reduced_u32(length)?))),
            ScopeIE::Cache => Ok(ScopeField::Cache(Cache(
                cur.read_bytes(length as usize)?.into(),
            ))),
            ScopeIE::Template => Ok(ScopeField::Template(Template(
                cur.read_bytes(length as usize)?.into(),
            ))),
        }
    }
}
