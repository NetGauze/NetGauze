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

use std::{cell::RefMut, rc::Rc};

use chrono::{LocalResult, TimeZone, Utc};
use nom::{
    error::ErrorKind,
    number::complete::{be_u16, be_u32, be_u8},
    IResult,
};
use serde::{Deserialize, Serialize};

use crate::{
    ipfix::*,
    wire::deserializer::{ie, FieldSpecifierParsingError},
    DataSetId, DATA_SET_MIN_ID,
};
use netgauze_parse_utils::{
    parse_into_located, parse_into_located_one_input, parse_into_located_two_inputs,
    parse_till_empty_into_with_one_input_located, ErrorKindSerdeDeref, ReadablePduWithOneInput,
    Span,
};
use netgauze_serde_macros::LocatedError;

/// 2-octets version, 2-octets length, 4-octets * 3 (export time, seq no,
/// observation domain id)
pub const IPFIX_HEADER_LENGTH: u16 = 16;

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum IpfixPacketParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    UnsupportedVersion(u16),
    InvalidLength(u16),
    InvalidExportTime(u32),
    SetParsingError(#[from_located(module = "self")] SetParsingError),
}

impl<'a> ReadablePduWithOneInput<'a, TemplatesMap, LocatedIpfixPacketParsingError<'a>>
    for IpfixPacket
{
    fn from_wire(
        buf: Span<'a>,
        templates_map: TemplatesMap,
    ) -> IResult<Span<'a>, Self, LocatedIpfixPacketParsingError<'a>> {
        let input = buf;
        let (buf, version) = be_u16(buf)?;
        if version != IPFIX_VERSION {
            return Err(nom::Err::Error(LocatedIpfixPacketParsingError::new(
                input,
                IpfixPacketParsingError::UnsupportedVersion(version),
            )));
        }
        let input = buf;
        let (buf, length) = be_u16(buf)?;
        if length < IPFIX_HEADER_LENGTH {
            return Err(nom::Err::Error(LocatedIpfixPacketParsingError::new(
                input,
                IpfixPacketParsingError::InvalidLength(length),
            )));
        }
        let (reminder, buf) = nom::bytes::complete::take(length - 4)(buf)?;
        let (buf, export_time) = be_u32(buf)?;
        let export_time = match Utc.timestamp_opt(export_time as i64, 0) {
            LocalResult::Single(time) => time,
            _ => {
                return Err(nom::Err::Error(LocatedIpfixPacketParsingError::new(
                    input,
                    IpfixPacketParsingError::InvalidExportTime(export_time),
                )));
            }
        };
        let (buf, sequence_number) = be_u32(buf)?;
        let (buf, observation_domain_id) = be_u32(buf)?;
        let (_, payload) = parse_till_empty_into_with_one_input_located(buf, templates_map)?;
        Ok((
            reminder,
            IpfixPacket::new(export_time, sequence_number, observation_domain_id, payload),
        ))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum SetParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidLength(u16),
    InvalidSetId(u16),
    NoTemplateDefinedFor(u16),
    InvalidPaddingValue(u8),
    TemplateRecordError(#[from_located(module = "self")] TemplateRecordParsingError),
    OptionsTemplateRecordError(#[from_located(module = "self")] OptionsTemplateRecordParsingError),
    DataRecordError(#[from_located(module = "self")] DataRecordParsingError),
}

impl<'a> ReadablePduWithOneInput<'a, TemplatesMap, LocatedSetParsingError<'a>> for Set {
    fn from_wire(
        buf: Span<'a>,
        templates_map: TemplatesMap,
    ) -> IResult<Span<'a>, Self, LocatedSetParsingError<'a>> {
        let input = buf;
        let (buf, id) = nom::combinator::map_res(be_u16, |id| {
            if id != IPFIX_TEMPLATE_SET_ID
                && id != IPFIX_OPTIONS_TEMPLATE_SET_ID
                && id < DATA_SET_MIN_ID
            {
                Err(SetParsingError::InvalidSetId(id))
            } else {
                Ok(id)
            }
        })(buf)?;
        let (buf, length) = nom::combinator::map_res(be_u16, |length| {
            if length < 4 {
                Err(SetParsingError::InvalidLength(length))
            } else {
                Ok(length)
            }
        })(buf)?;
        let (reminder, mut buf) = nom::bytes::complete::take(length - 4)(buf)?;
        let set = match id {
            IPFIX_TEMPLATE_SET_ID => {
                let (_buf, templates) =
                    parse_till_empty_into_with_one_input_located(buf, templates_map)?;
                Set::Template(templates)
            }
            IPFIX_OPTIONS_TEMPLATE_SET_ID => {
                let mut option_templates = vec![];
                // THE RFC is not super clear about
                // length allowed in the Options
                // Template set. Like Wireshark implementation, we assume anything
                // less than 4-octets (min field size) is padding
                while buf.len() > 3 {
                    let (t, option_template) =
                        parse_into_located_one_input(buf, Rc::clone(&templates_map))?;
                    buf = t;
                    option_templates.push(option_template);
                }
                // buf could be a non zero value for padding
                check_padding_value(buf)?;
                Set::OptionsTemplate(option_templates)
            }
            // We don't need to check for valid Set ID again, since we already checked
            id => {
                // Temp variable to keep the borrowed value from RC
                let binding = templates_map.as_ref().borrow();
                let template = if let Some(fields) = binding.get(&id) {
                    fields
                } else {
                    return Err(nom::Err::Error(LocatedSetParsingError::new(
                        input,
                        SetParsingError::NoTemplateDefinedFor(id),
                    )));
                };

                let (scope_field_specs, field_specs) = template.as_ref();
                // since we could have vlen fields, we can only state a min_record_len here
                let min_record_length = scope_field_specs
                    .iter()
                    .map(|x| if x.length() == 65535 { 0 } else { x.length() as usize })
                    .sum::<usize>()
                    + field_specs
                        .iter()
                        .map(|x| if x.length() == 65535 { 0 } else { x.length() as usize })
                        .sum::<usize>();

                let mut remaining_buf_len = buf.len();
                let mut records = Vec::new();
                while remaining_buf_len >= min_record_length {
                    let (t, record): (Span<'_>, DataRecord) =
                        parse_into_located_one_input(buf, Rc::clone(template))?;
                    buf = t;
                    remaining_buf_len -= remaining_buf_len - buf.len();
                    records.push(record);
                }
                // buf could be a non zero value for padding
                while buf.len() > 0 && nom::combinator::peek(be_u8)(buf)?.1 == 0 {
                    let (t, _) = be_u8(buf)?;
                    buf = t;
                }

                // We can safely unwrap DataSetId here since we already checked the range
                Set::Data {
                    id: DataSetId::new(id).unwrap(),
                    records,
                }
            }
        };
        Ok((reminder, set))
    }
}

#[inline]
fn check_padding_value(mut buf: Span<'_>) -> IResult<Span<'_>, (), LocatedSetParsingError<'_>> {
    while buf.len() > 0 {
        let (t, padding_value) = be_u8(buf)?;
        if padding_value != 0 {
            return Err(nom::Err::Error(LocatedSetParsingError::new(
                buf,
                SetParsingError::InvalidPaddingValue(padding_value),
            )));
        }
        buf = t;
    }
    Ok((buf, ()))
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum OptionsTemplateRecordParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidTemplateId(u16),
    /// Scope fields count must be less than the total fields count
    InvalidScopeFieldsCount(u16),
    FieldError(#[from_located(module = "crate::wire::deserializer")] FieldSpecifierParsingError),
}

impl<'a> ReadablePduWithOneInput<'a, TemplatesMap, LocatedOptionsTemplateRecordParsingError<'a>>
    for OptionsTemplateRecord
{
    fn from_wire(
        buf: Span<'a>,
        templates_map: TemplatesMap,
    ) -> IResult<Span<'a>, Self, LocatedOptionsTemplateRecordParsingError<'a>> {
        let input = buf;
        let (buf, template_id) = be_u16(buf)?;
        // from RFC7011: Each Template Record is given a unique Template ID in the range
        // 256 to 65535.
        if template_id < 256 {
            return Err(nom::Err::Error(
                LocatedOptionsTemplateRecordParsingError::new(
                    input,
                    OptionsTemplateRecordParsingError::InvalidTemplateId(template_id),
                ),
            ));
        }
        let (buf, total_fields_count) = be_u16(buf)?;
        let input = buf;
        let (mut buf, scope_fields_count) = be_u16(buf)?;
        if scope_fields_count > total_fields_count {
            return Err(nom::Err::Error(
                LocatedOptionsTemplateRecordParsingError::new(
                    input,
                    OptionsTemplateRecordParsingError::InvalidScopeFieldsCount(scope_fields_count),
                ),
            ));
        }
        let mut scope_fields = Vec::with_capacity(scope_fields_count as usize);
        for _ in 0..scope_fields_count {
            let (t, field) = parse_into_located(buf)?;
            scope_fields.push(field);
            buf = t;
        }
        let fields_count = total_fields_count - scope_fields_count;
        let mut fields = Vec::with_capacity(fields_count as usize);
        for _ in 0..fields_count {
            let (t, field) = parse_into_located(buf)?;
            fields.push(field);
            buf = t;
        }
        {
            let mut map: RefMut<'_, _> = templates_map.borrow_mut();
            map.insert(template_id, Rc::new((scope_fields.clone(), fields.clone())));
        }
        Ok((
            buf,
            OptionsTemplateRecord::new(template_id, scope_fields, fields),
        ))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum DataRecordParsingError {
    FieldError(#[from_located(module = "")] ie::FieldParsingError),
}

impl<'a> ReadablePduWithOneInput<'a, Rc<DecodingTemplate>, LocatedDataRecordParsingError<'a>>
    for DataRecord
{
    fn from_wire(
        buf: Span<'a>,
        field_specifiers: Rc<DecodingTemplate>,
    ) -> IResult<Span<'a>, Self, LocatedDataRecordParsingError<'a>> {
        let mut buf = buf;
        let (scope_fields_specs, field_specs) = field_specifiers.as_ref();

        let mut scope_fields = Vec::<crate::ie::Field>::with_capacity(scope_fields_specs.len());
        for spec in scope_fields_specs {
            let (t, scope_field) =
                parse_into_located_two_inputs(buf, &spec.element_id(), spec.length)?;
            buf = t;
            scope_fields.push(scope_field);
        }

        let mut fields = Vec::<crate::ie::Field>::with_capacity(field_specs.len());
        for spec in field_specs {
            let (t, field) = parse_into_located_two_inputs(buf, &spec.element_id(), spec.length)?;
            buf = t;
            fields.push(field);
        }
        Ok((buf, DataRecord::new(scope_fields, fields)))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum TemplateRecordParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidTemplateId(u16),
    FieldSpecifierError(
        #[from_located(module = "crate::wire::deserializer")] FieldSpecifierParsingError,
    ),
}

impl<'a> ReadablePduWithOneInput<'a, TemplatesMap, LocatedTemplateRecordParsingError<'a>>
    for TemplateRecord
{
    fn from_wire(
        buf: Span<'a>,
        templates_map: TemplatesMap,
    ) -> IResult<Span<'a>, Self, LocatedTemplateRecordParsingError<'a>> {
        let input = buf;
        let (buf, template_id) = be_u16(buf)?;
        // from RFC7011: Each Template Record is given a unique Template ID in the range
        // 256 to 65535.
        if template_id < 256 {
            return Err(nom::Err::Error(LocatedTemplateRecordParsingError::new(
                input,
                TemplateRecordParsingError::InvalidTemplateId(template_id),
            )));
        }
        let (mut buf, field_count) = be_u16(buf)?;
        let mut fields = Vec::with_capacity(field_count as usize);
        for _ in 0..field_count {
            let (t, field) = parse_into_located(buf)?;
            fields.push(field);
            buf = t;
        }
        {
            let mut map: RefMut<'_, _> = templates_map.borrow_mut();
            map.insert(template_id, Rc::new((vec![], fields.clone())));
        }
        Ok((buf, TemplateRecord::new(template_id, fields)))
    }
}
