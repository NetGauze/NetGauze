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
    ErrorKindSerdeDeref, ReadablePduWithOneInput, Span,
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

impl std::fmt::Display for IpfixPacketParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NomError(e) => write!(f, "{}", nom::Err::Error(e)),
            Self::UnsupportedVersion(version) => write!(f, "unsupported IPFIX version: {version}"),
            Self::InvalidLength(len) => write!(f, "invalid IPFIX packet length: {len}"),
            Self::InvalidExportTime(time) => write!(f, "invalid IPFIX export time: {time}"),
            Self::SetParsingError(e) => write!(f, "Set parsing error: {e}"),
        }
    }
}

impl std::error::Error for IpfixPacketParsingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NomError(_err) => None,
            Self::UnsupportedVersion(_) => None,
            Self::InvalidLength(_) => None,
            Self::InvalidExportTime(_) => None,
            Self::SetParsingError(err) => Some(err),
        }
    }
}

impl<'a> ReadablePduWithOneInput<'a, &mut TemplatesMap, LocatedIpfixPacketParsingError<'a>>
    for IpfixPacket
{
    fn from_wire(
        buf: Span<'a>,
        templates_map: &mut TemplatesMap,
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
        let (remainder, buf) = nom::bytes::complete::take(length - 4)(buf)?;
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
        let (mut buf, observation_domain_id) = be_u32(buf)?;
        let mut payload = Vec::new();
        while !buf.is_empty() {
            let (tmp, element) = match Set::from_wire(buf, templates_map) {
                Ok((buf, value)) => Ok((buf, value)),
                Err(err) => match err {
                    nom::Err::Incomplete(needed) => Err(nom::Err::Incomplete(needed)),
                    nom::Err::Error(error) => Err(nom::Err::Error(error.into())),
                    nom::Err::Failure(failure) => Err(nom::Err::Failure(failure.into())),
                },
            }?;
            payload.push(element);
            buf = tmp;
        }
        Ok((
            remainder,
            IpfixPacket::new(
                export_time,
                sequence_number,
                observation_domain_id,
                payload.into_boxed_slice(),
            ),
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

impl std::fmt::Display for SetParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NomError(e) => write!(f, "{}", nom::Err::Error(e)),
            Self::InvalidLength(len) => write!(f, "invalid Set length: {len}"),
            Self::InvalidSetId(id) => write!(f, "invalid Set id: {id}"),
            Self::NoTemplateDefinedFor(id) => write!(f, "no template defined for: {id}"),
            Self::InvalidPaddingValue(padding) => write!(f, "invalid Padding value: {padding}"),
            Self::TemplateRecordError(e) => write!(f, "{e}"),
            Self::OptionsTemplateRecordError(e) => write!(f, "{e}"),
            Self::DataRecordError(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for SetParsingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NomError(_err) => None,
            Self::InvalidLength(_) => None,
            Self::InvalidSetId(_) => None,
            Self::NoTemplateDefinedFor(_) => None,
            Self::InvalidPaddingValue(_) => None,
            Self::TemplateRecordError(e) => Some(e),
            Self::OptionsTemplateRecordError(e) => Some(e),
            Self::DataRecordError(e) => Some(e),
        }
    }
}

impl<'a> ReadablePduWithOneInput<'a, &mut TemplatesMap, LocatedSetParsingError<'a>> for Set {
    fn from_wire(
        buf: Span<'a>,
        templates_map: &mut TemplatesMap,
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
        let (remainder, mut buf) = nom::bytes::complete::take(length - 4)(buf)?;
        let set = match id {
            IPFIX_TEMPLATE_SET_ID => {
                let mut templates = Vec::new();
                while !buf.is_empty() {
                    let (tmp, element) = match TemplateRecord::from_wire(buf, templates_map) {
                        Ok((buf, value)) => Ok((buf, value)),
                        Err(err) => match err {
                            nom::Err::Incomplete(needed) => Err(nom::Err::Incomplete(needed)),
                            nom::Err::Error(error) => Err(nom::Err::Error(error.into())),
                            nom::Err::Failure(failure) => Err(nom::Err::Failure(failure.into())),
                        },
                    }?;
                    templates.push(element);
                    buf = tmp;
                }
                Set::Template(templates.into_boxed_slice())
            }
            IPFIX_OPTIONS_TEMPLATE_SET_ID => {
                let mut option_templates = vec![];
                // THE RFC is not super clear about
                // length allowed in the Options
                // Template set. Like Wireshark implementation, we assume anything
                // less than 4-octets (min field size) is padding
                while buf.len() > 3 {
                    // let (t, option_template) =
                    //     parse_into_located_one_input(buf, templates_map)?;
                    let (t, option_template) =
                        match OptionsTemplateRecord::from_wire(buf, templates_map) {
                            Ok((buf, value)) => Ok((buf, value)),
                            Err(err) => match err {
                                nom::Err::Incomplete(needed) => Err(nom::Err::Incomplete(needed)),
                                nom::Err::Error(error) => Err(nom::Err::Error(error.into())),
                                nom::Err::Failure(failure) => {
                                    Err(nom::Err::Failure(failure.into()))
                                }
                            },
                        }?;
                    buf = t;
                    option_templates.push(option_template);
                }
                // buf could be a non zero value for padding
                check_padding_value(buf)?;
                Set::OptionsTemplate(option_templates.into_boxed_slice())
            }
            // We don't need to check for valid Set ID again, since we already checked
            id => {
                let template = if let Some(fields) = templates_map.get_mut(&id) {
                    fields
                } else {
                    return Err(nom::Err::Error(LocatedSetParsingError::new(
                        input,
                        SetParsingError::NoTemplateDefinedFor(id),
                    )));
                };
                // since we could have vlen fields, we can only state a min_record_len here
                let min_record_length = template
                    .scope_fields_specs
                    .iter()
                    .map(|x| {
                        if x.length() == 65535 {
                            0
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
                                0
                            } else {
                                x.length() as usize
                            }
                        })
                        .sum::<usize>();

                let mut records = Vec::new();

                while buf.len() >= min_record_length && min_record_length > 0 {
                    let read_template: &DecodingTemplate = template;
                    let (t, record): (Span<'_>, DataRecord) =
                        parse_into_located_one_input(buf, read_template)?;
                    buf = t;
                    records.push(record);
                }
                template.increment_processed_count();
                // buf could be a non zero value for padding
                while buf.len() > 0 && nom::combinator::peek(be_u8)(buf)?.1 == 0 {
                    let (t, _) = be_u8(buf)?;
                    buf = t;
                }

                // We can safely unwrap DataSetId here since we already checked the range
                Set::Data {
                    id: DataSetId::new(id).unwrap(),
                    records: records.into_boxed_slice(),
                }
            }
        };
        Ok((remainder, set))
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

impl std::fmt::Display for OptionsTemplateRecordParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NomError(err) => write!(f, "Nom error {}", nom::Err::Error(err)),
            Self::InvalidTemplateId(id) => write!(f, "invalid template ID {id}"),
            Self::InvalidScopeFieldsCount(count) => write!(f, "invalid scope {count}"),
            Self::FieldError(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for OptionsTemplateRecordParsingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NomError(_err) => None,
            Self::InvalidTemplateId(_) => None,
            Self::InvalidScopeFieldsCount(_) => None,
            Self::FieldError(err) => Some(err),
        }
    }
}

impl<'a>
    ReadablePduWithOneInput<'a, &mut TemplatesMap, LocatedOptionsTemplateRecordParsingError<'a>>
    for OptionsTemplateRecord
{
    fn from_wire(
        buf: Span<'a>,
        templates_map: &mut TemplatesMap,
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
        templates_map.insert(
            template_id,
            DecodingTemplate::new(
                scope_fields.clone().into_boxed_slice(),
                fields.clone().into_boxed_slice(),
            ),
        );
        Ok((
            buf,
            OptionsTemplateRecord::new(
                template_id,
                scope_fields.into_boxed_slice(),
                fields.into_boxed_slice(),
            ),
        ))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum DataRecordParsingError {
    FieldError(#[from_located(module = "")] ie::FieldParsingError),
}

impl std::fmt::Display for DataRecordParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FieldError(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for DataRecordParsingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::FieldError(err) => Some(err),
        }
    }
}

impl<'a> ReadablePduWithOneInput<'a, &DecodingTemplate, LocatedDataRecordParsingError<'a>>
    for DataRecord
{
    fn from_wire(
        buf: Span<'a>,
        field_specifiers: &DecodingTemplate,
    ) -> IResult<Span<'a>, Self, LocatedDataRecordParsingError<'a>> {
        let mut buf = buf;
        let mut scope_fields =
            Vec::<crate::ie::Field>::with_capacity(field_specifiers.scope_fields_specs.len());
        for spec in &field_specifiers.scope_fields_specs {
            let (t, scope_field) =
                parse_into_located_two_inputs(buf, &spec.element_id(), spec.length)?;
            buf = t;
            scope_fields.push(scope_field);
        }

        let mut fields =
            Vec::<crate::ie::Field>::with_capacity(field_specifiers.fields_specs.len());
        for spec in &field_specifiers.fields_specs {
            let (t, field) = parse_into_located_two_inputs(buf, &spec.element_id(), spec.length)?;
            buf = t;
            fields.push(field);
        }

        Ok((
            buf,
            DataRecord::new(scope_fields.into_boxed_slice(), fields.into_boxed_slice()),
        ))
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

impl std::fmt::Display for TemplateRecordParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NomError(err) => write!(f, "Nom error {}", nom::Err::Error(err)),
            Self::InvalidTemplateId(err) => write!(f, "Invalid template id {err}"),
            Self::FieldSpecifierError(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for TemplateRecordParsingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NomError(_err) => None,
            Self::InvalidTemplateId(_) => None,
            Self::FieldSpecifierError(err) => Some(err),
        }
    }
}

impl<'a> ReadablePduWithOneInput<'a, &mut TemplatesMap, LocatedTemplateRecordParsingError<'a>>
    for TemplateRecord
{
    fn from_wire(
        buf: Span<'a>,
        templates_map: &mut TemplatesMap,
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
        templates_map.insert(
            template_id,
            DecodingTemplate::new(Box::new([]), fields.clone().into_boxed_slice()),
        );
        Ok((
            buf,
            TemplateRecord::new(template_id, fields.into_boxed_slice()),
        ))
    }
}
