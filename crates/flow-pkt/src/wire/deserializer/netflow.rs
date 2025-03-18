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
    IResult, InputIter, InputLength, Slice,
};
use serde::{Deserialize, Serialize};

use netgauze_parse_utils::{
    parse_into_located, parse_into_located_one_input, parse_into_located_two_inputs,
    parse_till_empty_into_located, ErrorKindSerdeDeref, ReadablePdu, ReadablePduWithOneInput,
    ReadablePduWithTwoInputs, Span,
};
use netgauze_serde_macros::LocatedError;

use crate::{
    ie::InformationElementTemplate, netflow::*, wire::deserializer::FieldSpecifierParsingError,
    DataSetId, FieldSpecifier, DATA_SET_MIN_ID,
};

/// 2-octets version, 2-octets count, 4-octets * 4 (sysUpTime, UNIX time, seq
/// no, source id)
pub const NETFLOW_V9_HEADER_LENGTH: u16 = 20;

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum NetFlowV9PacketParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    UnsupportedVersion(u16),
    InvalidCount(u16),
    InvalidUnixTime(u32),
    SetError(#[from_located(module = "self")] SetParsingError),
}

impl std::fmt::Display for NetFlowV9PacketParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NomError(e) => write!(f, "{}", nom::Err::Error(e)),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported NetFlow V9 version: {version}")
            }
            Self::InvalidCount(len) => write!(f, "invalid records count: {len}"),
            Self::InvalidUnixTime(time) => write!(f, "invalid Netflow export time: {time}"),
            Self::SetError(e) => write!(f, "Set parsing error: {e}"),
        }
    }
}

impl std::error::Error for NetFlowV9PacketParsingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NomError(_err) => None,
            NetFlowV9PacketParsingError::UnsupportedVersion(_) => None,
            NetFlowV9PacketParsingError::InvalidCount(_) => None,
            NetFlowV9PacketParsingError::InvalidUnixTime(_) => None,
            NetFlowV9PacketParsingError::SetError(err) => Some(err),
        }
    }
}

impl<'a> ReadablePduWithOneInput<'a, &mut TemplatesMap, LocatedNetFlowV9PacketParsingError<'a>>
    for NetFlowV9Packet
{
    fn from_wire(
        buf: Span<'a>,
        templates_map: &mut TemplatesMap,
    ) -> IResult<Span<'a>, Self, LocatedNetFlowV9PacketParsingError<'a>> {
        let input = buf;
        let (buf, version) = be_u16(buf)?;
        if version != NETFLOW_V9_VERSION {
            return Err(nom::Err::Error(LocatedNetFlowV9PacketParsingError::new(
                input,
                NetFlowV9PacketParsingError::UnsupportedVersion(version),
            )));
        }
        let input = buf;
        let (buf, count) = be_u16(buf)?;
        let (buf, sys_up_time) = be_u32(buf)?;
        let (buf, unix_time) = be_u32(buf)?;
        let unix_time = match Utc.timestamp_opt(unix_time as i64, 0) {
            LocalResult::Single(time) => time,
            _ => {
                return Err(nom::Err::Error(LocatedNetFlowV9PacketParsingError::new(
                    input,
                    NetFlowV9PacketParsingError::InvalidUnixTime(unix_time),
                )));
            }
        };
        let (buf, sequence_number) = be_u32(buf)?;
        let (mut buf, source_id) = be_u32(buf)?;
        let mut payload = Vec::with_capacity(count as usize);
        let mut i = count as usize;
        while i > 0 && buf.len() > 3 {
            let (tmp, set) = match Set::from_wire(buf, templates_map) {
                Ok((buf, value)) => Ok((buf, value)),
                Err(err) => match err {
                    nom::Err::Incomplete(needed) => Err(nom::Err::Incomplete(needed)),
                    nom::Err::Error(error) => Err(nom::Err::Error(error.into())),
                    nom::Err::Failure(failure) => Err(nom::Err::Failure(failure.into())),
                },
            }?;
            buf = tmp;
            match set {
                Set::Template(_) => i -= 1,
                Set::OptionsTemplate(_) => i -= 1,
                Set::Data { id: _, ref records } => {
                    if records.len() > i {
                        return Err(nom::Err::Error(LocatedNetFlowV9PacketParsingError::new(
                            input,
                            NetFlowV9PacketParsingError::InvalidCount(count),
                        )));
                    }
                    i -= records.len()
                }
            }
            payload.push(set);
        }
        Ok((
            buf,
            NetFlowV9Packet::new(
                sys_up_time,
                unix_time,
                sequence_number,
                source_id,
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
            if id != NETFLOW_TEMPLATE_SET_ID
                && id != NETFLOW_OPTIONS_TEMPLATE_SET_ID
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
            NETFLOW_TEMPLATE_SET_ID => {
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
            NETFLOW_OPTIONS_TEMPLATE_SET_ID => {
                let mut option_templates = vec![];
                // THE RFC is not super clear about padding length allowed in the Options
                // Template set. Like Wireshark implementation, we assume anything
                // less than 4-octets (min field size) is padding
                while buf.len() > 3 {
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
                let template = if let Some(fields) = templates_map.get(&id) {
                    fields
                } else {
                    return Err(nom::Err::Error(LocatedSetParsingError::new(
                        input,
                        SetParsingError::NoTemplateDefinedFor(id),
                    )));
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
                let records = if record_length > 0 {
                    let count = buf.len() / record_length;
                    let mut records = Vec::with_capacity(count);
                    while buf.len() >= record_length {
                        let (t, record) = parse_into_located_one_input(buf, template)?;
                        buf = t;
                        records.push(record);
                    }
                    records
                } else {
                    vec![]
                };
                // buf could be a non zero value for padding
                check_padding_value(buf)?;
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
    FieldSpecifierError(
        #[from_located(module = "crate::wire::deserializer")] FieldSpecifierParsingError,
    ),
    ScopeFieldSpecifierError(#[from_located(module = "self")] ScopeFieldSpecifierParsingError),
}

impl std::fmt::Display for OptionsTemplateRecordParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NomError(err) => write!(f, "Nom error {}", nom::Err::Error(err)),
            Self::InvalidTemplateId(id) => write!(f, "invalid template ID {id}"),
            Self::InvalidScopeFieldsCount(count) => write!(f, "invalid scope {count}"),
            Self::FieldSpecifierError(err) => write!(f, "{err}"),
            Self::ScopeFieldSpecifierError(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for OptionsTemplateRecordParsingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NomError(_err) => None,
            Self::InvalidTemplateId(_) => None,
            Self::InvalidScopeFieldsCount(_) => None,
            Self::FieldSpecifierError(err) => Some(err),
            Self::ScopeFieldSpecifierError(err) => Some(err),
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
        let (buf, options_scope_length) = be_u16(buf)?;
        let (buf, options_length) = be_u16(buf)?;
        let (buf, options_scope_buf) = nom::bytes::complete::take(options_scope_length)(buf)?;
        let (buf, options_buf) = nom::bytes::complete::take(options_length)(buf)?;
        let (_, options_scope_fields): (_, Vec<ScopeFieldSpecifier>) =
            parse_till_empty_into_located(options_scope_buf)?;
        let (_, options_fields): (_, Vec<FieldSpecifier>) =
            parse_till_empty_into_located(options_buf)?;
        let mut scope_fields = Vec::with_capacity(options_scope_fields.len());
        for a in &options_scope_fields {
            scope_fields.push((*a).clone());
        }
        let mut fields = Vec::with_capacity(options_fields.len());
        for a in &options_fields {
            fields.push(a.clone());
        }
        templates_map.insert(
            template_id,
            DecodingTemplate {
                scope_fields_specs: scope_fields.clone().into_boxed_slice(),
                fields_specs: fields.clone().into_boxed_slice(),
            },
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
            DecodingTemplate {
                scope_fields_specs: Box::new([]),
                fields_specs: fields.clone().into_boxed_slice(),
            },
        );
        Ok((
            buf,
            TemplateRecord::new(template_id, fields.into_boxed_slice()),
        ))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum ScopeFieldSpecifierParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidLength(ScopeIE, u16),
}

impl std::fmt::Display for ScopeFieldSpecifierParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NomError(err) => write!(f, "Nom error {}", nom::Err::Error(err)),
            Self::InvalidLength(field, length) => {
                write!(f, "Invalid length {field:?}, length {length}")
            }
        }
    }
}

impl std::error::Error for ScopeFieldSpecifierParsingError {}

impl<'a> ReadablePdu<'a, LocatedScopeFieldSpecifierParsingError<'a>> for ScopeFieldSpecifier {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedScopeFieldSpecifierParsingError<'a>> {
        let input = buf;
        let (buf, code) = be_u16(buf)?;
        let is_enterprise = code & 0x8000u16 != 0;
        let (buf, length) = be_u16(buf)?;
        let (buf, pen) = if is_enterprise {
            be_u32(buf)?
        } else {
            (buf, 0)
        };
        let ie = ScopeIE::from((pen, code));
        if !ie
            .length_range()
            .as_ref()
            .map(|x| x.contains(&length))
            .unwrap_or(true)
        {
            return Err(nom::Err::Error(
                LocatedScopeFieldSpecifierParsingError::new(
                    input,
                    ScopeFieldSpecifierParsingError::InvalidLength(ie, length),
                ),
            ));
        }
        Ok((buf, ScopeFieldSpecifier::new(ie, length)))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum DataRecordParsingError {
    FieldError(#[from_located(module = "")] crate::wire::deserializer::ie::FieldParsingError),
    ScopeFieldError(#[from_located(module = "self")] ScopeFieldParsingError),
}

impl std::fmt::Display for DataRecordParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FieldError(err) => write!(f, "{err}"),
            Self::ScopeFieldError(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for DataRecordParsingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::FieldError(err) => Some(err),
            Self::ScopeFieldError(err) => Some(err),
        }
    }
}

impl<'a> ReadablePduWithOneInput<'a, &DecodingTemplate, LocatedDataRecordParsingError<'a>>
    for DataRecord
{
    fn from_wire(
        buf: Span<'a>,
        decoding_template: &DecodingTemplate,
    ) -> IResult<Span<'a>, Self, LocatedDataRecordParsingError<'a>> {
        let mut buf = buf;
        let mut scope_fields =
            Vec::<ScopeField>::with_capacity(decoding_template.scope_fields_specs.len());
        for spec in &decoding_template.scope_fields_specs {
            let (t, scope_field) =
                parse_into_located_two_inputs(buf, &spec.element_id(), spec.length())?;
            buf = t;
            scope_fields.push(scope_field);
        }

        let mut fields =
            Vec::<crate::ie::Field>::with_capacity(decoding_template.fields_specs.len());
        for spec in &decoding_template.fields_specs {
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

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum ScopeFieldParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidLength(u16),
    Utf8Error(String),
}

impl std::fmt::Display for ScopeFieldParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NomError(err) => write!(f, "Nom error {}", nom::Err::Error(err)),
            Self::InvalidLength(len) => write!(f, "Invalid length {len}"),
            Self::Utf8Error(err) => write!(f, "UTF8 error {err}"),
        }
    }
}

impl std::error::Error for ScopeFieldParsingError {}

impl<'a> nom::error::FromExternalError<Span<'a>, std::str::Utf8Error>
    for LocatedScopeFieldParsingError<'a>
{
    fn from_external_error(input: Span<'a>, _kind: ErrorKind, error: std::str::Utf8Error) -> Self {
        LocatedScopeFieldParsingError::new(
            input,
            ScopeFieldParsingError::Utf8Error(error.to_string()),
        )
    }
}

impl<'a> ReadablePduWithTwoInputs<'a, &ScopeIE, u16, LocatedScopeFieldParsingError<'a>>
    for ScopeField
{
    fn from_wire(
        buf: Span<'a>,
        ie: &ScopeIE,
        length: u16,
    ) -> IResult<Span<'a>, Self, LocatedScopeFieldParsingError<'a>> {
        match ie {
            ScopeIE::Unknown { .. } => {
                let (buf, value) = nom::multi::count(be_u8, length as usize)(buf)?;
                Ok((
                    buf,
                    ScopeField::Unknown {
                        pen: ie.pen(),
                        id: ie.id(),
                        value: value.into_boxed_slice(),
                    },
                ))
            }
            ScopeIE::System => {
                let len = length as usize;
                if length > 4 || buf.input_len() < len {
                    return Err(nom::Err::Error(LocatedScopeFieldParsingError::new(
                        buf,
                        ScopeFieldParsingError::InvalidLength(length),
                    )));
                }
                let mut res = 0u32;
                for byte in buf.iter_elements().take(len) {
                    res = (res << 8) + byte as u32;
                }
                Ok((buf.slice(len..), ScopeField::System(System(res))))
            }
            ScopeIE::Interface => {
                let len = length as usize;
                if length > 4 || buf.input_len() < len {
                    return Err(nom::Err::Error(LocatedScopeFieldParsingError::new(
                        buf,
                        ScopeFieldParsingError::InvalidLength(length),
                    )));
                }
                let mut res = 0u32;
                for byte in buf.iter_elements().take(len) {
                    res = (res << 8) + byte as u32;
                }
                Ok((buf.slice(len..), ScopeField::Interface(Interface(res))))
            }
            ScopeIE::LineCard => {
                let len = length as usize;
                if length > 4 || buf.input_len() < len {
                    return Err(nom::Err::Error(LocatedScopeFieldParsingError::new(
                        buf,
                        ScopeFieldParsingError::InvalidLength(length),
                    )));
                }
                let mut res = 0u32;
                for byte in buf.iter_elements().take(len) {
                    res = (res << 8) + byte as u32;
                }
                Ok((buf.slice(len..), ScopeField::LineCard(LineCard(res))))
            }
            ScopeIE::Cache => {
                let (buf, value) = nom::multi::count(be_u8, length as usize)(buf)?;
                Ok((buf, ScopeField::Cache(Cache(value.into_boxed_slice()))))
            }
            ScopeIE::Template => {
                let (buf, value) = nom::multi::count(be_u8, length as usize)(buf)?;
                Ok((
                    buf,
                    ScopeField::Template(Template(value.into_boxed_slice())),
                ))
            }
        }
    }
}
