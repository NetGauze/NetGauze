// Copyright (C) 2022-present The NetGauze Authors.
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

use std::{
    cell::{RefCell, RefMut},
    collections::HashMap,
    rc::Rc,
};

use chrono::{LocalResult, TimeZone, Utc};
use nom::{
    error::ErrorKind,
    number::complete::{be_u16, be_u32, be_u8},
    IResult,
};
use serde::{Deserialize, Serialize};

use netgauze_parse_utils::{
    parse_into_located, parse_into_located_one_input, parse_into_located_two_inputs,
    parse_till_empty_into_with_one_input_located, parse_till_empty_into_with_two_inputs_located,
    ErrorKindSerdeDeref, ReadablePDU, ReadablePDUWithOneInput, ReadablePDUWithTwoInputs, Span,
};
use netgauze_serde_macros::LocatedError;

use crate::{
    ie::InformationElementTemplate, DataRecord, FieldSpecifier, Flow, InformationElementId,
    InformationElementIdError, IpfixHeader, IpfixPacket, OptionsTemplateRecord, Set, SetPayload,
    TemplateRecord, IPFIX_VERSION,
};

pub mod ie;

/// 2-octets version, 2-octets length, 4-octets * 3 (export time, seq no,
/// observation domain id)
const IPFIX_HEADER_LENGTH: u16 = 16;

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum IpfixPacketParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    IpfixHeaderError(#[from_located(module = "self")] IpfixHeaderParsingError),
    SetParsingError(#[from_located(module = "self")] SetParsingError),
}

impl<'a>
    ReadablePDUWithOneInput<
        'a,
        Rc<RefCell<HashMap<u16, Rc<Vec<FieldSpecifier>>>>>,
        LocatedIpfixPacketParsingError<'a>,
    > for IpfixPacket
{
    fn from_wire(
        buf: Span<'a>,
        templates_map: Rc<RefCell<HashMap<u16, Rc<Vec<FieldSpecifier>>>>>,
    ) -> IResult<Span<'a>, Self, LocatedIpfixPacketParsingError<'a>> {
        let (buf, header) = parse_into_located(buf)?;
        let (buf, payload) = parse_till_empty_into_with_one_input_located(buf, templates_map)?;
        Ok((buf, IpfixPacket::new(header, payload)))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum IpfixHeaderParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    UnsupportedVersion(u16),
    InvalidLength(u16),
    InvalidExportTime(u32),
}

impl<'a> ReadablePDU<'a, LocatedIpfixHeaderParsingError<'a>> for IpfixHeader {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedIpfixHeaderParsingError<'a>> {
        let input = buf;
        let (buf, version) = be_u16(buf)?;
        if version != IPFIX_VERSION {
            return Err(nom::Err::Error(LocatedIpfixHeaderParsingError::new(
                input,
                IpfixHeaderParsingError::UnsupportedVersion(version),
            )));
        }
        let input = buf;
        let (buf, length) = be_u16(buf)?;
        if length < IPFIX_HEADER_LENGTH {
            return Err(nom::Err::Error(LocatedIpfixHeaderParsingError::new(
                input,
                IpfixHeaderParsingError::InvalidLength(length),
            )));
        }
        let (buf, export_time) = be_u32(buf)?;
        let export_time = match Utc.timestamp_opt(export_time as i64, 0) {
            LocalResult::Single(time) => time,
            _ => {
                return Err(nom::Err::Error(LocatedIpfixHeaderParsingError::new(
                    input,
                    IpfixHeaderParsingError::InvalidExportTime(export_time),
                )));
            }
        };
        let (buf, seq_number) = be_u32(buf)?;
        let (buf, observation_domain_id) = be_u32(buf)?;
        Ok((
            buf,
            IpfixHeader::new(export_time, seq_number, observation_domain_id),
        ))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum FieldParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InformationElementIdError(InformationElementIdError),
    InvalidLength(InformationElementId, u16),
}

impl<'a> ReadablePDU<'a, LocatedFieldParsingError<'a>> for FieldSpecifier {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedFieldParsingError<'a>> {
        let input = buf;
        let (buf, code) = be_u16(buf)?;
        let is_enterprise = code & 0x8000u16 != 0;
        let (buf, length) = be_u16(buf)?;
        let (buf, pen) = if is_enterprise {
            be_u32(buf)?
        } else {
            (buf, 0)
        };
        let ie = match InformationElementId::try_from((pen, code)) {
            Ok(ie) => ie,
            Err(err) => {
                return Err(nom::Err::Error(LocatedFieldParsingError::new(
                    input,
                    FieldParsingError::InformationElementIdError(err),
                )));
            }
        };
        if !ie
            .length_range()
            .as_ref()
            .map(|x| x.contains(&length))
            .unwrap_or(true)
        {
            return Err(nom::Err::Error(LocatedFieldParsingError::new(
                input,
                FieldParsingError::InvalidLength(ie, length),
            )));
        }
        Ok((buf, FieldSpecifier::new(ie, length)))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum FlowParsingError {
    RecordError(#[from_located(module = "")] ie::RecordParsingError),
}

impl<'a> ReadablePDUWithOneInput<'a, Rc<Vec<FieldSpecifier>>, LocatedFlowParsingError<'a>>
    for Flow
{
    fn from_wire(
        buf: Span<'a>,
        fields: Rc<Vec<FieldSpecifier>>,
    ) -> IResult<Span<'a>, Self, LocatedFlowParsingError<'a>> {
        let mut buf = buf;
        let mut records = Vec::<crate::ie::Record>::with_capacity(fields.len());
        for field in fields.as_ref() {
            let (t, record) =
                parse_into_located_two_inputs(buf, &field.element_id(), field.length)?;
            buf = t;
            records.push(record);
        }
        Ok((buf, Flow::new(records)))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum TemplateRecordParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidTemplateId(u16),
    FieldError(#[from_located(module = "self")] FieldParsingError),
}

impl<'a>
    ReadablePDUWithOneInput<
        'a,
        Rc<RefCell<HashMap<u16, Rc<Vec<FieldSpecifier>>>>>,
        LocatedTemplateRecordParsingError<'a>,
    > for TemplateRecord
{
    fn from_wire(
        buf: Span<'a>,
        templates_map: Rc<RefCell<HashMap<u16, Rc<Vec<FieldSpecifier>>>>>,
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
            let mut map: RefMut<_> = templates_map.borrow_mut();
            map.insert(template_id, Rc::new(fields.clone()));
        }
        Ok((buf, TemplateRecord::new(template_id, fields)))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum OptionsTemplateRecordParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidTemplateId(u16),
    /// Scope fields count must be less than the total fields count
    InvalidScopeFieldsCount(u16),
    FieldError(#[from_located(module = "self")] FieldParsingError),
}

impl<'a>
    ReadablePDUWithOneInput<
        'a,
        Rc<RefCell<HashMap<u16, Rc<Vec<FieldSpecifier>>>>>,
        LocatedOptionsTemplateRecordParsingError<'a>,
    > for OptionsTemplateRecord
{
    fn from_wire(
        buf: Span<'a>,
        templates_map: Rc<RefCell<HashMap<u16, Rc<Vec<FieldSpecifier>>>>>,
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
        let mut fields = Vec::with_capacity(total_fields_count as usize);
        for _ in 0..total_fields_count {
            let (t, field) = parse_into_located(buf)?;
            fields.push(field);
            buf = t;
        }
        {
            let mut map: RefMut<_> = templates_map.borrow_mut();
            map.insert(template_id, Rc::new(fields.clone()));
        }
        let (scope, normal) = fields.split_at(scope_fields_count as usize);
        Ok((
            buf,
            OptionsTemplateRecord::new(template_id, scope.to_vec(), normal.to_vec()),
        ))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum DataRecordParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    FlowError(#[from_located(module = "self")] FlowParsingError),
    InvalidTemplateId(u16),
}

impl<'a>
    ReadablePDUWithTwoInputs<'a, Rc<Vec<FieldSpecifier>>, usize, LocatedDataRecordParsingError<'a>>
    for DataRecord
{
    fn from_wire(
        mut buf: Span<'a>,
        fields: Rc<Vec<FieldSpecifier>>,
        padding: usize,
    ) -> IResult<Span<'a>, Self, LocatedDataRecordParsingError<'a>> {
        let mut flows = vec![];
        while buf.len() > padding {
            let (t, flow) = parse_into_located_one_input(buf, fields.clone())?;
            flows.push(flow);
            buf = t;
        }
        // TODO: handle padding calculations
        let (buf, _) = nom::bytes::complete::take(padding)(buf)?;
        Ok((buf, DataRecord::new(flows)))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum SetParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidLength(u16),
    InvalidSetId(u16),
    NoTemplateDefinedFor(u16),
    TemplateRecordError(#[from_located(module = "self")] TemplateRecordParsingError),
    OptionsTemplateRecordError(#[from_located(module = "self")] OptionsTemplateRecordParsingError),
    DataRecordError(#[from_located(module = "self")] DataRecordParsingError),
}

impl<'a>
    ReadablePDUWithOneInput<
        'a,
        Rc<RefCell<HashMap<u16, Rc<Vec<FieldSpecifier>>>>>,
        LocatedSetParsingError<'a>,
    > for Set
{
    fn from_wire(
        buf: Span<'a>,
        templates_map: Rc<RefCell<HashMap<u16, Rc<Vec<FieldSpecifier>>>>>,
    ) -> IResult<Span<'a>, Self, LocatedSetParsingError<'a>> {
        let (buf, id) = be_u16(buf)?;
        let input = buf;
        let (buf, length) = be_u16(buf)?;
        if length < 4 {
            return Err(nom::Err::Error(LocatedSetParsingError::new(
                input,
                SetParsingError::InvalidLength(length),
            )));
        }
        let (reminder, mut buf) = nom::bytes::complete::take(length - 4)(buf)?;
        let (_buf, payload) = if id == 2 {
            let (buf, templates) =
                parse_till_empty_into_with_one_input_located(buf, templates_map)?;
            (buf, SetPayload::Template(templates))
        } else if id == 3 {
            let mut option_templates = vec![];
            // THE RFC is not super clear about padding length allowed in the Options
            // Template set. Like Wireshark implementation, we assume anything
            // less than 4-octets (min field size) is padding
            while buf.len() > 3 {
                let (t, option_template) =
                    parse_into_located_one_input(buf, templates_map.clone())?;
                buf = t;
                option_templates.push(option_template);
            }
            let (buf, _) = nom::multi::many0(be_u8)(buf)?;
            (buf, SetPayload::OptionsTemplate(option_templates))
        } else if id == 0 || id == 1 {
            todo!("Handle Netflow sets")
        } else if (4..=255).contains(&id) {
            return Err(nom::Err::Error(LocatedSetParsingError::new(
                input,
                SetParsingError::InvalidSetId(id),
            )));
        } else {
            // TODO: handle padding calculations
            let binding = templates_map.borrow();
            let fields = if let Some(fields) = binding.get(&id) {
                fields
            } else {
                return Err(nom::Err::Error(LocatedSetParsingError::new(
                    input,
                    SetParsingError::NoTemplateDefinedFor(id),
                )));
            };
            let (buf, data) =
                parse_till_empty_into_with_two_inputs_located(buf, fields.clone(), 0usize)?;
            (buf, SetPayload::Data(data))
        };
        Ok((reminder, Set::new(id, payload)))
    }
}
