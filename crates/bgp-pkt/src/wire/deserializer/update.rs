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

//! Deserializer for BGP Update message

use crate::{wire::deserializer::path_attribute::PathAttributeParsingError, BgpUpdateMessage};
use netgauze_iana::address_family::AddressType;
use netgauze_parse_utils::{
    parse_till_empty_into_with_one_input_located, parse_till_empty_into_with_three_inputs_located,
    ReadablePduWithThreeInputs, Span,
};
use nom::{error::ErrorKind, number::complete::be_u16, IResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::wire::deserializer::nlri::{Ipv4UnicastAddressParsingError, Ipv4UnicastParsingError};
use netgauze_parse_utils::ErrorKindSerdeDeref;
use netgauze_serde_macros::LocatedError;

/// BGP Open Message Parsing errors
#[derive(LocatedError, Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum BgpUpdateMessageParsingError {
    /// Errors triggered by the nom parser, see [nom::error::ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    PathAttributeError(
        #[from_located(module = "crate::wire::deserializer::path_attribute")]
        PathAttributeParsingError,
    ),
    Ipv4UnicastError(
        #[from_located(module = "crate::wire::deserializer::nlri")] Ipv4UnicastParsingError,
    ),
    Ipv4UnicastAddressError(
        #[from_located(module = "crate::wire::deserializer::nlri")] Ipv4UnicastAddressParsingError,
    ),
}

impl<'a>
    ReadablePduWithThreeInputs<
        'a,
        bool,
        &HashMap<AddressType, u8>,
        &HashMap<AddressType, bool>,
        LocatedBgpUpdateMessageParsingError<'a>,
    > for BgpUpdateMessage
{
    fn from_wire(
        buf: Span<'a>,
        asn4: bool,
        multiple_labels: &HashMap<AddressType, u8>,
        add_path_map: &HashMap<AddressType, bool>,
    ) -> IResult<Span<'a>, Self, LocatedBgpUpdateMessageParsingError<'a>> {
        let (buf, withdrawn_buf) = nom::multi::length_data(be_u16)(buf)?;
        let add_path = add_path_map
            .get(&AddressType::Ipv4Unicast)
            .map_or(false, |x| *x);
        let (_, withdrawn_routes) =
            parse_till_empty_into_with_one_input_located(withdrawn_buf, add_path)?;
        let (buf, path_attributes_buf) = nom::multi::length_data(be_u16)(buf)?;
        let (_, path_attributes) = parse_till_empty_into_with_three_inputs_located(
            path_attributes_buf,
            asn4,
            multiple_labels,
            add_path_map,
        )?;
        let (buf, nlri_vec) = parse_till_empty_into_with_one_input_located(buf, add_path)?;
        Ok((
            buf,
            BgpUpdateMessage::new(withdrawn_routes, path_attributes, nlri_vec),
        ))
    }
}
