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

//! Serializer for BGP Path Attributes

use crate::{
    path_attribute::PathAttribute, serde::serializer::update::BGPUpdateMessageWritingError,
};
use netgauze_parse_utils::WritablePDU;

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum PathAttributeWritingError {
    StdIOError(String),
}

impl From<std::io::Error> for PathAttributeWritingError {
    fn from(err: std::io::Error) -> Self {
        PathAttributeWritingError::StdIOError(err.to_string())
    }
}

impl From<PathAttributeWritingError> for BGPUpdateMessageWritingError {
    fn from(value: PathAttributeWritingError) -> Self {
        BGPUpdateMessageWritingError::PathAttributeError(value)
    }
}

impl WritablePDU<PathAttributeWritingError> for PathAttribute {
    const BASE_LENGTH: usize = 0;

    fn len(&self) -> usize {
        todo!()
    }

    fn write<T: std::io::Write>(&self, _writer: &mut T) -> Result<(), PathAttributeWritingError> {
        todo!()
    }
}
