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

use crate::community::{ExperimentalExtendedCommunity, UnknownExtendedCommunity};
use byteorder::WriteBytesExt;
use netgauze_parse_utils::WritablePDU;
use netgauze_serde_macros::WritingError;

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ExperimentalExtendedCommunityWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePDU<ExperimentalExtendedCommunityWritingError> for ExperimentalExtendedCommunity {
    // 1-octet subtype + 6-octets value
    const BASE_LENGTH: usize = 7;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), ExperimentalExtendedCommunityWritingError>
    where
        Self: Sized,
    {
        writer.write_u8(self.sub_type())?;
        writer.write_all(self.value())?;
        Ok(())
    }
}

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum UnknownExtendedCommunityWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl WritablePDU<UnknownExtendedCommunityWritingError> for UnknownExtendedCommunity {
    // 1-octet subtype + 6-octets value
    const BASE_LENGTH: usize = 7;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), UnknownExtendedCommunityWritingError>
    where
        Self: Sized,
    {
        writer.write_u8(self.sub_type())?;
        writer.write_all(self.value())?;
        Ok(())
    }
}
