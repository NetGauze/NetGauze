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

//! Serializer for BGP Route Refresh message

use crate::BgpRouteRefreshMessage;
use netgauze_parse_utils::{WritablePdu, impl_from_io_error};

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum BgpRouteRefreshMessageWritingError {
    #[error("IO error while writing BGP route refresh message: {0}")]
    StdIOError(Box<str>),
}
impl_from_io_error!(BgpRouteRefreshMessageWritingError);

impl WritablePdu<BgpRouteRefreshMessageWritingError> for BgpRouteRefreshMessage {
    // 4 octet = 2 afi + 1 op + + 1 safi
    const BASE_LENGTH: usize = 4;

    fn len(&self) -> usize {
        Self::BASE_LENGTH
    }

    fn write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), BgpRouteRefreshMessageWritingError> {
        writer.write_all(&u16::from(self.address_type().address_family()).to_be_bytes())?;
        writer.write_all(&[self.operation_type().into()])?;
        writer.write_all(&[self.address_type().subsequent_address_family().into()])?;
        Ok(())
    }
}
