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

use crate::{connection::ConnectionState, events::BgpEvent};
use netgauze_bgp_pkt::wire::serializer::BgpMessageWritingError;
use std::fmt::{Debug, Display, Formatter};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum FsmState {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

#[derive(Debug, PartialEq)]
pub enum FsmStateError<A> {
    BgpMessageWritingError(BgpMessageWritingError),
    InvalidConnectionStateTransition(BgpEvent<A>, FsmState, ConnectionState, ConnectionState),
}

impl<A> From<BgpMessageWritingError> for FsmStateError<A> {
    fn from(value: BgpMessageWritingError) -> Self {
        FsmStateError::BgpMessageWritingError(value)
    }
}

impl<A: Display> Display for FsmStateError<A> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            FsmStateError::BgpMessageWritingError(err) => {
                write!(f, "BgpMessageWritingError({err:?})")
            }
            FsmStateError::InvalidConnectionStateTransition(event, fsm, frm, to) => write!(
                f,
                "InvalidConnectionStateTransition({event}, {fsm}, {frm}, {to})"
            ),
        }
    }
}

impl Display for FsmState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            FsmState::Idle => write!(f, "Idle"),
            FsmState::Connect => write!(f, "Connect"),
            FsmState::Active => write!(f, "Active"),
            FsmState::OpenSent => write!(f, "OpenSent"),
            FsmState::OpenConfirm => write!(f, "OpenConfirm"),
            FsmState::Established => write!(f, "Established"),
        }
    }
}
