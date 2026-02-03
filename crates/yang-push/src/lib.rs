// Copyright (C) 2025-present The NetGauze Authors.
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

pub mod cache;
pub mod model;
pub mod validation;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub type ContentId = String;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CustomSchema {
    pub content_id: ContentId,
    pub search_dir: PathBuf,
    pub yanglib: PathBuf,
    pub schema: PathBuf,
}

pub const OTL_YANG_PUSH_SUBSCRIPTION_ID_KEY: &str = "netgauze.udp.notif.yang.push.subscription.id";
pub const OTL_YANG_PUSH_SUBSCRIPTION_TARGET_KEY: &str =
    "netgauze.udp.notif.yang.push.subscription.target";
pub const OTL_YANG_PUSH_SUBSCRIPTION_ROUTER_CONTENT_ID_KEY: &str =
    "netgauze.udp.notif.yang.push.subscription.router_content_id";
pub const OTL_YANG_PUSH_CACHED_CONTENT_ID_KEY: &str =
    "netgauze.udp.notif.yang.push.subscription.cached_content_id";
const OTL_CACHE_DROP_REASON_KEY: &str = "netgauze.udp.notif.yang.push.cache.drop.reason";
const OTL_CACHE_DROP_REASON_SUBSCRIPTION_CACHE_FULL: &str = "subscription cache is full";
const OTL_CACHE_DROP_REASON_PEER_CACHE_FULL: &str = "peer cache is full";
pub const OTL_UDP_NOTIF_MESSAGE_ID_KEY: &str = "netgauze.udp.notif.message_id";
pub const OTL_UDP_NOTIF_PUBLISHER_ID_KEY: &str = "netgauze.udp.notif.publisher_id";
const OTL_YANG_PUSH_DECODE_ERROR_ID_KEY: &str = "netgauze.udp.notif.yang.push.decode.error";
