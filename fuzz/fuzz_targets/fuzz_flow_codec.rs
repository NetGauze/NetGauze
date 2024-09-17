// Copyright (C) 2024-present The NetGauze Authors.
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

#![no_main]
use libfuzzer_sys::fuzz_target;
use netgauze_flow_pkt::codec::FlowInfoCodec;
use tokio_util::{
    bytes::BytesMut,
    codec::{Decoder, Encoder},
};

fuzz_target!(|data: &[u8]| {
    let mut codec = FlowInfoCodec::default();
    let mut out_buf = BytesMut::with_capacity(data.len());
    let mut in_buf = BytesMut::from(data);
    while let Ok(Some(pkt)) = codec.decode(&mut in_buf) {
        codec
            .encode(pkt, &mut out_buf)
            .expect("encoding error, couldn't encode back a decoded packet");
    }
});
