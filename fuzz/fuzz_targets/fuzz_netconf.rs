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

#![no_main]

use libfuzzer_sys::fuzz_target;
use netgauze_netconf_proto::{
    protocol::NetConfMessage,
    xml_utils::{XmlDeserialize, XmlParser, XmlSerialize, XmlWriter},
};
use quick_xml::NsReader;
use std::io;

fuzz_target!(|data: &str| {
    let reader = NsReader::from_str(data);
    let mut xml_parser = if let Ok(xml_parser) = XmlParser::new(reader) {
        xml_parser
    } else {
        return;
    };
    let ret = NetConfMessage::xml_deserialize(&mut xml_parser);
    if let Ok(ret) = ret {
        let writer = quick_xml::writer::Writer::new(io::Cursor::new(Vec::new()));
        let mut writer = XmlWriter::new(writer);
        ret.xml_serialize(&mut writer).expect("xml serialization");
    }
});
