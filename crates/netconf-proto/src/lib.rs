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

pub mod capabilities;
pub mod client;
pub mod codec;
pub mod protocol;
pub mod xml_parser;

/// Helper function to decode HTML special chars
pub(crate) fn decode_html_entities(s: &str) -> String {
    s.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&#34;", "\"")
        .replace("&#39;", "'")
        .replace("&#38;", "&")
        .replace("&#60;", "<")
        .replace("&#62;", ">")
}

#[cfg(test)]
mod tests {
    use crate::xml_parser::{ParsingError, XmlDeserialize, XmlParser, XmlSerialize, XmlWriter};
    use quick_xml::NsReader;
    use std::{fmt::Debug, io, str::FromStr};

    pub(crate) fn test_xml_value<T: XmlDeserialize<T> + XmlSerialize + PartialEq + Debug>(
        input_str: &str,
        expected: T,
    ) -> Result<(), ParsingError> {
        // Check first we can deserialize value correctly
        let reader = NsReader::from_str(input_str);
        let mut xml_parser = XmlParser::new(reader)?;
        let parsed = <T as XmlDeserialize<T>>::xml_deserialize(&mut xml_parser);
        assert!(parsed.is_ok(), "{parsed:?}");
        let parsed = parsed?;
        assert_eq!(
            parsed, expected,
            "Expecting:\n{expected:#?}\nparsed:\n{parsed:#?}"
        );

        // Check after we serialize the test value we can deserialize back the same
        // value
        let writer = quick_xml::writer::Writer::new(io::Cursor::new(Vec::new()));
        let mut writer = XmlWriter {
            inner: writer,
            ns_to_apply: vec![(
                "xmlns".into(),
                "urn:ietf:params:xml:ns:netconf:base:1.0".to_string(),
            )],
        };
        parsed.xml_serialize(&mut writer)?;

        let serialize_str = String::from_utf8(writer.inner.into_inner().into_inner())
            .expect("Serialized value is not valid UTF-8");
        let reader = NsReader::from_str(&serialize_str);
        let mut xml_parser = XmlParser::new(reader)?;
        let parsed = <T as XmlDeserialize<T>>::xml_deserialize(&mut xml_parser)?;
        assert_eq!(parsed, expected);
        Ok(())
    }

    pub(crate) fn test_from_str<T: FromStr + ToString + PartialEq + Debug>(
        input_str: &str,
        expected: &T,
    ) -> Result<(), ParsingError>
    where
        <T as FromStr>::Err: Debug,
    {
        // Check first we can deserialize value correctly
        let parsed = T::from_str(input_str);
        assert!(parsed.is_ok(), "{parsed:?}");
        let parsed = parsed.unwrap();
        assert_eq!(
            &parsed, expected,
            "Expecting: {expected:?}, parsed: {parsed:?}"
        );
        // Check after we serialize it we can deserialize back the same value
        let serialize_str = parsed.to_string();
        assert_eq!(serialize_str, input_str);
        Ok(())
    }
}
