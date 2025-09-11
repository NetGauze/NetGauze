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

use quick_xml::name::Namespace;

pub mod capabilities;
pub mod codec;
pub mod protocol;
pub mod xml_utils;

pub(crate) const NETCONF_NS_STR: &[u8] = b"urn:ietf:params:xml:ns:netconf:base:1.0";
pub(crate) const NETCONF_NS: Namespace<'static> = Namespace(NETCONF_NS_STR);

#[cfg(test)]
mod tests {
    use crate::xml_utils::{ParsingError, XmlDeserialize, XmlParser, XmlSerialize, XmlWriter};
    use quick_xml::NsReader;
    use std::{fmt, io};

    pub(crate) fn test_parse_error<T: XmlDeserialize<T> + XmlSerialize + PartialEq + fmt::Debug>(
        input_str: &'_ str,
    ) -> Result<(), ParsingError> {
        // Check first we can deserialize value correctly
        let cursor = io::Cursor::new(input_str);
        let mut reader = NsReader::from_reader(cursor);
        reader.config_mut().trim_text(false);
        let mut xml_parser = XmlParser::new(reader)?;
        let ret = T::xml_deserialize(&mut xml_parser);
        assert!(ret.is_err(), "Expected an error but parsed successfully");
        ret.map(|_| ())
    }

    /// Test function for types that own all their data (no borrowed references)
    /// This version can do round-trip testing
    pub(crate) fn test_xml_value_owned<T>(
        input_str: &'_ str,
        expected: T,
    ) -> Result<(), ParsingError>
    where
        T: XmlDeserialize<T> + XmlSerialize + PartialEq + fmt::Debug + Clone,
    {
        // Check first we can deserialize value correctly
        let mut reader = NsReader::from_str(input_str);
        reader.config_mut().trim_text(false);
        let mut xml_parser = XmlParser::new(reader)?;
        let parsed = T::xml_deserialize(&mut xml_parser);
        assert!(parsed.is_ok(), "{parsed:?}");
        let parsed = parsed?;
        assert_eq!(
            parsed, expected,
            "Expecting:\n{expected:#?}\nparsed:\n{parsed:#?}"
        );

        // Now test round-trip: serialize and deserialize again
        let writer = quick_xml::writer::Writer::new(io::Cursor::new(Vec::new()));
        let mut writer = XmlWriter::new(
            writer,
            vec![(
                "xmlns".into(),
                "urn:ietf:params:xml:ns:netconf:base:1.0".to_string(),
            )],
        );
        expected.clone().xml_serialize(&mut writer)?;

        let serialize_vec = writer.into_inner().into_inner();
        let serialize_str =
            String::from_utf8(serialize_vec).expect("Serialized value is not valid UTF-8");

        // Deserialize from the serialized string
        let mut reader = NsReader::from_reader(serialize_str.as_bytes());
        reader.config_mut().trim_text(false);
        let mut xml_parser = XmlParser::new(reader)?;
        let parsed_again = T::xml_deserialize(&mut xml_parser)?;
        assert_eq!(parsed_again, expected);

        Ok(())
    }

    pub(crate) fn test_xml_value<
        T: XmlDeserialize<T> + XmlSerialize + PartialEq + fmt::Debug + Clone,
    >(
        input_str: &'_ str,
        expected: T,
    ) -> Result<(), ParsingError> {
        // Check first we can deserialize value correctly
        let mut reader = NsReader::from_str(input_str);
        reader.config_mut().trim_text(false);
        let mut xml_parser = XmlParser::new(reader)?;
        let parsed = T::xml_deserialize(&mut xml_parser);
        assert!(parsed.is_ok(), "{parsed:?}");
        let parsed = parsed?;
        assert_eq!(
            parsed, expected,
            "Expecting:\n{expected:#?}\nparsed:\n{parsed:#?}"
        );

        // Check after we serialize the test value we can deserialize back the same
        // value
        let writer = quick_xml::writer::Writer::new(io::Cursor::new(Vec::new()));
        let mut writer = XmlWriter::new(
            writer,
            vec![(
                "xmlns".into(),
                "urn:ietf:params:xml:ns:netconf:base:1.0".to_string(),
            )],
        );
        parsed.xml_serialize(&mut writer)?;

        let serialize_str = String::from_utf8(writer.into_inner().into_inner())
            .expect("Serialized value is not valid UTF-8");

        let reader = NsReader::from_str(&serialize_str);
        let mut xml_parser = XmlParser::new(reader)?;
        let parsed = <T as XmlDeserialize<T>>::xml_deserialize(&mut xml_parser)?;
        assert_eq!(parsed, expected);
        Ok(())
    }
}
