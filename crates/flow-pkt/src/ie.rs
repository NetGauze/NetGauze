#[allow(non_camel_case_types)]
#[repr(u8)]
#[derive(
    strum_macros::Display,
    strum_macros::FromRepr,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Debug,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum InformationElementDataType {
    /// [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// [RFC7011](https://datatracker.ietf.org/doc/html/rfc7011)
    octetArray = 0,

    /// [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// [RFC7011](https://datatracker.ietf.org/doc/html/rfc7011)
    unsigned8 = 1,

    /// [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// [RFC7011](https://datatracker.ietf.org/doc/html/rfc7011)
    unsigned16 = 2,

    /// [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// [RFC7011](https://datatracker.ietf.org/doc/html/rfc7011)
    unsigned32 = 3,

    /// [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// [RFC7011](https://datatracker.ietf.org/doc/html/rfc7011)
    unsigned64 = 4,

    /// [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// [RFC7011](https://datatracker.ietf.org/doc/html/rfc7011)
    signed8 = 5,

    /// [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// [RFC7011](https://datatracker.ietf.org/doc/html/rfc7011)
    signed16 = 6,

    /// [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// [RFC7011](https://datatracker.ietf.org/doc/html/rfc7011)
    signed32 = 7,

    /// [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// [RFC7011](https://datatracker.ietf.org/doc/html/rfc7011)
    signed64 = 8,

    /// [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// [RFC7011](https://datatracker.ietf.org/doc/html/rfc7011)
    float32 = 9,

    /// [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// [RFC7011](https://datatracker.ietf.org/doc/html/rfc7011)
    float64 = 10,

    /// [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// [RFC7011](https://datatracker.ietf.org/doc/html/rfc7011)
    boolean = 11,

    /// [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// [RFC7011](https://datatracker.ietf.org/doc/html/rfc7011)
    macAddress = 12,

    /// [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// [RFC7011](https://datatracker.ietf.org/doc/html/rfc7011)
    string = 13,

    /// [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// [RFC7011](https://datatracker.ietf.org/doc/html/rfc7011)
    dateTimeSeconds = 14,

    /// [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// [RFC7011](https://datatracker.ietf.org/doc/html/rfc7011)
    dateTimeMilliseconds = 15,

    /// [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// [RFC7011](https://datatracker.ietf.org/doc/html/rfc7011)
    dateTimeMicroseconds = 16,

    /// [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// [RFC7011](https://datatracker.ietf.org/doc/html/rfc7011)
    dateTimeNanoseconds = 17,

    /// [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// [RFC7011](https://datatracker.ietf.org/doc/html/rfc7011)
    ipv4Address = 18,

    /// [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// [RFC7011](https://datatracker.ietf.org/doc/html/rfc7011)
    ipv6Address = 19,

    /// [RFC6313](https://datatracker.ietf.org/doc/html/rfc6313)
    /// [RFC7011](https://datatracker.ietf.org/doc/html/rfc7011)
    basicList = 20,

    /// [RFC6313](https://datatracker.ietf.org/doc/html/rfc6313)
    /// [RFC7011](https://datatracker.ietf.org/doc/html/rfc7011)
    subTemplateList = 21,

    /// [RFC6313](https://datatracker.ietf.org/doc/html/rfc6313)
    /// [RFC7011](https://datatracker.ietf.org/doc/html/rfc7011)
    subTemplateMultiList = 22,

    /// [RFC9740](https://datatracker.ietf.org/doc/html/rfc9740)
    unsigned256 = 23,
}

pub trait InformationElementTemplate {
    fn semantics(&self) -> Option<InformationElementSemantics>;
    fn data_type(&self) -> InformationElementDataType;
    fn length_range(&self) -> Option<std::ops::Range<u16>> {
        match self.data_type() {
            InformationElementDataType::octetArray => None,
            InformationElementDataType::unsigned8 => Some(std::ops::Range { start: 1, end: 2 }),
            InformationElementDataType::unsigned16 => Some(std::ops::Range { start: 1, end: 3 }),
            InformationElementDataType::unsigned32 => Some(std::ops::Range { start: 1, end: 5 }),
            InformationElementDataType::unsigned64 => Some(std::ops::Range { start: 1, end: 9 }),
            InformationElementDataType::signed8 => Some(std::ops::Range { start: 1, end: 2 }),
            InformationElementDataType::signed16 => Some(std::ops::Range { start: 1, end: 3 }),
            InformationElementDataType::signed32 => Some(std::ops::Range { start: 1, end: 5 }),
            InformationElementDataType::signed64 => Some(std::ops::Range { start: 1, end: 9 }),
            InformationElementDataType::float32 => Some(std::ops::Range { start: 4, end: 5 }),
            InformationElementDataType::float64 => Some(std::ops::Range { start: 8, end: 9 }),
            InformationElementDataType::boolean => Some(std::ops::Range { start: 1, end: 2 }),
            InformationElementDataType::macAddress => Some(std::ops::Range { start: 6, end: 7 }),
            InformationElementDataType::string => None,
            InformationElementDataType::dateTimeSeconds => {
                Some(std::ops::Range { start: 4, end: 5 })
            }
            InformationElementDataType::dateTimeMilliseconds => {
                Some(std::ops::Range { start: 8, end: 9 })
            }
            InformationElementDataType::dateTimeMicroseconds => {
                Some(std::ops::Range { start: 8, end: 9 })
            }
            InformationElementDataType::dateTimeNanoseconds => {
                Some(std::ops::Range { start: 8, end: 9 })
            }
            InformationElementDataType::ipv4Address => Some(std::ops::Range { start: 4, end: 5 }),
            InformationElementDataType::ipv6Address => Some(std::ops::Range { start: 16, end: 17 }),
            InformationElementDataType::basicList => None,
            InformationElementDataType::subTemplateList => None,
            InformationElementDataType::subTemplateMultiList => None,
            InformationElementDataType::unsigned256 => Some(std::ops::Range { start: 1, end: 33 }),
        }
    }
    fn value_range(&self) -> Option<std::ops::Range<u64>>;
    fn units(&self) -> Option<InformationElementUnits>;

    /// Returns the numerical ID for the IE.
    fn id(&self) -> u16;

    /// Returns the private enterprise number for the given IE.
    /// IANA is assigned to zero.
    fn pen(&self) -> u32;
}

include!(concat!(env!("OUT_DIR"), "/ie_generated.rs"));
