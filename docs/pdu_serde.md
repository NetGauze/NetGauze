# Packet Representation and Serde

NetGauze relies heavily on the rust's rich type system to represent packets in the away that allows the rust compiler
help the user to construct correct packets at compile time.

1. PDU are immutable once constructed.

2. For constants, use `enum` to list the possible values. For example, if the PDU has a type field with limited set
   of options, then NetGauze uses an enum to represent them.

### Example PDU

```rust
use strum_macros::{Display, FromRepr};

// Make sure the type is represented the same way it would be in the PDU, here it's a one unassigned octet.
// Derive [strum_macros::FromRepr] to make it easier to create the enum from a numerical value 
#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum OuterPDUType {
    APdu = 1,
    BPdu = 2,
}

// The From<> helps to encode the enum back to it basic numerical value.
// This is helpful in serializing the packets
impl From<OuterPDUType> for u8 {
    fn from(value: OuterPDUType) -> Self {
        value as u8
    }
}

// Always create meaningful error types
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct InvalidOuterPDUType(pub u8);

// The idea here, is to always use TryFrom when deserializing the PDU type,
// hence we can always get meaningful errors 
impl TryFrom<u8> for OuterPDUType {
    type Error = InvalidOuterPDUType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(InvalidOuterPDUType(value)),
        }
    }
}

// With this enum construction we always guaranteed to produce a valid type for the PDU
pub enum OuterPDU {
    APdu(APdu),
    BPdu(APdu),
}

#[repr(u8)]
#[derive(Display, FromRepr, Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum APdu {
    Val1,
    Val2,
}

// The From<> helps to encode the enum back to it basic numerical value.
// This is helpful in serializing the packets
impl From<APdu> for u8 {
    fn from(value: APdu) -> Self {
        value as u8
    }
}

// Always create meaningful error types
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct InvalidAPduType(pub u8);

// The idea here, is to always use TryFrom when deserializing the PDU type,
// hence we can always get meaningful errors 
impl TryFrom<u8> for APdu {
    type Error = InvalidAPduType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Self::from_repr(value) {
            Some(val) => Ok(val),
            None => Err(InvalidAPduType(value)),
        }
    }
}


#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BPdu {
    value: u16
}

impl BPdu {
    pub const fn new(value: u16) -> Self { Self { value } }
    pub const fn value(&self) -> u16 { self.value }
}
```

## PDU Deserialization

### Main principles

* NetGauze parses directly from a byte slice using `SliceReader`, a cursor over `&[u8]` that tracks its own
  offset. There is no parser-combinator framework involved.
* [netgauze-parse-utils](../crates/parse-utils) provides the reader, the `ParseFrom*` traits every PDU
  implements, and — behind the `test-helpers` feature — the assertions used in unit tests.
* A PDU implements one of the `ParseFrom*` traits depending on how much context it needs:

  | Trait                                      | Signature                                                                                 |
      |--------------------------------------------|-------------------------------------------------------------------------------------------|
  | `ParseFrom<'a>`                            | `parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error>`                           |
  | `ParseFromWithOneInput<'a, I1>`            | `parse(cur, i1)`                                                                          |
  | `ParseFromWithTwoInputs<'a, I1, I2>`       | `parse(cur, i1, i2)`                                                                      |
  | `ParseFromWithThreeInputs<'a, I1, I2, I3>` | `parse(cur, i1, i2, i3)`                                                                  |
  | `ParseFromWithMut<'a, Ctx>`                | `parse(cur, ctx: &mut Ctx)` — for parsers that mutate shared state, e.g. a template cache |

* In case of a deserialization error, the first error must be reported effectively, which includes:
    * The exact location in the byte stream where the parsing error occurred
    * A custom, informative error type for the PDU or part of the PDU that failed

### Error conventions

Errors are plain `thiserror` enums — the location travels *inside* the error rather than in a wrapper type:

* Every domain variant carries an `offset: usize` field pointing at the first byte of the offending field.
  Read the offset *before* consuming, so it points at the field start rather than past it.
* Reader failures are folded in with a transparent `Parse(#[from] ParseError)` variant. `ParseError` covers
  the buffer-level failures such as `UnexpectedEof`, and already carries its own offset.
* Nested errors read as `in <context>: {0}`, so a failure deep inside a PDU prints the full path it took:

  ```text
  in set: in data record: in field: invalid UTF-8 for IE interfaceName
  at byte offset 32: invalid utf-8 sequence of 1 bytes from index 0
  ```

### Example PDU deserializer

```rust
use netgauze_parse_utils::{
    error::ParseError,
    reader::SliceReader,
    traits::ParseFrom,
};

#[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
pub enum OuterPDUParsingError {
    // Buffer-level failures (end of stream, bad padding, ...). `ParseError`
    // carries its own offset, so it is simply forwarded.
    #[error("{0}")]
    Parse(#[from] ParseError),

    // A domain error of this PDU: it carries the offset itself.
    #[error("undefined outer PDU type {code} at byte offset {offset}")]
    UndefinedOuterPDUType { offset: usize, code: u8 },

    // Errors carried up from the nested PDUs. The `in <context>:` prefix is
    // what builds the readable path in the final message.
    #[error("in a-pdu: {0}")]
    APduError(#[from] APduParsingError),

    #[error("in b-pdu: {0}")]
    BPduError(#[from] BPduParsingError),
}

impl<'a> ParseFrom<'a> for OuterPDU {
    type Error = OuterPDUParsingError;

    fn parse(cur: &mut SliceReader<'a>) -> Result<Self, Self::Error> {
        // Take the offset first so it points at the type octet, not past it.
        let offset = cur.offset();
        let code = cur.read_u8()?;
        let pdu_type = OuterPDUType::from_repr(code)
            .ok_or(OuterPDUParsingError::UndefinedOuterPDUType { offset, code })?;

        // `?` converts the nested error through the `#[from]` above.
        Ok(match pdu_type {
            OuterPDUType::A => OuterPDU::A(APdu::parse(cur)?),
            OuterPDUType::B => OuterPDU::B(BPdu::parse(cur)?),
        })
    }
}
```

### Testing

`netgauze-parse-utils` exposes matching assertions behind the `test-helpers` feature —
`test_parsed_completely_bytes_reader`, `test_parsed_completely_with_one_input_bytes_reader` and friends for
the success path, `test_parse_error_bytes_reader` and its variants for the failure path, and `test_write*`
for serialization. The `*_completely_*` helpers additionally assert that the parser consumed the whole
input.
