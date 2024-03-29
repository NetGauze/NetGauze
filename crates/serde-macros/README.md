# Helper macros to make ser/deser binary protocols easier

*LocatedError*: For a given error enum {Name} generate a struct called Located{Name} that
carries the `Span` (the error location in the input stream) info along the
error. Additionally, generates [`From`] for `nom` library errors, external,
and another located errors.

```rust
use netgauze_serde_macros::LocatedError;

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum ExtendedCommunityParsingError {
    NomError(#[from_nom] nom::error::ErrorKind),
    CommunityError(#[from_located(module = "self")] CommunityParsingError),
    UndefinedCapabilityCode(#[from_external] UndefinedBgpCapabilityCode),
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum CommunityParsingError {
    NomError(#[from_nom] nom::error::ErrorKind),
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct UndefinedBgpCapabilityCode(pub u8);

fn test() {
    let span = Span::new(&[1, 2, 3]);
    // LocatedExtendedCommunityParsingError is generated by LocatedError
    let _located = LocatedExtendedCommunityParsingError::new(
        span,
        ExtendedCommunityParsingError::UndefinedCapabilityCode(UndefinedBgpCapabilityCode(1)));
}
```

*WritingError*: Decorate an `enum` as an error for serializing binary protocol
provides the following decorations for any members of the enum.

1. `#[from_std_io_error]` automatically generate [`From`] implementation
   from [`std::io::Error`] to a [`String`].
2. `#[from]`, automatically generates a [`From`] implementation for a given
   type.

Example:

```rust
use netgauze_serde_macros::WritingError;

#[derive(WritingError, Eq, PartialEq, Clone, Debug)]
pub enum BgpMessageWritingError {
    /// std::io::Error will be converted to this value
    StdIOError(#[from_std_io_error] String),

    /// BgpOpenMessageWritingError will be converted to this value
    OpenError(#[from] BgpOpenMessageWritingError),
}
```