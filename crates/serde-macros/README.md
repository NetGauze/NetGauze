# Helper macros to make ser/deser binary protocols easier

[![Crates.io][crates-badge]][crates-url]
[![Documentation][docs-badge]][docs-url]
[![Apache licensed][apache-badge]][apache-url]


[crates-badge]: https://img.shields.io/crates/v/netgauze-serde-macros.svg

[crates-url]: https://crates.io/crates/netgauze-serde-macros

[apache-badge]: https://img.shields.io/badge/license-Apache-blue.svg

[apache-url]: https://github.com/NetGauze/NetGauze/blob/main/LICENSE

[docs-badge]: https://docs.rs/netgauze-serde-macros/badge.svg

[docs-url]: https://docs.rs/netgauze-serde-macros


*StringBackedEnum*: Treat an `enum` as a string-backed value for Serde and Avro. The derive implements:

1. `serde::Serialize` — serializes the enum as a string via `to_string()`.
2. `serde::Deserialize` — parses a string with `std::str::FromStr`, mapping failures through
   `serde::de::Error::custom`.
3. `apache_avro::schema::derive::AvroSchemaComponent` — returns `Schema::String`.

The enum must already implement [`std::fmt::Display`] and [`std::str::FromStr`]; this derive does not
generate them. `strum_macros` is the usual way to supply both.

Example:

```rust
use netgauze_serde_macros::StringBackedEnum;

#[derive(
    strum_macros::Display,
    strum_macros::EnumString,
    StringBackedEnum,
    Eq,
    PartialEq,
    Clone,
    Debug,
)]
pub enum BgpOrigin {
    #[strum(to_string = "i")]
    IGP,
    #[strum(to_string = "e")]
    EGP,
    #[strum(to_string = "u")]
    Unknown,
}
```
