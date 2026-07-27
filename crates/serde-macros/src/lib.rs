// Copyright (C) 2022-present The NetGauze Authors.
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

use quote::quote;

/// Treat an enum as a string-backed value for Serde and Avro.
///
/// This derive implements:
/// - `serde::Serialize` — serializes the enum as a string using `to_string()`.
/// - `serde::Deserialize` — deserializes a string and parses it using
///   `std::str::FromStr`; parse failures are mapped with
///   `serde::de::Error::custom`.
/// - `apache_avro::schema::derive::AvroSchemaComponent` — returns
///   `Schema::String`.
///
/// Requirements:
/// - The enum must implement `std::fmt::Display` (or otherwise provide
///   `to_string()`).
/// - The enum must implement `std::str::FromStr`. The `Err` type of `FromStr`
///   should be convertible to a `serde` error via `serde::de::Error::custom`
///   (typically it implements `Display`).
///
/// Notes:
/// - This macro does NOT generate `Display` or `FromStr` implementations;
///   provide them yourself (for example via `strum_macros::Display` /
///   `strum_macros::EnumString`) before deriving `StringEnum`.
/// - Avro schema is always emitted as a string regardless of the enum variant
///   names.
///
/// Example (using `strum` to provide `Display` and `FromStr`):
/// ```rust,ignore
/// #[derive(
///     strum_macros::Display,
///     strum_macros::EnumString,
///     Debug,
///     PartialEq,
///     Clone,
///     netgauze_serde_macros::StringBackedEnum,
/// )]
/// pub enum BgpOrigin {
///     #[strum(to_string = "i")]
///     IGP,
///     #[strum(to_string = "e")]
///     EGP,
///     #[strum(to_string = "u")]
///     Unknown,
/// }
/// ```
#[proc_macro_derive(StringBackedEnum)]
pub fn string_backed_enum_derive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);
    let name = input.ident;

    let expanded = quote! {
        impl serde::Serialize for #name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(&self.to_string())
            }
        }

        impl<'de> serde::Deserialize<'de> for #name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?;
                std::str::FromStr::from_str(&s).map_err(serde::de::Error::custom)
            }
        }

        impl apache_avro::schema::derive::AvroSchemaComponent for #name {
            fn get_schema_in_ctxt(
                _named_schemas: &mut std::collections::HashMap<apache_avro::schema::Name, apache_avro::Schema>,
                _enclosing_namespace: &apache_avro::schema::Namespace,
            ) -> apache_avro::Schema {
                apache_avro::Schema::String
            }
        }
    };

    proc_macro::TokenStream::from(expanded)
}
