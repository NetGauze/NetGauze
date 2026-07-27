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

//! Traits for Ser/Deser wire protocols

pub mod common;
pub mod error;
pub mod reader;
#[cfg(feature = "test-helpers")]
pub mod test_helpers;
pub mod traits;

/// Generates `From<std::io::Error>` for one or more serializer error enums.
///
/// Serializer errors store the IO failure as a string rather than a
/// [`std::io::Error`], because they derive `Eq`/`PartialEq`/`Clone` (the
/// `test_write*` helpers require `E: Eq`) and `std::io::Error` implements none
/// of those. That lossy conversion is why `thiserror`'s `#[from]` cannot be
/// used here: it requires the variant field to *be* the source error type.
///
/// Each enum is expected to carry a `StdIOError` variant holding anything
/// convertible from [`String`] — [`Box<str>`] is preferred, since it is 8 bytes
/// smaller and these errors sit in the `Result` of every write call. Pass
/// `Type => Variant` explicitly if the variant is spelled differently.
///
/// ```
/// # use netgauze_parse_utils::impl_from_io_error;
/// #[derive(thiserror::Error, Eq, PartialEq, Clone, Debug)]
/// pub enum MyWritingError {
///     #[error("IO error while writing: {0}")]
///     StdIOError(Box<str>),
/// }
/// impl_from_io_error!(MyWritingError);
/// ```
#[macro_export]
macro_rules! impl_from_io_error {
    ($($ty:ty),+ $(,)?) => {
        $( $crate::impl_from_io_error!($ty => StdIOError); )+
    };
    ($ty:ty => $variant:ident) => {
        #[automatically_derived]
        impl From<std::io::Error> for $ty {
            fn from(err: std::io::Error) -> Self {
                // `.into()` so the variant can hold `Box<str>` or `String`
                <$ty>::$variant(err.to_string().into())
            }
        }
    };
}

/// Generic trait for Writable Protocol Data Unit that doesn't need any external
/// input while writing the packet.
#[allow(clippy::len_without_is_empty)]
pub trait WritablePdu<ErrorType> {
    const BASE_LENGTH: usize;

    /// The total length of the written buffer
    ///
    /// *Note*: the [`Self::len`] might be less than the length value written in
    /// the PDU, since most PDUs don't include the length of their 'length'
    /// field in the calculation
    fn len(&self) -> usize;

    fn write<T: std::io::Write>(&self, _writer: &mut T) -> Result<(), ErrorType>
    where
        Self: Sized;
}

/// Generic trait for Writable Protocol Data Unit that doesn't need any external
/// input while writing the packet.
#[allow(clippy::len_without_is_empty)]
pub trait WritablePduWithOneInput<I, ErrorType> {
    const BASE_LENGTH: usize;

    /// The total length of the written buffer
    ///
    /// *Note*: the [`Self::len`] might be less than the length value written in
    /// the PDU, since most PDUs don't include the length of their 'length'
    /// field in the calculation
    fn len(&self, input: I) -> usize;

    fn write<T: std::io::Write>(&self, _writer: &mut T, input: I) -> Result<(), ErrorType>
    where
        Self: Sized;
}

/// Generic trait for Writable Protocol Data Unit that doesn't need any external
/// input while writing the packet.
#[allow(clippy::len_without_is_empty)]
pub trait WritablePduWithTwoInputs<I1, I2, ErrorType> {
    const BASE_LENGTH: usize;

    /// The total length of the written buffer
    ///
    /// *Note*: the [`Self::len`] might be less than the length value written in
    /// the PDU, since most PDUs don't include the length of their 'length'
    /// field in the calculation
    fn len(&self, input1: I1, input2: I2) -> usize;

    fn write<T: std::io::Write>(
        &self,
        _writer: &mut T,
        input1: I1,
        input2: I2,
    ) -> Result<(), ErrorType>
    where
        Self: Sized;
}
