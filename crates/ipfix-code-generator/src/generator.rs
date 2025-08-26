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

//! Generate Rust code for the given Netflow/IPFIX definitions

use crate::{
    generator_sub_registries::*, InformationElement, InformationElementSubRegistry, SimpleRegistry,
    Xref,
};
use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;

pub fn generate_derive(
    num_enum: bool,
    from_repr: bool,
    copy: bool,
    eq: bool,
    hash: bool,
    ord: bool,
) -> String {
    let mut base = "".to_string();
    if num_enum {
        base.push_str("strum_macros::Display, ");
    }
    if from_repr {
        base.push_str("strum_macros::FromRepr, ");
    }
    if copy {
        base.push_str("Copy, ");
    }
    if eq {
        base.push_str("Eq, ");
    }
    if hash {
        base.push_str("Hash, ");
    }
    if ord {
        base.push_str("PartialOrd, Ord, ");
    }
    base.push_str("Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize");
    format!("#[derive({base})]\n")
}

/// Convert [Xref] to markdown link
pub fn generate_xref_link(xref: &Xref) -> Option<String> {
    match xref.ty.as_str() {
        "rfc" => Some(format!(
            "[{}](https://datatracker.ietf.org/doc/html/{})",
            xref.data.to_uppercase(),
            xref.data,
        )),
        "rfc-errata" => Some(format!(
            "[RFC Errata {}](https://www.rfc-editor.org/errata_search.php?eid={})",
            xref.data, xref.data,
        )),
        "draft" => Some(format!(
            "[RFC Draft {}](https://datatracker.ietf.org/doc/html/{})",
            xref.data.to_uppercase(),
            xref.data,
        )),
        "person" => None,
        "html" => Some(format!("[{}]({})", xref.data, xref.data)),
        _ => None,
    }
}

/// Generate `InformationElementDataType`
/// Currently we manually write this provide option for user defined types
#[allow(dead_code)]
pub(crate) fn generate_ie_data_type(data_types: &[SimpleRegistry]) -> String {
    let mut ret = String::new();
    ret.push_str("#[allow(non_camel_case_types)]\n");
    ret.push_str("#[repr(u8)]\n");
    ret.push_str(generate_derive(true, true, true, true, true, false).as_str());
    ret.push_str("#[cfg_attr(feature = \"fuzz\", derive(arbitrary::Arbitrary))]\n");
    ret.push_str("pub enum InformationElementDataType {\n");
    for x in data_types {
        for xref in x.xref.iter().filter_map(generate_xref_link) {
            ret.push_str(format!("  /// {xref}\n").as_str());
        }
        ret.push_str(format!("  {} = {},\n", x.description, x.value).as_str());
    }
    ret.push_str("}\n");
    ret
}

/// Generate code for `InformationElementUnits`
pub(crate) fn generate_ie_units(entries: &[SimpleRegistry]) -> TokenStream {
    // Generate each variant
    let variants = entries.iter().map(|entry| {
        // Handle the special case for "4-octet words"
        let description = if entry.description == "4-octet words" {
            "fourOctetWords"
        } else {
            &entry.description
        };

        let variant_name = Ident::new(description, Span::call_site());
        let value = entry.value;

        // Collect comments if present
        let mut doc_comments = Vec::new();

        if let Some(comments) = &entry.comments {
            doc_comments.push(quote! { #[doc = #comments] });
            doc_comments.push(quote! { #[doc = ""] });
        }

        // Add xref links as doc comments
        for xref_link in entry.xref.iter().filter_map(generate_xref_link) {
            doc_comments.push(quote! { #[doc = #xref_link] });
        }

        quote! {
            #(#doc_comments)*
            #variant_name = #value
        }
    });

    // Build the complete enum
    quote! {
        #[allow(non_camel_case_types)]
        #[repr(u8)]
        #[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Eq, Hash, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
        #[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
        pub enum InformationElementUnits {
            #(#variants,)*
        }
    }
}

/// Generate rust code for `InformationElementSemantics`
pub(crate) fn generate_ie_semantics(data_types: &[SimpleRegistry]) -> TokenStream {
    // Generate each variant
    let variants = data_types.iter().map(|dt| {
        let variant_name = Ident::new(&dt.description, Span::call_site());
        let value = dt.value;
        // Collect all doc comments from xrefs
        let doc_comments = dt.xref.iter().filter_map(generate_xref_link).map(|xref| {
            quote! { #[doc = #xref] }
        });
        quote! {
            #(#doc_comments)*
            #variant_name = #value
        }
    });

    quote! {
        #[allow(non_camel_case_types)]
        #[repr(u8)]
        #[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Eq, Hash, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
        #[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
        pub enum InformationElementSemantics {
            #(#variants,)*
        }
    }
}

fn generate_impl_ie_template_for_ie(ie: &[InformationElement]) -> TokenStream {
    let semantics = ie.iter().map(|ie| {
        let name = Ident::new(&ie.name, Span::call_site());
        ie.data_type_semantics
            .as_ref()
            .map_or(quote! { Self::#name => None }, |x| {
                let ident = Ident::new(x, Span::call_site());
                quote! { Self::#name => Some(super::InformationElementSemantics::#ident)
                }
            })
    });

    let data_types = ie.iter().map(|ie| {
        let name = Ident::new(&ie.name, Span::call_site());
        let data_type = Ident::new(&ie.data_type, Span::call_site());
        quote! {
            Self::#name => super::InformationElementDataType::#data_type
        }
    });

    let units = ie.iter().map(|ie| {
        let name = Ident::new(&ie.name, Span::call_site());
        ie.units
            .as_ref()
            .map_or(quote! { Self::#name => None }, |x| {
                let ident = Ident::new(x, Span::call_site());
                quote! { Self::#name => Some(super::InformationElementUnits::#ident) }
            })
    });

    let value_ranges = ie.iter().map(|ie| {
        let name = Ident::new(&ie.name, Span::call_site());
        ie.range
            .as_ref()
            .map_or(quote! { Self::#name => None }, |x| {
                let mut parts = vec![];
                for part in x.split('-') {
                    parts.push(part);
                }
                let start = parts.first().expect("Couldn't parse units range");
                let end = parts.get(1).unwrap().trim();
                let end = if end.starts_with("0x") {
                    u64::from_str_radix(end.trim_start_matches("0x"), 16).unwrap()
                } else {
                    end.parse::<u64>().expect("Couldn't parse units range")
                };
                let end = end + 1;
                quote! { Self::#name => Some(std::ops::Range{start: #start, end: #end }) }
            })
    });

    let pen = ie.first().unwrap().pen;
    quote! {
        impl super::InformationElementTemplate for IE {
            fn id(&self) -> u16 {
                (*self) as u16
            }

            fn pen(&self) -> u32 {
                #pen
            }

            fn semantics(&self) -> Option<super::InformationElementSemantics> {
                match self {
                    #(#semantics,)*
                }
            }

            fn data_type(&self) -> super::InformationElementDataType {
                match self {
                    #(#data_types,)*
                }
            }

            fn units(&self) -> Option<super::InformationElementUnits> {
                match self {
                    #(#units,)*
                }
            }

            fn value_range(&self) -> Option<std::ops::Range<u64>> {
                match self {
                    #(#value_ranges,)*
                }
            }
        }
    }
}

fn generate_from_for_ie(vendor_name: &str) -> TokenStream {
    let ident = Ident::new(vendor_name, Span::call_site());
    quote! {
        #[derive(Copy, Eq, Hash, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
        #[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
        pub struct UndefinedIE(pub u16);

        impl From<IE> for u16 {
            fn from(value: IE) -> Self {
                value as u16
            }
        }

        impl TryFrom<u16> for IE {
            type Error = UndefinedIE;

            fn try_from(value: u16) -> Result<Self, Self::Error> {
               // Remove Enterprise bit
               let value = value & 0x7FFF;
               match Self::from_repr(value) {
                   Some(val) => Ok(val),
                   None => Err(UndefinedIE(value)),
               }
            }
        }

        impl From<IE> for crate::IE {
            fn from(value: IE) -> crate::IE {
                crate::IE::#ident(value)
            }
        }
    }
}

/// Generate an enum of InformationElementIDs.
/// different names spaces; i.e. IANA vs enterprise space.
pub(crate) fn generate_information_element_ids(
    vendor_name: &str,
    ie: &[InformationElement],
) -> TokenStream {
    let ie_variants = ie.iter().map(|ie| {
        let ie_name = Ident::new(ie.name.as_str(), Span::call_site());
        let ie_value = ie.element_id;
        let mut doc_comments = Vec::new();
        for line in ie.description.lines() {
            let line = format!(" {}", line.trim());
            doc_comments.push(quote! { #[doc = #line] });
        }
        if !doc_comments.is_empty() && !ie.xrefs.is_empty() {
            let empty = "";
            doc_comments.push(quote! { #[doc = #empty] });
        }
        for xref_link in ie.xrefs.iter().filter_map(generate_xref_link) {
            let ref_link = format!(" Reference: {xref_link}");
            doc_comments.push(quote! { #[doc = #ref_link] });
        }

        quote! {
            #(#doc_comments)*
            #ie_name = #ie_value
        }
    });

    let if_has_subregistry_variants = ie.iter().map(|ie| {
        let ie_name = Ident::new(ie.name.as_str(), Span::call_site());
        let has_subreg = ie.subregistry.is_some();
        quote! { Self::#ie_name => #has_subreg }
    });
    let mut tokens = quote! {
        #[allow(non_camel_case_types)]
        #[repr(u16)]
        #[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Eq, Hash, Clone, PartialEq, Debug, Ord, PartialOrd, serde::Serialize, serde::Deserialize)]
        #[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
        pub enum IE {
            #(#ie_variants,)*
        }

        impl IE {
             pub const fn has_registry(&self) -> bool {
                match self {
                    #(#if_has_subregistry_variants,)*
                }
            }
        }
    };

    tokens.extend(generate_impl_ie_template_for_ie(ie));
    tokens.extend(generate_from_for_ie(vendor_name));
    tokens
}

/// Information Elements can be either current or deprecated, no IANA registry
/// for it at the moment, it's hard coded here.
pub(crate) fn generate_ie_status() -> TokenStream {
    quote! {
        #[allow(non_camel_case_types)]
        #[repr(u8)]
        #[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Eq, Hash, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
        #[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
        pub enum InformationElementStatus {
            current = 0,
            deprecated = 1,
        }
    }
}

/// Use at the beginning of `ie_generated` for defining custom types
pub(crate) fn generate_common_types() -> TokenStream {
    quote! {
        /// MacAddress type
        pub type MacAddress = [u8; 6];

        /// A trait to indicate that we can get the [IE] for a given element
        pub trait HasIE {
            fn ie(&self) -> IE;
        }
    }
}

/// `TryFrom` block for  InformationElementId
fn generate_ie_try_from_pen_code(
    iana_ies: &[InformationElement],
    name_prefixes: &[(String, String, u32)],
) -> TokenStream {
    let vendor_variants = name_prefixes.iter().map(|(name, pkg, pen)| {
        let name = Ident::new(name.as_str(), Span::call_site());
        let pkg = Ident::new(pkg.as_str(), Span::call_site());
        quote! {
            #pen => {
                match #pkg::IE::try_from(code) {
                    Ok(ie) => Ok(Self::#name(ie)),
                    Err(err) => Err(IEError::#name(err)),
                }
            }
        }
    });
    let iana_variants = iana_ies.iter().map(|ie| {
        let element_id = ie.element_id;
        let name = Ident::new(ie.name.as_str(), Span::call_site());
        quote! { #element_id =>  Ok(IE::#name) }
    });
    quote! {
        impl TryFrom<(u32, u16)> for IE {
            type Error = IEError;

            fn try_from(value: (u32, u16)) -> Result<Self, Self::Error> {
                let (pen, code) = value;
                match pen {
                    0 => {
                        match code {
                            #(#iana_variants,)*
                            _ =>  Err(IEError::UndefinedIANAIE(code)),
                        }
                    }
                    #(#vendor_variants,)*
                    unknown => Ok(IE::Unknown{pen: unknown, id: code}),
                }
            }
        }
    }
}

fn generate_ie_template_trait_for_main(
    iana_ies: &[InformationElement],
    vendors: &[(String, String, u32)],
) -> TokenStream {
    let vendor_semantic_variants = vendors.iter().map(|(name, _, _)| {
        let name = Ident::new(name.as_str(), Span::call_site());
        quote! { Self::#name(ie) => ie.semantics() }
    });

    let iana_semantic_variants = iana_ies.iter().map(|ie| {
        let name = Ident::new(ie.name.as_str(), Span::call_site());
        match &ie.data_type_semantics {
            None => quote! { Self::#name => None },
            Some(x) => {
                let x = Ident::new(x, Span::call_site());
                quote! { Self::#name => Some(InformationElementSemantics::#x) }
            }
        }
    });

    let vendor_datatypes_variants = vendors.iter().map(|(name, _, _)| {
        let name = Ident::new(name.as_str(), Span::call_site());
        quote! { Self::#name(ie) => ie.data_type() }
    });

    let iana_datatypes_variants = iana_ies.iter().map(|ie| {
        let name = Ident::new(ie.name.as_str(), Span::call_site());
        let ty = Ident::new(&ie.data_type, Span::call_site());
        quote! { Self::#name => InformationElementDataType::#ty }
    });

    let vendor_units_variants = vendors.iter().map(|(name, _, _)| {
        let name = Ident::new(name.as_str(), Span::call_site());
        quote! { Self::#name(ie) => ie.units() }
    });

    let iana_units_variants = iana_ies.iter().map(|ie| {
        let name = Ident::new(ie.name.as_str(), Span::call_site());
        match &ie.units {
            None => quote! { Self::#name => None },
            Some(units) => {
                let ty = Ident::new(units, Span::call_site());
                quote! { Self::#name => Some(InformationElementUnits::#ty) }
            }
        }
    });

    let vendor_pen_variants = vendors.iter().map(|(name, _, _)| {
        let name = Ident::new(name, Span::call_site());
        quote! { Self::#name(vendor_ie) => vendor_ie.pen() }
    });

    let vendor_id_variants = vendors.iter().map(|(name, _, _)| {
        let name = Ident::new(name, Span::call_site());
        quote! { Self::#name(vendor_ie) => vendor_ie.id() }
    });

    let iana_id_variants = iana_ies.iter().map(|ie| {
        let name = Ident::new(ie.name.as_str(), Span::call_site());
        let element = ie.element_id;
        quote! { Self::#name => #element }
    });

    let vendor_value_range_variants = vendors.iter().map(|(name, _, _)| {
        let name = Ident::new(name, Span::call_site());
        quote! { Self::#name(vendor_ie) => vendor_ie.value_range() }
    });

    let iana_value_range_variants = iana_ies.iter().map(|ie| {
        let name = Ident::new(ie.name.as_str(), Span::call_site());
        match &ie.range {
            None => quote! { Self::#name => None },
            Some(x) => {
                let mut parts = vec![];
                for part in x.split('-') {
                    parts.push(part);
                }
                let start = parts
                    .first()
                    .expect("Couldn't parse units range")
                    .trim()
                    .parse::<u64>()
                    .expect("invalid range");
                let end = parts.get(1).unwrap().trim();
                let end = 1 + if end.starts_with("0x") {
                    u64::from_str_radix(end.trim_start_matches("0x"), 16).unwrap()
                } else {
                    end.parse::<u64>().unwrap()
                };
                quote! { Self::#name => Some(std::ops::Range{start: #start, end: #end}) }
            }
        }
    });

    quote! {
        impl super::InformationElementTemplate for IE {
            fn semantics(&self) -> Option<InformationElementSemantics> {
                match self {
                    Self::Unknown{..} => None,
                    #(#vendor_semantic_variants,)*
                    #(#iana_semantic_variants,)*
                }
             }

            fn data_type(&self) -> InformationElementDataType {
                match self {
                    Self::Unknown{..} => InformationElementDataType::octetArray,
                    #(#vendor_datatypes_variants,)*
                    #(#iana_datatypes_variants,)*
                }
            }

            fn units(&self) -> Option<InformationElementUnits> {
                match self {
                    Self::Unknown{..} => None,
                    #(#vendor_units_variants,)*
                    #(#iana_units_variants,)*
                }
            }

            fn value_range(&self) -> Option<std::ops::Range<u64>> {
                match self {
                    Self::Unknown{..} => None,
                    #(#vendor_value_range_variants,)*
                    #(#iana_value_range_variants,)*
                }
            }

            fn id(&self) -> u16{
                match self {
                    Self::Unknown{id, ..} => *id,
                    #(#vendor_id_variants,)*
                    #(#iana_id_variants,)*
                }
            }

            fn pen(&self) -> u32{
                match self {
                    Self::Unknown{pen, ..} => *pen,
                    #(#vendor_pen_variants,)*
                    // Rest is IANA with PEN 0
                    _ => 0,
                }
            }
        }
    }
}

fn is_numeric(ie: &InformationElement) -> bool {
    if ie.data_type == "unsigned256" {
        return false;
    }
    if ie.data_type_semantics == Some("identifier".to_string()) {
        return false;
    }
    if ie.data_type_semantics == Some("flags".to_string()) {
        return false;
    }
    if ie.subregistry.is_some() {
        return false;
    }
    ie.data_type.starts_with("signed")
        || ie.data_type.starts_with("unsigned")
        || ie.data_type.starts_with("float")
}

fn is_comparable(ie: &InformationElement) -> bool {
    if [
        "string",
        "octetArray",
        "basicList",
        "subTemplateList",
        "subTemplateMultiList",
        "unsigned256",
    ]
    .contains(&ie.data_type.as_str())
    {
        return false;
    }
    true
}

fn is_bitwise(ie: &InformationElement) -> bool {
    if [
        "string",
        "float32",
        "float64",
        "basicList",
        "subTemplateList",
        "subTemplateMultiList",
    ]
    .contains(&ie.data_type.as_str())
        | ie.data_type.starts_with("dateTime")
    {
        return false;
    }
    true
}

fn generate_ie_field_enum_for_ie(
    iana_ies: &[InformationElement],
    vendors: &[(String, String, u32)],
) -> TokenStream {
    let vendor_variants = vendors.iter().map(|(name, pkg, _)| {
        let name = Ident::new(name, Span::call_site());
        let pkg = Ident::new(pkg, Span::call_site());
        quote! { #name(#pkg::Field) }
    });

    let iana_variants = iana_ies.iter().map(|ie| {
        let name = Ident::new(&ie.name, Span::call_site());
        if ie.name == "tcpControlBits" {
            quote! { #name(netgauze_iana::tcp::TCPHeaderFlags) }
        } else {
            let rust_type = get_rust_type(&ie.data_type, &ie.name);
            let field_type = if ie.subregistry.is_some() {
                ie.name.clone()
            } else {
                rust_type
            };
            let field_type_ty =  syn::parse_str::<syn::Type>(&field_type).unwrap();
            let mut doc_comments = Vec::new();
            for line in ie.description.lines() {
                let line = format!(" {}", line.trim());
                doc_comments.push(quote! { #[doc = #line] });
            }
            if !doc_comments.is_empty() && !ie.xrefs.is_empty(){
                let empty = "";
                doc_comments.push(quote! { #[doc = #empty] });
            }
            for xref_link in ie.xrefs.iter().filter_map(generate_xref_link) {
                let ref_link = format!(" Reference: {xref_link}");
                doc_comments.push(quote! { #[doc = #ref_link] });
            }
            if field_type.contains("Date") {
                quote! {
                    #(#doc_comments)*
                    #name(#[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_datetime))] #field_type_ty)
                }
            } else {
                quote! {
                    #(#doc_comments)*
                    #name(#field_type_ty)
                }
            }
        }
    });

    let vendor_ie_variants = vendors.iter().map(|(name, _pkg, _)| {
        let name = Ident::new(name, Span::call_site());
        quote! { Self::#name(x) => IE::#name(x.ie()) }
    });

    let iana_ie_variants = iana_ies.iter().map(|ie| {
        let name = Ident::new(&ie.name, Span::call_site());
        quote! { Self::#name(_) => IE::#name }
    });

    let into_for_field = generate_into_for_field(iana_ies, vendors);

    let vendor_add_variants = vendors.iter().map(|(name, _, _)| {
        let name = Ident::new(name, Span::call_site());
        quote! { (Self::#name(lhs), Self::#name(rhs)) => Ok(Self::#name(lhs.add_field(rhs)?)) }
    });

    let vendor_add_assign_variants = vendors.iter().map(|(name, _, _)| {
        let name = Ident::new(name, Span::call_site());
        quote! {
            (Self::#name(lhs), Self::#name(rhs)) => {
                lhs.add_assign_field(rhs)?;
                Ok(())
            }
        }
    });

    let vendor_bitwise_or_variants = vendors.iter().map(|(name, _, _)| {
        let name = Ident::new(name, Span::call_site());
        quote! { (Self::#name(lhs), Self::#name(rhs)) => Ok(Self::#name(lhs.bitwise_or_field(rhs)?)) }
    });

    let vendor_bitwise_or_assign_variants = vendors.iter().map(|(name, _, _)| {
        let name = Ident::new(name, Span::call_site());
        quote! {
            (Self::#name(lhs), Self::#name(rhs)) => {
                lhs.bitwise_or_assign_field(rhs)?;
                Ok(())
            }
        }
    });

    let vendor_min_variants = vendors.iter().map(|(name, _, _)| {
        let name = Ident::new(name, Span::call_site());
        quote! { (Self::#name(lhs), Self::#name(rhs)) => Ok(Self::#name(lhs.min_field(rhs)?)) }
    });

    let vendor_min_assign_variants = vendors.iter().map(|(name, _, _)| {
        let name = Ident::new(name, Span::call_site());
        quote! {
            (Self::#name(lhs), Self::#name(rhs)) => {
                lhs.min_assign_field(rhs)?;
                Ok(())
            }
        }
    });

    let vendor_max_variants = vendors.iter().map(|(name, _, _)| {
        let name = Ident::new(name, Span::call_site());
        quote! { (Self::#name(lhs), Self::#name(rhs)) => Ok(Self::#name(lhs.max_field(rhs)?)) }
    });

    let vendor_max_assign_variants = vendors.iter().map(|(name, _, _)| {
        let name = Ident::new(name, Span::call_site());
        quote! {
            (Self::#name(lhs), Self::#name(rhs)) => {
                lhs.max_assign_field(rhs)?;
                Ok(())
            }
        }
    });

    let OperationVariants {
        ie_add_variants,
        ie_add_assign_variants,
        ie_min_variants,
        ie_min_assign_variants,
        ie_max_variants,
        ie_max_assign_variants,
        ie_bitwise_or_variants,
        ie_bitwise_or_assign_variants,
    } = field_operations_variants(iana_ies);

    quote! {
            #[allow(non_camel_case_types)]
            #[derive(strum_macros::Display, Eq, Hash, PartialOrd, Ord, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
            #[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
            pub enum Field {
                Unknown{pen: u32, id: u16, value: Vec<u8>},
                #(#vendor_variants,)*
                #(#iana_variants,)*
            }
            impl HasIE for Field {
                /// Get the [IE] element for a given field
                fn ie(&self) -> IE {
                    match self {
                        Self::Unknown{pen, id, value: _value} => IE::Unknown{pen: *pen, id: *id},
                        #(#vendor_ie_variants,)*
                        #(#iana_ie_variants,)*
                    }
                }
            }

            #[derive(Debug, Clone)]
            pub enum FieldConversionError {
                UnknownField,
                InvalidType(String, String),
            }
            impl std::error::Error for FieldConversionError {}

            impl std::fmt::Display for FieldConversionError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::UnknownField => write!(f, "Unknown Field"),
                Self::InvalidType(t, fld) => write!(f, "Invalid Type ({t}) selected for conversion of field: {fld}"),
            }
        }
    }

            #into_for_field

            #[derive(Debug, Clone, Eq, PartialEq, strum_macros::Display)]
            pub enum FieldOperationError {
                InapplicableAdd(IE, IE),
                InapplicableMin(IE, IE),
                InapplicableMax(IE, IE),
                InapplicableBitwise(IE, IE),
            }
            impl std::error::Error for FieldOperationError {}

            impl Field {
                /// Arithmetic addition operation of two fields and produce a field with the new value
                pub fn add_field(&self, rhs: &Field) -> Result<Field, FieldOperationError> {
                    match (self, rhs) {
                        #(#vendor_add_variants,)*
                        #(#ie_add_variants,)*
                        (f1, f2) => Err(FieldOperationError::InapplicableAdd(f1.ie(), f2.ie())),
                    }
                }

                /// The addition assignment operation += of two fields
                pub fn add_assign_field(&mut self, rhs: &Field) -> Result<(), FieldOperationError> {
                    match (self, rhs) {
                        #(#vendor_add_assign_variants)*
                        #(#ie_add_assign_variants)*
                        (f1, f2) => Err(FieldOperationError::InapplicableAdd(f1.ie(), f2.ie())),
                    }
                }

                /// Bitwise OR operation of two fields and produce a field with the new value
                 pub fn bitwise_or_field(&self, other: &Field) -> Result<Field, FieldOperationError> {
                    match (self, other) {
                        #(#vendor_bitwise_or_variants,)*
                        #(#ie_bitwise_or_variants,)*
                        (f1, f2) => Err(FieldOperationError::InapplicableBitwise(f1.ie(), f2.ie())),
                    }
                }

                /// The bitwise OR assignment operation |= of two fields
                pub fn bitwise_or_assign_field(&mut self, other: &Field) -> Result<(), FieldOperationError> {
                    match (self, other) {
                        #(#vendor_bitwise_or_assign_variants)*
                        #(#ie_bitwise_or_assign_variants)*
                        (f1, f2) => Err(FieldOperationError::InapplicableBitwise(f1.ie(), f2.ie())),
                    }
                }

                /// Returns a new field with the minimum of the two fields
                pub fn min_field(&self, rhs: &Field) -> Result<Field, FieldOperationError> {
                    match (self, rhs) {
                        #(#vendor_min_variants,)*
                        #(#ie_min_variants,)*
                        (f1, f2) => Err(FieldOperationError::InapplicableMin(f1.ie(), f2.ie())),
                    }
                }

                /// Assign the field's value to be minimum of the two fields
                pub fn min_assign_field(&mut self, rhs: &Field) -> Result<(), FieldOperationError> {
                    match (self, rhs) {
                        #(#vendor_min_assign_variants)*
                        #(#ie_min_assign_variants)*
                        (f1, f2) => Err(FieldOperationError::InapplicableMin(f1.ie(), f2.ie())),
                    }
                }

                /// Returns a new field with the maximum of the two fields
                pub fn max_field(&self, rhs: &Field) -> Result<Field, FieldOperationError> {
                    match (self, rhs) {
                        #(#vendor_max_variants,)*
                        #(#ie_max_variants,)*
                        (f1, f2) => Err(FieldOperationError::InapplicableMax(f1.ie(), f2.ie())),
                    }
                }

                /// Assign the field's value to be maximum of the two fields
                pub fn max_assign_field(&mut self, rhs: &Field) -> Result<(), FieldOperationError> {
                    match (self, rhs) {
                        #(#vendor_max_assign_variants)*
                        #(#ie_max_assign_variants)*
                        (f1, f2) => Err(FieldOperationError::InapplicableMax(f1.ie(), f2.ie())),
                    }
                }
            }
        }
}

struct OperationVariants {
    ie_add_variants: Vec<TokenStream>,
    ie_add_assign_variants: Vec<TokenStream>,
    ie_min_variants: Vec<TokenStream>,
    ie_min_assign_variants: Vec<TokenStream>,
    ie_max_variants: Vec<TokenStream>,
    ie_max_assign_variants: Vec<TokenStream>,
    ie_bitwise_or_variants: Vec<TokenStream>,
    ie_bitwise_or_assign_variants: Vec<TokenStream>,
}
fn field_operations_variants(iana_ies: &[InformationElement]) -> OperationVariants {
    let ie_add_variants = iana_ies
        .iter()
        .flat_map(|ie| {
            let name = Ident::new(&ie.name, Span::call_site());
            if is_numeric(ie) {
                Some(
                    quote! { (Self::#name(lhs), Self::#name(rhs)) => Ok(Self::#name(*lhs + *rhs)) },
                )
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let ie_add_assign_variants = iana_ies
        .iter()
        .flat_map(|ie| {
            let name = Ident::new(&ie.name, Span::call_site());
            if is_numeric(ie) {
                Some(quote! {
                    (Self::#name(lhs), Self::#name(rhs)) => {
                        *lhs += *rhs; Ok(())
                    }
                })
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let ie_min_variants = iana_ies.iter().flat_map(|ie| {
        let name = Ident::new(&ie.name, Span::call_site());
        if is_comparable(ie) {
            Some(quote! { (Self::#name(lhs), Self::#name(rhs)) => Ok(Self::#name(*lhs.min(rhs))) })
        } else {
            None
        }
    }).collect::<Vec<_>>();

    let ie_min_assign_variants = iana_ies
        .iter()
        .flat_map(|ie| {
            let name = Ident::new(&ie.name, Span::call_site());
            if is_comparable(ie) {
                Some(quote! {
                    (Self::#name(v1), Self::#name(v2)) => {
                        *v1 = (*v1).min(*v2);
                        Ok(())
                    }
                })
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let ie_max_variants = iana_ies
        .iter()
        .flat_map(|ie| {
            let name = Ident::new(&ie.name, Span::call_site());
            if is_comparable(ie) {
                Some(quote! { (Self::#name(v1), Self::#name(v2)) => Ok(Self::#name(*v1.max(v2))) })
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let ie_max_assign_variants = iana_ies
        .iter()
        .flat_map(|ie| {
            let name = Ident::new(&ie.name, Span::call_site());
            if is_comparable(ie) {
                Some(quote! {
                    (Self::#name(v1), Self::#name(v2)) => {
                        *v1 = (*v1).max(*v2);
                        Ok(())
                    }
                })
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let ie_bitwise_or_variants = iana_ies.iter().flat_map(|ie| {
        let name = Ident::new(&ie.name, Span::call_site());
        if is_bitwise(ie) {
            let rust_type = get_rust_type(&ie.data_type, &ie.name);
            match ie.data_type.as_str() {
                "octetArray" if rust_type == "[u8; 3]" => {
                    Some(quote! {
                        (Self::#name(lhs), Self::#name(rhs)) => {
                            let mut result = [0u8; 3];
                             lhs.iter().zip(rhs.iter()).enumerate().for_each(|(i, (&val1, &val2))| {
                                result[i] = val1 | val2;
                            });
                            Ok(Self::#name(result))
                        }
                    })
                }
                "octetArray" => {
                    Some(quote! {
                        (Self::#name(lhs), Self::#name(rhs)) => {
                            let v = lhs.iter().zip(rhs.iter()).map(|(a, b)| *a | *b).collect::<Vec<_>>().into_boxed_slice();
                            Ok(Self::#name(v))
                        }
                    })
                }
                "unsigned256" => {
                    Some(quote! {
                        (Self::#name(lhs), Self::#name(rhs)) => {
                            let mut result = [0u8; 32];
                             lhs.iter().zip(rhs.iter()).enumerate().for_each(|(i, (&val1, &val2))| {
                                result[i] = val1 | val2;
                            });
                            Ok(Self::#name(Box::new(result)))
                        }
                    })
                }
                "macAddress" => {
                    Some(quote! {
                        (Self::#name(lhs), Self::#name(rhs)) => {
                            let mut result = [0u8; 6];
                             lhs.iter().zip(rhs.iter()).enumerate().for_each(|(i, (&val1, &val2))| {
                                result[i] = val1 | val2;
                            });
                            Ok(Self::#name(result))
                        }
                    })
                }
                _ => Some(quote! { (Self::#name(lhs), Self::#name(rhs)) => Ok(Self::#name(*lhs | *rhs)) })
            }
        } else {
            None
        }
    }).collect::<Vec<_>>();

    let ie_bitwise_or_assign_variants = iana_ies
        .iter()
        .flat_map(|ie| {
            let name = Ident::new(&ie.name, Span::call_site());
            if is_bitwise(ie) {
                let rust_type = get_rust_type(&ie.data_type, &ie.name);
                match ie.data_type.as_str() {
                    "octetArray" if rust_type == "[u8; 3]" => Some(quote! {
                        (Self::#name(lhs), Self::#name(rhs)) => {
                            lhs.iter_mut().zip(rhs.iter()).for_each(|(val1, val2)| {
                                *val1 |= val2;
                            });
                            Ok(())
                        }
                    }),
                    "octetArray" => Some(quote! {
                        (Self::#name(lhs), Self::#name(rhs)) => {
                             lhs.iter_mut().zip(rhs.iter()).for_each(|(val1, val2)| {
                                *val1 |= val2;
                            });
                            Ok(())
                        }
                    }),
                    "unsigned256" => Some(quote! {
                        (Self::#name(lhs), Self::#name(rhs)) => {
                             lhs.iter_mut().zip(rhs.iter()).for_each(|(val1, val2)| {
                                *val1 |= val2;
                            });
                            Ok(())
                        }
                    }),
                    "macAddress" => Some(quote! {
                        (Self::#name(lhs), Self::#name(rhs)) => {
                             lhs.iter_mut().zip(rhs.iter()).for_each(|(val1, val2)| {
                                *val1 |= val2;
                            });
                            Ok(())
                        }
                    }),
                    _ => Some(quote! {
                        (Self::#name(lhs), Self::#name(rhs)) => {
                            *lhs |= *rhs;
                            Ok(())
                        }
                    }),
                }
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    OperationVariants {
        ie_add_variants,
        ie_add_assign_variants,
        ie_min_variants,
        ie_min_assign_variants,
        ie_max_variants,
        ie_max_assign_variants,
        ie_bitwise_or_variants,
        ie_bitwise_or_assign_variants,
    }
}

pub(crate) fn generate_ie_ids(
    iana_ies: &[InformationElement],
    vendors: &[(String, String, u32)],
) -> TokenStream {
    let vendor_ie_variants = vendors.iter().map(|(name, pkg, _)| {
        let name = Ident::new(name, Span::call_site());
        let pkg = Ident::new(pkg, Span::call_site());
        let strum_attr = format!("{name} {{0}}");
        quote! {
            #[strum(to_string = #strum_attr)]
            #name(#pkg::IE)
        }
    });

    let iana_ie_variants = iana_ies.iter().map(|ie| {
        let ie_name = Ident::new(ie.name.as_str(), Span::call_site());
        let mut doc_comments = Vec::new();
        for line in ie.description.lines() {
            let line = format!(" {}", line.trim());
            doc_comments.push(quote! { #[doc = #line] });
        }
        if !doc_comments.is_empty() && !ie.xrefs.is_empty() {
            let empty = "";
            doc_comments.push(quote! { #[doc = #empty] });
        }
        for xref_link in ie.xrefs.iter().filter_map(generate_xref_link) {
            let ref_link = format!(" Reference: {xref_link}");
            doc_comments.push(quote! { #[doc = #ref_link] });
        }
        quote! {
            #(#doc_comments)*
            #ie_name
        }
    });

    let vendor_errors = vendors.iter().map(|(name, pkg, _)| {
        let name = Ident::new(name.as_str(), Span::call_site());
        let pkg = Ident::new(pkg, Span::call_site());
        quote! { #name(#pkg::UndefinedIE) }
    });

    let vendor_errors_display = vendors.iter().map(|(name, pkg, _)| {
        let name = Ident::new(name.as_str(), Span::call_site());
        let msg = format!("invalid {pkg} IE {{}}");
        quote! {  Self::#name(e) => write!(f, #msg, e.0) }
    });

    let vendor_has_subregistry_variants = vendors.iter().map(|(name, _, _)| {
        let name = Ident::new(name, Span::call_site());
        quote! { Self::#name(v) => v.has_registry() }
    });

    let iana_has_subregistry_variants = iana_ies.iter().map(|ie| {
        let ie_name = Ident::new(ie.name.as_str(), Span::call_site());
        let has_subreg = ie.subregistry.is_some();
        quote! { Self::#ie_name => #has_subreg }
    });

    let mut code = quote! {
        #[allow(non_camel_case_types)]
        #[derive(strum_macros::Display, Copy, Eq, Hash, PartialOrd, Ord, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
        #[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
        pub enum IE {
            Unknown{pen: u32, id: u16},
            #(#vendor_ie_variants,)*
            #(#iana_ie_variants,)*
        }

        impl IE {
            pub const fn has_registry(&self) -> bool {
                match self {
                    Self::Unknown{..} => false,
                    #(#vendor_has_subregistry_variants,)*
                    #(#iana_has_subregistry_variants,)*
                }
            }

            /// True if the Field of this IE element supports arithmetic operations: +, -, *, /.
            pub fn supports_arithmetic_ops(&self) -> bool {
                match self.semantics() {
                    Some(InformationElementSemantics::identifier) | Some(InformationElementSemantics::flags) => return false,
                    _ => {}
                }
                if self.has_registry() {
                    return false;
                }
                match self.data_type() {
                    InformationElementDataType::octetArray => false,
                    InformationElementDataType::signed8 => true,
                    InformationElementDataType::signed16 => true,
                    InformationElementDataType::signed32 => true,
                    InformationElementDataType::signed64 => true,
                    InformationElementDataType::unsigned8 => true,
                    InformationElementDataType::unsigned16 => true,
                    InformationElementDataType::unsigned32 => true,
                    InformationElementDataType::unsigned64 => true,
                    InformationElementDataType::float32 => true,
                    InformationElementDataType::float64 => true,
                    InformationElementDataType::boolean => false,
                    InformationElementDataType::macAddress => false,
                    InformationElementDataType::string => false,
                    InformationElementDataType::dateTimeSeconds => false,
                    InformationElementDataType::dateTimeMilliseconds => false,
                    InformationElementDataType::dateTimeMicroseconds => false,
                    InformationElementDataType::dateTimeNanoseconds => false,
                    InformationElementDataType::ipv4Address => false,
                    InformationElementDataType::ipv6Address => false,
                    InformationElementDataType::basicList => false,
                    InformationElementDataType::subTemplateList => false,
                    InformationElementDataType::subTemplateMultiList => false,
                    InformationElementDataType::unsigned256 => {
                        // Currently unsigned256 are used only as identifiers
                        // hence, the arithmetics ops are not implemented
                        false
                    },
                }
            }

            /// True if the Field of this IE element supports comparison operations: min, max.
            pub fn supports_comparison_ops(&self) -> bool {
                match self.data_type() {
                    InformationElementDataType::octetArray => false,
                    InformationElementDataType::signed8 => true,
                    InformationElementDataType::signed16 => true,
                    InformationElementDataType::signed32 => true,
                    InformationElementDataType::signed64 => true,
                    InformationElementDataType::unsigned8 => true,
                    InformationElementDataType::unsigned16 => true,
                    InformationElementDataType::unsigned32 => true,
                    InformationElementDataType::unsigned64 => true,
                    InformationElementDataType::float32 => true,
                    InformationElementDataType::float64 => true,
                    InformationElementDataType::boolean => false,
                    InformationElementDataType::macAddress => false,
                    InformationElementDataType::string => false,
                    InformationElementDataType::dateTimeSeconds => true,
                    InformationElementDataType::dateTimeMilliseconds => true,
                    InformationElementDataType::dateTimeMicroseconds => true,
                    InformationElementDataType::dateTimeNanoseconds => true,
                    InformationElementDataType::ipv4Address => true,
                    InformationElementDataType::ipv6Address => true,
                    InformationElementDataType::basicList => true,
                    InformationElementDataType::subTemplateList => true,
                    InformationElementDataType::subTemplateMultiList => true,
                    InformationElementDataType::unsigned256 => false,
                }
            }

            /// True if the Field of this IE element supports bitwise operations: OR, AND, XOR.
            pub fn supports_bitwise_ops(&self) -> bool {
                match self.data_type() {
                    InformationElementDataType::octetArray => true,
                    InformationElementDataType::signed8 => true,
                    InformationElementDataType::signed16 => true,
                    InformationElementDataType::signed32 => true,
                    InformationElementDataType::signed64 => true,
                    InformationElementDataType::unsigned8 => true,
                    InformationElementDataType::unsigned16 => true,
                    InformationElementDataType::unsigned32 => true,
                    InformationElementDataType::unsigned64 => true,
                    InformationElementDataType::float32 => false,
                    InformationElementDataType::float64 => false,
                    InformationElementDataType::boolean => true,
                    InformationElementDataType::macAddress => true,
                    InformationElementDataType::string => false,
                    InformationElementDataType::dateTimeSeconds => false,
                    InformationElementDataType::dateTimeMilliseconds => false,
                    InformationElementDataType::dateTimeMicroseconds => false,
                    InformationElementDataType::dateTimeNanoseconds => false,
                    InformationElementDataType::ipv4Address => true,
                    InformationElementDataType::ipv6Address => true,
                    InformationElementDataType::basicList => false,
                    InformationElementDataType::subTemplateList => false,
                    InformationElementDataType::subTemplateMultiList => false,
                    InformationElementDataType::unsigned256 => true,
                }
            }
        }

        #[derive(Copy, Eq, Hash, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
        #[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
        pub enum IEError {
            UndefinedIANAIE(u16),
            #(#vendor_errors,)*
        }

        impl std::fmt::Display for IEError {
             fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    Self::UndefinedIANAIE(id) => write!(f, "invalid IE id {id}"),
                    #(#vendor_errors_display,)*
                }
             }
        }

        impl std::error::Error for IEError {}
    };
    code.extend(generate_ie_try_from_pen_code(iana_ies, vendors));
    code.extend(generate_ie_template_trait_for_main(iana_ies, vendors));
    code.extend(generate_ie_field_enum_for_ie(iana_ies, vendors));
    code
}

/// Held out temporary, we might not need this
#[allow(dead_code)]
fn generate_ie_value_converters(rust_type: &str, ie_name: &String) -> String {
    let mut ret = String::new();
    match rust_type {
        "u8" => {
            ret.push_str(format!("impl From<[u8; 1]> for {ie_name} {{\n").as_str());
            ret.push_str("    fn from(value: [u8; 1]) -> Self {\n");
            ret.push_str("        Self(value[0])\n");
            ret.push_str("    }\n");
            ret.push_str("}\n\n");

            ret.push_str(format!("impl From<u8> for {ie_name} {{\n").as_str());
            ret.push_str("    fn from(value: u8) -> Self {\n");
            ret.push_str("        Self(value)\n");
            ret.push_str("    }\n");
            ret.push_str("}\n");
            ret.push('\n');
        }
        "u16" => {
            ret.push_str(format!("impl From<[u8; 1]> for {ie_name} {{\n").as_str());
            ret.push_str("    fn from(value: [u8; 1]) -> Self {\n");
            ret.push_str("        Self(value[0] as u16)\n");
            ret.push_str("    }\n");
            ret.push_str("}\n\n");

            ret.push_str(format!("impl From<[u8; 2]> for {ie_name} {{\n").as_str());
            ret.push_str("    fn from(value: [u8; 2]) -> Self {\n");
            ret.push_str("        Self(u16::from_be_bytes(value))\n");
            ret.push_str("    }\n");
            ret.push_str("}\n\n");

            ret.push_str(format!("impl From<u16> for {ie_name} {{\n").as_str());
            ret.push_str("    fn from(value: u16) -> Self {\n");
            ret.push_str("        Self(value)\n");
            ret.push_str("    }\n");
            ret.push_str("}\n");
            ret.push('\n');
        }
        "u32" => {
            ret.push_str(format!("impl From<[u8; 1]> for {ie_name} {{\n").as_str());
            ret.push_str("    fn from(value: [u8; 1]) -> Self {\n");
            ret.push_str("        Self(value[0] as u32)\n");
            ret.push_str("    }\n");
            ret.push_str("}\n\n");

            ret.push_str(format!("impl From<[u8; 2]> for {ie_name} {{\n").as_str());
            ret.push_str("    fn from(value: [u8; 2]) -> Self {\n");
            ret.push_str("        let tmp = u16::from_be_bytes(value);\n");
            ret.push_str("        Self(tmp as u32)\n");
            ret.push_str("    }\n");
            ret.push_str("}\n\n");

            ret.push_str(format!("impl From<[u8; 4]> for {ie_name} {{\n").as_str());
            ret.push_str("    fn from(value: [u8; 4]) -> Self {\n");
            ret.push_str("        Self(u32::from_be_bytes(value))\n");
            ret.push_str("    }\n");
            ret.push_str("}\n\n");

            ret.push_str(format!("impl From<u32> for {ie_name} {{\n").as_str());
            ret.push_str("    fn from(value: u32) -> Self {\n");
            ret.push_str("        Self(value)\n");
            ret.push_str("    }\n");
            ret.push_str("}\n");
            ret.push('\n');
        }
        "u64" => {
            ret.push_str(format!("impl From<[u8; 1]> for {ie_name} {{\n").as_str());
            ret.push_str("    fn from(value: [u8; 1]) -> Self {\n");
            ret.push_str("        Self(value[0] as u64)\n");
            ret.push_str("    }\n");
            ret.push_str("}\n\n");

            ret.push_str(format!("impl From<[u8; 2]> for {ie_name} {{\n").as_str());
            ret.push_str("    fn from(value: [u8; 2]) -> Self {\n");
            ret.push_str("        let tmp = u16::from_be_bytes(value);\n");
            ret.push_str("        Self(tmp as u64)\n");
            ret.push_str("    }\n");
            ret.push_str("}\n\n");

            ret.push_str(format!("impl From<[u8; 4]> for {ie_name} {{\n").as_str());
            ret.push_str("    fn from(value: [u8; 4]) -> Self {\n");
            ret.push_str("        let tmp = u32::from_be_bytes(value);\n");
            ret.push_str("        Self(tmp as u64)\n");
            ret.push_str("    }\n");
            ret.push_str("}\n\n");

            ret.push_str(format!("impl From<[u8; 8]> for {ie_name} {{\n").as_str());
            ret.push_str("    fn from(value: [u8; 8]) -> Self {\n");
            ret.push_str("        Self(u64::from_be_bytes(value))\n");
            ret.push_str("    }\n");
            ret.push_str("}\n");

            ret.push_str(format!("impl From<u64> for {ie_name} {{\n").as_str());
            ret.push_str("    fn from(value: u64) -> Self {\n");
            ret.push_str("        Self(value)\n");
            ret.push_str("    }\n");
            ret.push_str("}\n");
            ret.push('\n');
        }
        _ => {
            // TODO: generate converts for the rest of data types
        }
    }
    ret
}

fn generate_u8_deserializer(ie_name: &String, enum_subreg: bool) -> TokenStream {
    let ident = Ident::new(ie_name.as_str(), Span::call_site());
    let subreg = if enum_subreg {
        quote! {
            let enum_val = #ident::from(value);
            (buf, Field::#ident(enum_val))
        }
    } else if ie_name == "tcpControlBits" {
        quote! { (buf, Field::#ident(netgauze_iana::tcp::TCPHeaderFlags::from(value))) }
    } else {
        quote! { (buf, Field::#ident(value)) }
    };

    quote! {
        {
            let (buf, value) = match length {
                1 => nom::number::complete::be_u8(buf)?,
                _ => return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{ie_name: #ie_name.to_string(), length})))
            };
            #subreg
        }
    }
}

fn generate_u16_deserializer(ie_name: &String, enum_subreg: bool) -> TokenStream {
    let ident = Ident::new(ie_name.as_str(), Span::call_site());
    let subreg = if enum_subreg {
        quote! {
            let enum_val = #ident::from(value);
            (buf, Field::#ident(enum_val))
        }
    } else if ie_name == "tcpControlBits" {
        quote! { (buf, Field::#ident(netgauze_iana::tcp::TCPHeaderFlags::from(value))) }
    } else {
        quote! { (buf, Field::#ident(value)) }
    };

    quote! {
        {
            let (buf, value) = match length {
                1 => {
                    let (buf, value) = nom::number::complete::be_u8(buf)?;
                    (buf, value as u16)
                },
                2 => nom::number::complete::be_u16(buf)?,
                _ => return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{ie_name: #ie_name.to_string(), length})))
            };
            #subreg
        }
    }
}

fn generate_u32_deserializer(ie_name: &String, enum_subreg: bool) -> TokenStream {
    let ident = Ident::new(ie_name.as_str(), Span::call_site());
    let subreg = if enum_subreg {
        quote! {
            let enum_val = #ident::from(res);
            (buf.slice(len..), Field::#ident(enum_val))
        }
    } else {
        quote! { (buf.slice(len..), Field::#ident(res)) }
    };
    quote! {
        {
            let len = length as usize;
            if length > 4 || buf.input_len() < len {
                return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{ie_name: #ie_name.to_string(), length})))
            }
            let mut res = 0u32;
            for byte in buf.iter_elements().take(len) {
                 res = (res << 8) + byte as u32;
            }
            #subreg
        }
    }
}

fn generate_u64_deserializer(ie_name: &String, enum_subreg: bool) -> TokenStream {
    let ident = Ident::new(ie_name.as_str(), Span::call_site());
    let subreg = if enum_subreg {
        quote! {
            let enum_val = #ident::from(res);
            (buf.slice(len..), Field::#ident(enum_val))
        }
    } else {
        quote! { (buf.slice(len..), Field::#ident(res)) }
    };
    quote! {
        {
            let len = length as usize;
            if length > 8 || buf.input_len() < len {
                return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{ie_name: #ie_name.to_string(), length})))
            }
            let mut res = 0u64;
            for byte in buf.iter_elements().take(len) {
                 res = (res << 8) + byte as u64;
            }
            #subreg
        }
    }
}

fn generate_u256_deserializer(ie_name: &String, enum_subreg: bool) -> TokenStream {
    let ident = Ident::new(ie_name.as_str(), Span::call_site());
    let subreg = if enum_subreg {
        quote! {
            let enum_val = #ident::from(res);
            (buf.slice(len..), Field::#ident(enum_val))
        }
    } else {
        quote! { (buf.slice(len..), Field::#ident(Box::new(res))) }
    };
    quote! {
        {
            let len = length as usize;
            if length > 32 || buf.input_len() < len {
                return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{ie_name: #ie_name.to_string(), length})))
            }
            let mut res: [u8; 32] = [0; 32];
            res[..len].copy_from_slice(buf.slice(..len).fragment());
            #subreg
        }
    }
}

fn generate_i8_deserializer(ie_name: &String) -> TokenStream {
    let ident = Ident::new(ie_name.as_str(), Span::call_site());
    quote! {
        {
            let (buf, value) = match length {
                1 => nom::number::complete::be_i8(buf)?,
                _ => return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{ie_name: #ie_name.to_string(), length})))
            };
            (buf, Field::#ident(value))
        }
    }
}

fn generate_i16_deserializer(ie_name: &String) -> TokenStream {
    let ident = Ident::new(ie_name.as_str(), Span::call_site());
    quote! {
        {
            let len = length as usize;
            if length > 2 || buf.input_len() < len {
                return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{ie_name: #ie_name.to_string(), length})))
            }
            let mut res = 0u16;
            let mut first = true;
            for byte in buf.iter_elements().take(len) {
                if first {
                    if byte & 0x80 != 0 {
                        res = u16::MAX;
                    }
                    first = false;
                }
                res = (res << 8) + byte as u16;
            }
            (buf.slice(len..), Field::#ident(res as i16))
        }
    }
}

fn generate_i32_deserializer(ie_name: &String) -> TokenStream {
    let ident = Ident::new(ie_name.as_str(), Span::call_site());
    quote! {
        {
            let len = length as usize;
            if length > 4 || buf.input_len() < len {
                return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{ie_name: #ie_name.to_string(), length})))
            }
            let mut res = 0u32;
            let mut first = true;
            for byte in buf.iter_elements().take(len) {
                if first {
                    if byte & 0x80 != 0 {
                        res = u32::MAX;
                    }
                    first = false;
                }
                res = (res << 8) + byte as u32;
            }
            (buf.slice(len..), Field::#ident(res as i32))
        }
    }
}

fn generate_i64_deserializer(ie_name: &String) -> TokenStream {
    let ident = Ident::new(ie_name.as_str(), Span::call_site());
    quote! {
        {
            let len = length as usize;
            if length > 8 || buf.input_len() < len {
                return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{ie_name: #ie_name.to_string(), length})))
            }
            let mut res = 0u64;
            let mut first = true;
            for byte in buf.iter_elements().take(len) {
                if first {
                    if byte & 0x80 != 0 {
                        res = u64::MAX;
                    }
                    first = false;
                }
                res = (res << 8) + byte as u64;
            }
            (buf.slice(len..), Field::#ident(res as i64))
        }
    }
}

fn generate_f32_deserializer(ie_name: &String) -> TokenStream {
    let ident = Ident::new(ie_name.as_str(), Span::call_site());
    quote! {
        {
             let (buf, value) = match length {
                4 => nom::number::complete::be_f32(buf)?,
                _ => return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{ie_name: #ie_name.to_string(), length})))
             };
            (buf, Field::#ident(value.into()))
        }
    }
}

fn generate_f64_deserializer(ie_name: &String) -> TokenStream {
    let ident = Ident::new(ie_name.as_str(), Span::call_site());
    quote! {
        {
            let (buf, value) = match length {
                8 => nom::number::complete::be_f64(buf)?,
                _ => return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{ie_name: #ie_name.to_string(), length})))
             };
            (buf, Field::#ident(value.into()))
        }
    }
}

fn generate_bool_deserializer(ie_name: &String) -> TokenStream {
    let ident = Ident::new(ie_name.as_str(), Span::call_site());
    quote! {
        {
            let (buf, value) = match length {
                1 => nom::number::complete::be_u8(buf)?,
                _ => return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{ie_name: #ie_name.to_string(), length})))
             };
            (buf, Field::#ident(value != 0))
        }
    }
}

fn generate_mac_address_deserializer(ie_name: &String) -> TokenStream {
    let ident = Ident::new(ie_name, Span::call_site());
    quote! {
        {
            if length != 6 {
                return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{ie_name: #ie_name.to_string(), length})))
            }
            let (buf, b0) = nom::number::complete::be_u8(buf)?;
            let (buf, b1) = nom::number::complete::be_u8(buf)?;
            let (buf, b2) = nom::number::complete::be_u8(buf)?;
            let (buf, b3) = nom::number::complete::be_u8(buf)?;
            let (buf, b4) = nom::number::complete::be_u8(buf)?;
            let (buf, b5) = nom::number::complete::be_u8(buf)?;
            (buf, Field::#ident([b0, b1, b2, b3, b4, b5]))
        }
    }
}

fn generate_string_deserializer(ie_name: &str) -> TokenStream {
    let ident = Ident::new(ie_name, Span::call_site());
    quote! {
        {
            if length == u16::MAX {
                let (buf, short_length) = nom::number::complete::be_u8(buf)?;
                let (buf, variable_length) = if short_length == u8::MAX {
                    let mut variable_length: u32= 0;
                    let (buf, part1) = nom::number::complete::be_u8(buf)?;
                    let (buf, part2) = nom::number::complete::be_u8(buf)?;
                    let (buf, part3) = nom::number::complete::be_u8(buf)?;
                    variable_length = (variable_length << 8) + part1  as u32;
                    variable_length = (variable_length << 8) + part2  as u32;
                    variable_length = (variable_length << 8) + part3  as u32;
                    (buf, variable_length)
                } else {
                    (buf, short_length as u32)
                };
                let (buf, value) = nom::combinator::map_res(nom::bytes::complete::take(variable_length), |str_buf: netgauze_parse_utils::Span<'_>| {
                    let result = ::std::str::from_utf8(&str_buf);
                    result.map(|x| x.into())
                })(buf)?;
                (buf,  Field::#ident(value))
            } else {
                let (buf, value) =
                nom::combinator::map_res(nom::bytes::complete::take(length), |str_buf: netgauze_parse_utils::Span<'_>| {
                    let nul_range_end = str_buf
                        .iter()
                        .position(|&c| c == b'\0')
                        .unwrap_or(str_buf.len());
                    let result = ::std::str::from_utf8(&str_buf[..nul_range_end]);
                    result.map(|x| x.into())
                })(buf)?;
                (buf,  Field::#ident(value))
            }
        }
    }
}

fn generate_ipv4_deserializer(ie_name: &String) -> TokenStream {
    let ident = Ident::new(ie_name, Span::call_site());
    quote! {
        {
            if length != 4 {
                return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{ie_name: #ie_name.to_string(), length})))
            }
            let (buf, ip) = nom::number::complete::be_u32(buf)?;
            let value = std::net::Ipv4Addr::from(ip);
            (buf, Field::#ident(value))
        }
    }
}

fn generate_ipv6_deserializer(ie_name: &String) -> TokenStream {
    let ident = Ident::new(ie_name, Span::call_site());
    quote! {
        {
            if length != 16 {
                return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{ie_name: #ie_name.to_string(), length})))
            }
            let (buf, ip) = nom::number::complete::be_u128(buf)?;
            let value = std::net::Ipv6Addr::from(ip);
            (buf, Field::#ident(value))
        }
    }
}

fn generate_date_time_seconds(ie_name: &String) -> TokenStream {
    let ident = Ident::new(ie_name, Span::call_site());
    quote! {
        {
            if length != 4 {
                return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{ie_name: #ie_name.to_string(), length})))
            };
            let (buf, secs) = nom::number::complete::be_u32(buf)?;
            let value = match chrono::Utc.timestamp_opt(secs as i64, 0) {
                chrono::LocalResult::Single(val) => val,
                _ => {
                    return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidTimestamp{ie_name: #ie_name.to_string(), seconds: secs})));
                }
            };
            (buf, Field::#ident(value))
        }
    }
}

fn generate_date_time_milli(ie_name: &String) -> TokenStream {
    let ident = Ident::new(ie_name, Span::call_site());
    quote! {
        {
            if length != 8 {
                return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{ie_name: #ie_name.to_string(), length})))
            };
            let (buf, millis) = nom::number::complete::be_u64(buf)?;
            let value = match chrono::Utc.timestamp_millis_opt(millis as i64) {
                chrono::LocalResult::Single(val) => val,
                _ => {
                    return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidTimestampMillis{ie_name: #ie_name.to_string(), millis})));
                }
            };
            (buf, Field::#ident(value))
        }
    }
}

fn generate_date_time_micro(ie_name: &String) -> TokenStream {
    let ident = Ident::new(ie_name, Span::call_site());
    quote! {
        {
            if length != 8 {
                return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{ie_name: #ie_name.to_string(), length})))
            }
            let (buf, seconds) = nom::number::complete::be_u32(buf)?;
            let (buf, fraction) = nom::number::complete::be_u32(buf)?;
            // Convert 1/2^32 of a second to nanoseconds
            let f: u32 = (1_000_000_000f64 * (fraction as f64 / u32::MAX as f64)) as u32;
            let value = match chrono::Utc.timestamp_opt(seconds as i64, f) {
                chrono::LocalResult::Single(val) => val,
                _ => {
                    return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidTimestampFraction{ie_name: #ie_name.to_string(), seconds, fraction})));
                }
            };
            (buf, Field::#ident(value))
        }
    }
}

fn generate_vec_u8_deserializer(ie_name: &str) -> TokenStream {
    let ident = Ident::new(ie_name, Span::call_site());
    quote! {
        {
            let (buf, value) = nom::multi::count(nom::number::complete::be_u8, length as usize)(buf)?;
            (buf, Field::#ident(value.into_boxed_slice()))
        }
    }
}

fn generate_mpls_deserializer(ie_name: &String) -> TokenStream {
    let ident = Ident::new(ie_name, Span::call_site());
    quote! {
        {
            if length != 3 {
                return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::InvalidLength{ie_name: #ie_name.to_string(), length})))
            }
            let (buf, value) = nom::multi::count(nom::number::complete::be_u8, length as usize)(buf)?;
            (buf, Field::#ident([value[0], value[1], value[2]]))
        }
    }
}

fn generate_ie_deserializer(data_type: &str, ie_name: &String, enum_subreg: bool) -> TokenStream {
    match data_type {
        "octetArray" => {
            if is_mpls_type(ie_name) {
                generate_mpls_deserializer(ie_name)
            } else {
                generate_vec_u8_deserializer(ie_name)
            }
        }
        "unsigned8" => generate_u8_deserializer(ie_name, enum_subreg),
        "unsigned16" => generate_u16_deserializer(ie_name, enum_subreg),
        "unsigned32" => generate_u32_deserializer(ie_name, enum_subreg),
        "unsigned64" => generate_u64_deserializer(ie_name, enum_subreg),
        "signed8" => generate_i8_deserializer(ie_name),
        "signed16" => generate_i16_deserializer(ie_name),
        "signed32" => generate_i32_deserializer(ie_name),
        "signed64" => generate_i64_deserializer(ie_name),
        "float32" => generate_f32_deserializer(ie_name),
        "float64" => generate_f64_deserializer(ie_name),
        "boolean" => generate_bool_deserializer(ie_name),
        "macAddress" => generate_mac_address_deserializer(ie_name),
        "string" => generate_string_deserializer(ie_name),
        "dateTimeSeconds" => generate_date_time_seconds(ie_name),
        "dateTimeMilliseconds" => generate_date_time_milli(ie_name),
        "dateTimeMicroseconds" => generate_date_time_micro(ie_name),
        // Nano and micro are using the same representation,
        // see https://www.rfc-editor.org/rfc/rfc7011.html#section-6.1.9
        "dateTimeNanoseconds" => generate_date_time_micro(ie_name),
        "ipv4Address" => generate_ipv4_deserializer(ie_name),
        "ipv6Address" => generate_ipv6_deserializer(ie_name),
        // TODO: better parsing for IPFIX structured Data
        "basicList" => generate_vec_u8_deserializer(ie_name),
        "subTemplateList" => generate_vec_u8_deserializer(ie_name),
        "subTemplateMultiList" => generate_vec_u8_deserializer(ie_name),
        "unsigned256" => generate_u256_deserializer(ie_name, enum_subreg),
        ty => todo!("Unsupported deserialization for type: {}", ty),
    }
}

pub(crate) fn generate_pkg_ie_deserializers(
    vendor_mod: &str,
    ies: &[InformationElement],
) -> TokenStream {
    let mut token_stream = TokenStream::new();
    // Not every vendor contains big integer types
    if ies.iter().any(|x| {
        [
            "unsigned32",
            "unsigned64",
            "signed16",
            "signed32",
            "signed64",
        ]
        .contains(&x.data_type.as_str())
    }) {
        token_stream.extend(quote! {use nom::{InputIter, InputLength, Slice};});
    }
    // Not every vendor is using time based values
    if ies.iter().any(|x| x.data_type.contains("Time")) {
        token_stream.extend(quote! {use chrono::TimeZone;});
    }
    let vendor_ident = Ident::new(vendor_mod, Span::call_site());
    token_stream.extend(quote! {use crate::ie::#vendor_ident::*;});
    token_stream.extend(generate_ie_values_deserializers(ies));
    token_stream
}

pub(crate) fn generate_pkg_ie_serializers(
    vendor_mod: &str,
    ies: &[InformationElement],
) -> TokenStream {
    let vendor_ident = Ident::new(vendor_mod, Span::call_site());

    let ie_len = ies.iter().map(|ie| {
        let name = Ident::new(&ie.name, Span::call_site());
        match ie.data_type.as_str() {
            "octetArray"
            | "macAddress"
            | "basicList"
            | "subTemplateList"
            | "subTemplateMultiList" => {
                quote! {
                    Self::#name(value) => {
                        value.len()
                    }
                }
            }
            "unsigned8" | "signed8" | "boolean" => {
                quote! {
                    Self::#name(_value) => {
                        1
                    }
                }
            }
            "unsigned16" | "signed16" => {
                quote! {
                    Self::#name(_value) => {
                        match length {
                            None => 2,
                            Some(len) => len as usize
                        }
                    }
                }
            }
            "unsigned32" | "signed32" | "float32" => {
                quote! {
                    Self::#name(_value) => {
                        match length {
                            None => 4,
                            Some(len) => len as usize
                        }
                    }
                }
            }
            "unsigned64" | "signed64" | "float64" => {
                quote! {
                    Self::#name(_value) => {
                        match length {
                            None => 8,
                            Some(len) => len as usize
                        }
                    }
                }
            }
            "string" => {
                quote! {
                    Self::#name(value) => {
                        match length {
                            None => value.len(),
                            Some(len) => if len == u16::MAX {
                                if value.len() < u8::MAX as usize {
                                    // One octet for the length field
                                    value.len() + 1
                                } else {
                                    // 4 octets for the length field, first is 255 and other three carries the len
                                    value.len() + 4
                                }
                            } else {
                                len as usize
                            }
                        }
                    }
                }
            }
            "dateTimeSeconds" | "ipv4Address" => {
                quote! {
                    Self::#name(_value) => {
                        4
                    }
                }
            }
            "dateTimeMilliseconds" | "dateTimeMicroseconds" | "dateTimeNanoseconds" => {
                quote! {
                    Self::#name(_value) => {
                        8
                    }
                }
            }
            "ipv6Address" => {
                quote! {
                    Self::#name(_value) => {
                        16
                    }
                }
            }
            "unsigned256" => {
                quote! {
                    Self::#name(value) => {
                        match length {
                            None => value.len(),
                            Some(len) => len as usize
                        }
                    }
                }
            }
            ty => todo!("Unsupported serialization for type: {}", ty),
        }
    });

    let ie_ser = ies.iter().map(|ie|{
        let ie_name = ie.name.clone();
        let ident = Ident::new(&ie_name, Span::call_site());
        match ie.data_type.as_str() {
            "octetArray" => {
                quote! {
                    Self::#ident(value) => {
                        writer.write_all(value.as_ref())?
                    }
                }
            }
            "unsigned8" => {
                if ie.subregistry.is_some() {
                    quote! {
                        Self::#ident(value) => {
                            let num_val = u8::from(*value);
                            writer.write_u8(num_val)?
                        }
                    }
                } else {
                    quote! {
                        Self::#ident(value) => {
                            writer.write_u8(*value)?
                        }
                    }
                }
            }
            "unsigned16" => {
                let value = if ie.subregistry.is_some() || ie.name == "tcpControlBits" {
                    quote! { let value = u16::from(*value); }
                } else {
                    quote! { let value = *value; }
                };
                quote! {
                    Self::#ident(value) => {
                        #value
                        match length {
                            None => writer.write_u16::<byteorder::NetworkEndian>(value)?,
                            Some(len) => {
                                let be_bytes = value.to_be_bytes();
                                if usize::from(len) > be_bytes.len() {
                                   return Err(FieldWritingError::InvalidLength{ie_name: #ie_name.to_string(), length: len});
                                }
                                let begin_offset = be_bytes.len() - len as usize;
                                writer.write_all(&be_bytes[begin_offset..])?
                            }
                        }
                    }
                }
            }
            "unsigned32" => {
                let value = if ie.subregistry.is_some() {
                    quote! { let value = u32::from(*value); }
                } else {
                    quote! { let value = *value; }
                };
                quote! {
                    Self::#ident(value) => {
                        #value
                        match length {
                            None => writer.write_u32::<byteorder::NetworkEndian>(value)?,
                            Some(len) => {
                                let be_bytes = value.to_be_bytes();
                                if usize::from(len) > be_bytes.len() {
                                   return Err(FieldWritingError::InvalidLength{ie_name: #ie_name.to_string(), length: len});
                                }
                                let begin_offset = be_bytes.len() - len as usize;
                                writer.write_all(&be_bytes[begin_offset..])?
                            }
                        }
                    }
                }
            }
            "unsigned64" => {
                let value = if ie.subregistry.is_some() {
                    quote! { let value = u64::from(*value); }
                } else {
                    quote! { let value = *value; }
                };
                quote! {
                    Self::#ident(value) => {
                        #value
                        match length {
                            None => writer.write_u64::<byteorder::NetworkEndian>(value)?,
                            Some(len) => {
                                let be_bytes = value.to_be_bytes();
                                if usize::from(len) > be_bytes.len() {
                                   return Err(FieldWritingError::InvalidLength{ie_name: #ie_name.to_string(), length: len});
                                }
                                let begin_offset = be_bytes.len() - len as usize;
                                writer.write_all(&be_bytes[begin_offset..])?
                            }
                        }
                    }
                }
            }
            "signed8" => {
                if ie.subregistry.is_some() {
                    quote! {
                        Self::#ident(value) => {
                            let num_val = i8::from(*value);
                            writer.write_i8(num_val)?
                        }
                    }
                } else {
                    quote! {
                        Self::#ident(value) => {
                            writer.write_i8(*value)?
                        }
                    }
                }
            }
            "signed16" => {
                let value = if ie.subregistry.is_some(){
                    quote! { let value = i16::from(*value); }
                } else {
                    quote! { let value = *value; }
                };
                quote! {
                    Self::#ident(value) => {
                        #value
                        match length {
                            None => writer.write_i16::<byteorder::NetworkEndian>(value)?,
                            Some(len) => {
                                let be_bytes = value.to_be_bytes();
                                if usize::from(len) > be_bytes.len() {
                                   return Err(FieldWritingError::InvalidLength{ie_name: #ie_name.to_string(), length: len});
                                }
                                let begin_offset = be_bytes.len() - len as usize;
                                writer.write_all(&be_bytes[begin_offset..])?
                            }
                        }
                    }
                }
            }
            "signed32" => {
                let value = if ie.subregistry.is_some(){
                    quote! { let value = i32::from(*value); }
                } else {
                    quote! { let value = *value; }
                };
                quote! {
                    Self::#ident(value) => {
                        #value
                        match length {
                            None => writer.write_i32::<byteorder::NetworkEndian>(value)?,
                            Some(len) => {
                                let be_bytes = value.to_be_bytes();
                                if usize::from(len) > be_bytes.len() {
                                   return Err(FieldWritingError::InvalidLength{ie_name: #ie_name.to_string(), length: len});
                                }
                                let begin_offset = be_bytes.len() - len as usize;
                                writer.write_all(&be_bytes[begin_offset..])?
                            }
                        }
                    }
                }
            }
            "signed64" => {
                let value = if ie.subregistry.is_some(){
                    quote! { let value = i64::from(*value); }
                } else {
                    quote! { let value = *value; }
                };
                quote! {
                    Self::#ident(value) => {
                        #value
                        match length {
                            None => writer.write_i32::<byteorder::NetworkEndian>(value)?,
                            Some(len) => {
                                let be_bytes = value.to_be_bytes();
                                if usize::from(len) > be_bytes.len() {
                                   return Err(FieldWritingError::InvalidLength{ie_name: #ie_name.to_string(), length: len});
                                }
                                let begin_offset = be_bytes.len() - len as usize;
                                writer.write_all(&be_bytes[begin_offset..])?
                            }
                        }
                    }
                }
            }
            "float32" => {
                quote! {
                    Self::#ident(value) => {
                        let value = f32::from(*value);
                        match length {
                            None => writer.write_f32::<byteorder::NetworkEndian>(value)?,
                            Some(len) => {
                                let be_bytes = value.to_be_bytes();
                                if usize::from(len) > be_bytes.len() {
                                   return Err(FieldWritingError::InvalidLength{ie_name: #ie_name.to_string(), length: len});
                                }
                                let begin_offset = be_bytes.len() - len as usize;
                                writer.write_all(&be_bytes[begin_offset..])?
                            }
                        }
                    }
                }
            }
            "float64" => {
                quote! {
                    Self::#ident(value) => {
                        let value = f64::from(*value);
                        match length {
                            None => writer.write_f64::<byteorder::NetworkEndian>(value)?,
                            Some(len) => {
                                let be_bytes = value.to_be_bytes();
                                if usize::from(len) > be_bytes.len() {
                                   return Err(FieldWritingError::InvalidLength{ie_name: #ie_name.to_string(), length: len});
                                }
                                let begin_offset = be_bytes.len() - len as usize;
                                writer.write_all(&be_bytes[begin_offset..])?
                            }
                        }
                    }
                }
            }
            "boolean" => {
                quote! {
                    Self::#ident(value) => {
                        writer.write_u8(*value as u8)?
                    }
                }
            }
            "macAddress" => {
                quote! {
                    Self::#ident(value) => {
                        writer.write_all(value)?
                    }
                }
            }
            "string" => {
                quote! {
                    Self::#ident(value) => {
                        match length {
                            Some(u16::MAX) | None => {
                                let bytes = value.as_bytes();
                                if bytes.len() < u8::MAX as usize {
                                    writer.write_u8(bytes.len() as u8)?;
                                } else {
                                    writer.write_u8(u8::MAX)?;
                                    writer.write_all(&bytes.len().to_be_bytes()[1..])?;
                                }
                                writer.write_all(value.as_bytes())?;
                            }
                            Some(len) => {
                                writer.write_all(value.as_bytes())?;
                                // fill the rest with zeros
                                for _ in value.len()..(len as usize) {
                                    writer.write_u8(0)?
                                }
                            }
                        }
                    }
                }
            }
            "dateTimeSeconds" => {
                quote! {
                    Self::#ident(value) => {
                        writer.write_u32::<byteorder::NetworkEndian>(value.timestamp() as u32)?
                    }
                }
            }
            "dateTimeMilliseconds" => {
                quote! {
                    Self::#ident(value) => {
                        writer.write_u64::<byteorder::NetworkEndian>(value.timestamp_millis() as u64)?;
                    }
                }
            }
            "dateTimeMicroseconds" | "dateTimeNanoseconds" => {
                quote! {
                    Self::#ident(value) => {
                        writer.write_u32::<byteorder::NetworkEndian>(value.timestamp() as u32)?;
                        let nanos = value.timestamp_subsec_nanos();
                        // Convert 1/2**32 of a second to a fraction of a nano second
                        let fraction = (nanos as u64 * u32::MAX as u64) / 1_000_000_000;
                        writer.write_u32::<byteorder::NetworkEndian>(fraction as u32)?;
                    }
                }
            }
            "ipv4Address" => {
                quote! {
                    Self::#ident(value) => {
                        writer.write_all(&value.octets())?
                    }
                }
            }
            "ipv6Address" => {
                quote! {
                    Self::#ident(value) => {
                        writer.write_all(&value.octets())?
                    }
                }
            }
            "basicList" => {
                quote! {
                    Self::#ident(value) => {
                        writer.write_all(value)?
                    }
                }
            }
            "subTemplateList" => {
                quote! {
                    Self::#ident(value) => {
                        writer.write_all(value)?
                    }
                }
            }
            "subTemplateMultiList" => {
                quote! {
                    Self::#ident(value) => {
                        writer.write_all(value)?
                    }
                }
            }
            "unsigned256" => {
                quote! {
                    Self::#ident(value) => {
                        let len = match length {
                            None => value.len(),
                            Some(len) => len as usize,
                        };
                        writer.write_all(value[..len].as_ref())?
                    }
                }
            }
            ty => todo!("Unsupported serialization for type: {}", ty),
        }
    });

    quote! {
        use byteorder::WriteBytesExt;
        use crate::ie::#vendor_ident::*;

        #[allow(non_camel_case_types)]
        #[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
        pub enum FieldWritingError {
            StdIOError(#[from_std_io_error] String),
            InvalidLength{ie_name: String, length: u16},
        }

        impl std::fmt::Display for FieldWritingError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    Self::StdIOError(err) => write!(f, "{err}"),
                    Self::InvalidLength{ie_name, length} => write!(f, "writing error of {ie_name} invalid length {length}"),
                }
            }
        }

        impl std::error::Error for FieldWritingError {}

        impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, FieldWritingError> for Field {
            const BASE_LENGTH: usize = 0;
            fn len(&self, length: Option<u16>) -> usize {
                match self {
                    #(#ie_len,)*
                }
            }

            fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), FieldWritingError> {
                match self {
                    #(#ie_ser)*
                }
                Ok(())
            }
        }
    }
}

pub(crate) fn generate_fields_enum(ies: &[InformationElement]) -> TokenStream {
    let ie_fields = ies.iter().map(|ie| {
        let name = Ident::new(&ie.name, Span::call_site());
        if ie.name == "tcpControlBits" {
            quote! { #name(netgauze_iana::tcp::TCPHeaderFlags) }
        } else {
            let rust_type = get_rust_type(&ie.data_type, &ie.name);
            let field_type = if ie.subregistry.is_some() {
                ie.name.clone()
            } else {
                rust_type
            };
            let field_type_ty =  syn::parse_str::<syn::Type>(&field_type).unwrap();
            let mut doc_comments = Vec::new();
            for line in ie.description.lines() {
                let line = format!(" {}", line.trim());
                doc_comments.push(quote! { #[doc = #line] });
            }
            if !doc_comments.is_empty() && !ie.xrefs.is_empty(){
                let empty = "";
                doc_comments.push(quote! { #[doc = #empty] });
            }
            for xref_link in ie.xrefs.iter().filter_map(generate_xref_link) {
                let ref_link = format!(" Reference: {xref_link}");
                doc_comments.push(quote! { #[doc = #ref_link] });
            }
            if field_type.contains("Date") {
                quote! {
                    #(#doc_comments)*
                    #name(#[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_datetime))] #field_type_ty)
                }
            } else {
                quote! {
                    #(#doc_comments)*
                    #name(#field_type_ty)
                }
            }
        }
    });
    let ie_variants = ies.iter().map(|ie| {
        let name = Ident::new(&ie.name, Span::call_site());
        quote! { Self::#name(_) => IE::#name }
    });

    let converters = generate_into_for_field(ies, &[]);
    let OperationVariants {
        ie_add_variants,
        ie_add_assign_variants,
        ie_min_variants,
        ie_min_assign_variants,
        ie_max_variants,
        ie_max_assign_variants,
        ie_bitwise_or_variants,
        ie_bitwise_or_assign_variants,
    } = field_operations_variants(ies);

    quote! {
        #[derive(Debug, Clone, Eq, PartialEq, strum_macros::Display)]
        pub enum FieldOperationError {
            InapplicableAdd(IE, IE),
            InapplicableMin(IE, IE),
            InapplicableMax(IE, IE),
            InapplicableBitwise(IE, IE),
        }
        impl std::error::Error for FieldOperationError {}

        impl From<FieldOperationError> for crate::FieldOperationError {
            fn from(value: FieldOperationError) -> crate::FieldOperationError {
                match value {
                    FieldOperationError::InapplicableAdd(lhs, rhs) => crate::FieldOperationError::InapplicableAdd(lhs.into(), rhs.into()),
                    FieldOperationError::InapplicableMin(lhs, rhs) => crate::FieldOperationError::InapplicableMin(lhs.into(), rhs.into()),
                    FieldOperationError::InapplicableMax(lhs, rhs) => crate::FieldOperationError::InapplicableMax(lhs.into(), rhs.into()),
                    FieldOperationError::InapplicableBitwise(lhs, rhs) => crate::FieldOperationError::InapplicableBitwise(lhs.into(), rhs.into()),
                }
            }
        }


        #[allow(non_camel_case_types)]
        #[derive(strum_macros::Display, Eq, Hash, PartialOrd, Ord, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
        #[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
        pub enum Field {
            #(#ie_fields,)*
        }

        impl Field {
            /// Get the [IE] element for a given field
            pub const fn ie(&self) -> IE {
                match self {
                    #(#ie_variants,)*
                }
            }

            /// Arithmetic addition operation of two fields and produce a field with the new value
            pub fn add_field(&self, rhs: &Field) -> Result<Field, FieldOperationError> {
                #[allow(clippy::match_single_binding)]
                match (self, rhs) {
                    #(#ie_add_variants,)*
                    (f1, f2) => Err(FieldOperationError::InapplicableAdd(f1.ie(), f2.ie())),
                }
            }

            /// The addition assignment operation += of two fields
            pub fn add_assign_field(&mut self, rhs: &Field) -> Result<(), FieldOperationError> {
                #[allow(clippy::match_single_binding)]
                match (self, rhs) {
                    #(#ie_add_assign_variants)*
                    (f1, f2) => Err(FieldOperationError::InapplicableAdd(f1.ie(), f2.ie())),
                }
            }

            /// Bitwise OR operation of two fields and produce a field with the new value
             pub fn bitwise_or_field(&self, other: &Field) -> Result<Field, FieldOperationError> {
                #[allow(clippy::match_single_binding)]
                match (self, other) {
                    #(#ie_bitwise_or_variants,)*
                    (f1, f2) => Err(FieldOperationError::InapplicableBitwise(f1.ie(), f2.ie())),
                }
            }

            /// The bitwise OR assignment operation |= of two fields
            pub fn bitwise_or_assign_field(&mut self, other: &Field) -> Result<(), FieldOperationError> {
                #[allow(clippy::match_single_binding)]
                match (self, other) {
                    #(#ie_bitwise_or_assign_variants)*
                    (f1, f2) => Err(FieldOperationError::InapplicableBitwise(f1.ie(), f2.ie())),
                }
            }

            /// Returns a new field with the minimum of the two fields
            pub fn min_field(&self, rhs: &Field) -> Result<Field, FieldOperationError> {
                #[allow(clippy::match_single_binding)]
                match (self, rhs) {
                    #(#ie_min_variants,)*
                    (f1, f2) => Err(FieldOperationError::InapplicableMin(f1.ie(), f2.ie())),
                }
            }

            /// Assign the field's value to be minimum of the two fields
            pub fn min_assign_field(&mut self, rhs: &Field) -> Result<(), FieldOperationError> {
                #[allow(clippy::match_single_binding)]
                match (self, rhs) {
                    #(#ie_min_assign_variants)*
                    (f1, f2) => Err(FieldOperationError::InapplicableMin(f1.ie(), f2.ie())),
                }
            }

            /// Returns a new field with the maximum of the two fields
            pub fn max_field(&self, rhs: &Field) -> Result<Field, FieldOperationError> {
                #[allow(clippy::match_single_binding)]
                match (self, rhs) {
                    #(#ie_max_variants,)*
                    (f1, f2) => Err(FieldOperationError::InapplicableMax(f1.ie(), f2.ie())),
                }
            }

            /// Assign the field's value to be maximum of the two fields
            pub fn max_assign_field(&mut self, rhs: &Field) -> Result<(), FieldOperationError> {
                #[allow(clippy::match_single_binding)]
                match (self, rhs) {
                    #(#ie_max_assign_variants)*
                    (f1, f2) => Err(FieldOperationError::InapplicableMax(f1.ie(), f2.ie())),
                }
            }
        }

        #converters
    }
}

/// Generates `impl TryInto<NativeRustType> for Field` to convert any field to
/// its native rust type Additionally for fields that could be represented as
/// String, a TryInto is generated Some special formatting is applied for
/// MacAddress to make it human-readable.
pub fn generate_into_for_field(
    ies: &[InformationElement],
    vendors: &[(String, String, u32)],
) -> TokenStream {
    // note this list is the inverse of what is defined in `get_rust_type`
    let rust_converted_types = [
        "u8",
        "u16",
        "u32",
        "u64",
        "i8",
        "i16",
        "i32",
        "i64",
        "ordered_float::OrderedFloat<f32>",
        "ordered_float::OrderedFloat<f64>",
        "bool",
        "super::MacAddress",
        "String",
        "chrono::DateTime<chrono::Utc>",
        "std::net::Ipv4Addr",
        "std::net::Ipv6Addr",
        "Box<[u8]>",
        "Box<[u8; 32]>",
        "Vec<String>",
    ];
    let mut code = TokenStream::new();
    for convert_rust_type in rust_converted_types {
        let ty = syn::parse_str::<syn::Type>(convert_rust_type).expect("wrong type");
        // only IANA have unknown, thus we check vendor is not configured
        let unknown = if !vendors.is_empty() {
            // only IANA have unknown, thus we check vendor is not configured
            quote! { Self::Unknown{ .. } => Err(Self::Error::UnknownField), }
        } else {
            quote! {}
        };
        let vendor_variants = vendors.iter().map(|(name, _pkg, _)| {
            let name = Ident::new(name, Span::call_site());
            quote! { Self::#name(value) => { value.try_into() } }
        });
        let ie_variants = ies.iter().map(|ie| {
            let name = Ident::new(&ie.name, Span::call_site());
            let ie_rust_type = get_rust_type(&ie.data_type, &ie.name);
            if ie_rust_type == convert_rust_type
                && ie.subregistry.is_none()
                && ie.name != "tcpControlBits"
            {
                // Native type conversion
                quote! { Self::#name(value) => { Ok(value) } }
            } else if convert_rust_type == "String"
                && ie_rust_type != "Box<[u8]>"
                && ie_rust_type != "[u8; 3]"
                && ie_rust_type != "Box<[u8; 32]>"
                && ie_rust_type != "super::MacAddress"
            {
                // Convert to using the defined Display implementation of the method
                quote! { Self::#name(value) => { Ok(format!("{value}")) } }
            } else if convert_rust_type == "String" && ie_rust_type == "super::MacAddress" {
                // convert MacAddresses to human-readable string
                quote! { Self::#name(value) => { Ok(value.iter().map(|x| format!("{x:x}")).collect::<Vec<_>>().join(":").to_string()) } }
            } else if convert_rust_type == "Vec<String>" && ie.name == "tcpControlBits" {
                quote! { Self::#name(value) => { Ok(value.to_vec()) } }
            } else if convert_rust_type == "String" && is_mpls_type(&ie.name) {
                quote! { Self::#name(value) => { Ok(u32::from_be_bytes([0, value[0], value[1], value[2]]).to_string()) } }
            } else if convert_rust_type == "String" && is_mpls_vpn_rd_type(&ie.name) {
                let ie_name_str = &ie.name;
                quote! {
                    Self::#name(value) => {
                        if value.len() != 8 {
                            return Err(
                                Self::Error::InvalidType(
                                    "String".to_string(),
                                    #ie_name_str.to_string(),
                                ),
                            );
                        }

                        let type_field = u16::from_be_bytes([value[0], value[1]]);
                        match type_field {
                            0 => {
                                // Type 0: Administrator field is a 2-octet AS number
                                let admin = u16::from_be_bytes([value[2], value[3]]);
                                let assigned = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
                                Ok(format!("0:{admin}:{assigned}"))
                            }
                            1 => {
                                // Type 1: Administrator field is a 4-octet IPv4 address
                                let admin = std::net::Ipv4Addr::new(value[2], value[3], value[4], value[5]);
                                let assigned = u16::from_be_bytes([value[6], value[7]]);
                                Ok(format!("1:{admin}:{assigned}"))
                            }
                            2 => {
                                // Type 2: Administrator field is a 4-octet AS number
                                let admin = u32::from_be_bytes([value[2], value[3], value[4], value[5]]);
                                let assigned = u16::from_be_bytes([value[6], value[7]]);
                                Ok(format!("2:{admin}:{assigned}"))
                            }
                            _ => {
                                // Unknown type - display as hex with type prefix
                                Ok(format!("{}:{:02x}{:02x}{:02x}{:02x}:{:02x}{:02x}",
                                    type_field,
                                    value[2], value[3],
                                    value[4], value[5],
                                    value[6], value[7]
                                ))
                            }
                        }
                    }
                }
            } else {
                let ie_name_str = &ie.name;
                quote! { Self::#name(_) => { Err(Self::Error::InvalidType(#convert_rust_type.to_string(), #ie_name_str.to_string())) } }
            }
        });
        let conv = quote! {
            impl TryInto<#ty,> for Field {
                type Error = crate::FieldConversionError;

                fn try_into(self) -> Result<#ty, Self::Error> {
                    match self {
                        #unknown
                        #(#vendor_variants)*
                        #(#ie_variants)*
                    }
                }
            }
        };
        code.extend(conv);
    }
    code
}

pub fn get_rust_type(data_type: &str, ie_name: &str) -> String {
    let rust_type = match data_type {
        "octetArray" => "Box<[u8]>",
        "unsigned8" => "u8",
        "unsigned16" => "u16",
        "unsigned32" => "u32",
        "unsigned64" => "u64",
        "signed8" => "i8",
        "signed16" => "i16",
        "signed32" => "i32",
        "signed64" => "i64",
        "float32" => "ordered_float::OrderedFloat<f32>",
        "float64" => "ordered_float::OrderedFloat<f64>",
        "boolean" => "bool",
        "macAddress" => "super::MacAddress",
        "string" => "Box<str>",
        "dateTimeSeconds"
        | "dateTimeMilliseconds"
        | "dateTimeMicroseconds"
        | "dateTimeNanoseconds" => "chrono::DateTime<chrono::Utc>",
        "ipv4Address" => "std::net::Ipv4Addr",
        "ipv6Address" => "std::net::Ipv6Addr",
        "basicList" | "subTemplateList" | "subTemplateMultiList" => "Box<[u8]>",
        "unsigned256" => "Box<[u8; 32]>",
        other => todo!("Implement rust data type conversion for {}", other),
    };
    if is_mpls_type(ie_name) {
        "[u8; 3]".to_string()
    } else {
        rust_type.to_string()
    }
}

fn is_mpls_type(ie_name: &str) -> bool {
    ie_name.eq("mplsTopLabelStackSection") || ie_name.starts_with("mplsLabelStackSection")
}

fn is_mpls_vpn_rd_type(ie_name: &str) -> bool {
    ie_name.ends_with("VpnRouteDistinguisher")
}

pub(crate) fn generate_ie_values(
    ies: &[InformationElement],
    vendor_name: Option<String>,
) -> TokenStream {
    let mut tokens = TokenStream::new();
    for ie in ies {
        let rust_type = get_rust_type(&ie.data_type, &ie.name);
        // Check if we have an InformationElementSubRegistry and is of type
        // ValueNameDescRegistry
        let strum_macros = matches!(
            ie.subregistry.as_ref().and_then(|v| v.first()),
            Some(InformationElementSubRegistry::ValueNameDescRegistry(_))
        );
        let is_copy = rust_type != "Box<[u8]>" && rust_type != "Box<str>";
        let derive = match (strum_macros, is_copy) {
            (true, true) => {
                quote! { #[derive(strum_macros::Display, Copy, Eq, Hash, PartialOrd, Ord, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)] }
            }
            (true, false) => {
                quote! { #[derive(strum_macros::Display, Eq, Hash, PartialOrd, Ord, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)] }
            }
            (false, true) => {
                quote! { #[derive(strum_macros::Display,Copy, Eq, Hash, PartialOrd, Ord, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)] }
            }
            (false, false) => {
                quote! { #[derive(strum_macros::Display, Eq, Hash, PartialOrd, Ord, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)] }
            }
        };
        let code = quote! {
            #[allow(non_camel_case_types)]
            #derive
        };
        let ie_name = Ident::new(&ie.name, Span::call_site());
        if let Some(ie_subregistry) = &ie.subregistry {
            tokens.extend(code);
            tokens.extend(generate_subregistry_enum_and_impl(
                &ie.name,
                &rust_type,
                ie_subregistry,
            ));
            let code = match &vendor_name {
                None => {
                    quote! {
                        impl crate::HasIE for #ie_name {
                            fn ie(&self) -> IE {
                                IE::#ie_name
                            }
                        }
                    }
                }
                Some(name) => {
                    let name = Ident::new(name, Span::call_site());
                    quote! {
                        impl crate::HasIE for #ie_name {
                            fn ie(&self) -> crate::IE {
                                crate::IE::#name(IE::#ie_name)
                            }
                        }
                    }
                }
            };
            tokens.extend(code);
        } else if ie.name == "tcpControlBits" {
            let code = quote! {
                impl HasIE for netgauze_iana::tcp::TCPHeaderFlags {
                    fn ie(&self) -> IE {
                        IE::tcpControlBits
                    }
                }
            };
            tokens.extend(code);
        }

        // TODO: check if value converters are needed
        // ret.push_str(generate_ie_value_converters(&rust_type,
        // &ie.name).as_str());
    }
    tokens
}

fn generate_ie_values_deserializers(ies: &[InformationElement]) -> TokenStream {
    let parsers = ies.iter().map(|ie| {
        let ident = Ident::new(&ie.name, Span::call_site());
        let deser = generate_ie_deserializer(&ie.data_type, &ie.name, ie.subregistry.is_some());
        quote! {
            IE::#ident => #deser
        }
    });
    quote! {
        #[allow(non_camel_case_types)]
        #[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
        pub enum FieldParsingError {
            #[serde(with = "netgauze_parse_utils::ErrorKindSerdeDeref")]
            NomError(#[from_nom] nom::error::ErrorKind),
            InvalidLength{ie_name: String, length: u16},
            InvalidTimestamp{ie_name: String, seconds: u32},
            InvalidTimestampMillis{ie_name: String, millis: u64},
            InvalidTimestampFraction{ie_name: String, seconds: u32, fraction: u32},
            Utf8Error(String),
        }

        impl<'a> nom::error::FromExternalError<netgauze_parse_utils::Span<'a>, std::str::Utf8Error> for LocatedFieldParsingError<'a>
        {
            fn from_external_error(input: netgauze_parse_utils::Span<'a>, _kind: nom::error::ErrorKind, error: std::str::Utf8Error) -> Self {
                LocatedFieldParsingError::new(
                    input,
                    FieldParsingError::Utf8Error(error.to_string()),
                )
            }
        }

        impl std::fmt::Display for FieldParsingError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                   Self::NomError(err) => write!(f, "Nom error {}", nom::Err::Error(err)),
                   Self::InvalidLength{ie_name, length} => write!(f, "error parsing {ie_name} invalid field length {length}"),
                   Self::InvalidTimestamp{ie_name, seconds} => write!(f, "error parsing {ie_name} invalid timestamp {seconds}"),
                   Self::InvalidTimestampMillis{ie_name, millis} => write!(f, "error parsing {ie_name} invalid timestamp {millis}"),
                   Self::InvalidTimestampFraction{ie_name, seconds, fraction} => write!(f, "error parsing {ie_name} invalid timestamp fraction ({seconds}, {fraction})"),
                   Self::Utf8Error(val) => write!(f, "utf8 error {val}"),
                }
            }
        }

        impl std::error::Error for FieldParsingError {}


        impl<'a> netgauze_parse_utils::ReadablePduWithTwoInputs<'a, &IE, u16, LocatedFieldParsingError<'a>> for Field {
            #[inline]
            fn from_wire(
                buf: netgauze_parse_utils::Span<'a>,
                ie: &IE,
                length: u16,
            ) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, LocatedFieldParsingError<'a>> {
                let (buf, value) = match ie {
                     #(#parsers,)*
                };
               Ok((buf, value))
            }
        }
    }
}

pub(crate) fn generate_ie_deser_main(
    iana_ies: &[InformationElement],
    vendor_prefixes: &[(String, String, u32)],
) -> TokenStream {
    let vendor_errors = vendor_prefixes.iter().map(|(name, pkg, _)| {
        let value_name_ident = Ident::new(&format!("{name}Error"), Span::call_site());
        let pkg_ident = Ident::new(pkg, Span::call_site());
        quote! {
            #value_name_ident(#[from_located(module = "")] #pkg_ident::FieldParsingError)
        }
    });

    let vendor_errors_display = vendor_prefixes.iter().map(|(name, _, _)| {
        let value_name_ident = Ident::new(&format!("{name}Error"), Span::call_site());
        quote! {
            Self::#value_name_ident(err) => write!(f, "{err}")
        }
    });

    let vendor_parsers = vendor_prefixes.iter().map(|(name, _, _)| {
        let ident = Ident::new(name, Span::call_site());
        quote! {
            IE::#ident(value_ie) => {
                let (buf, value) = netgauze_parse_utils::parse_into_located_two_inputs(buf, value_ie, length)?;
                (buf, crate::ie::Field::#ident(value))
            }
        }
    });

    let iana_parsers = iana_ies.iter().map(|ie| {
        let ident = Ident::new(&ie.name, Span::call_site());
        let parser = generate_ie_deserializer(&ie.data_type, &ie.name, ie.subregistry.is_some());
        quote! {
            IE::#ident => {
                #parser
            }
        }
    });

    quote! {
        use nom::{InputLength, InputIter, Slice};
        use chrono::TimeZone;

        #[allow(non_camel_case_types)]
        #[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
        pub enum FieldParsingError {
            #[serde(with = "netgauze_parse_utils::ErrorKindSerdeDeref")]
            NomError(#[from_nom] nom::error::ErrorKind),
            UnknownInformationElement(IE),
            #(#vendor_errors,)*
            InvalidLength{ie_name: String, length: u16},
            InvalidTimestamp{ie_name: String, seconds: u32},
            InvalidTimestampMillis{ie_name: String, millis: u64},
            InvalidTimestampFraction{ie_name: String, seconds: u32, fraction: u32},
            Utf8Error(String),
        }

        impl<'a> nom::error::FromExternalError<netgauze_parse_utils::Span<'a>, std::str::Utf8Error> for LocatedFieldParsingError<'a> {
            fn from_external_error(input: netgauze_parse_utils::Span<'a>, _kind: nom::error::ErrorKind, error: std::str::Utf8Error) -> Self {
                LocatedFieldParsingError::new(input, FieldParsingError::Utf8Error(error.to_string()))
            }
        }

        impl std::fmt::Display for FieldParsingError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                   Self::NomError(err) => write!(f, "Nom error {}", nom::Err::Error(err)),
                   Self::UnknownInformationElement(ie) => write!(f, "unknown information element {ie:?}"),
                    #(#vendor_errors_display,)*
                   Self::InvalidLength{ie_name, length} => write!(f, "error parsing {ie_name} invalid field length {length}"),
                   Self::InvalidTimestamp{ie_name, seconds} => write!(f, "error parsing {ie_name} invalid timestamp {seconds}"),
                   Self::InvalidTimestampMillis{ie_name, millis} => write!(f, "error parsing {ie_name} invalid timestamp {millis}"),
                   Self::InvalidTimestampFraction{ie_name, seconds, fraction} => write!(f, "error parsing {ie_name} invalid timestamp fraction ({seconds}, {fraction})"),
                   Self::Utf8Error(val) => write!(f, "utf8 error {val}"),
                }
            }
        }

        impl std::error::Error for FieldParsingError {}

        impl<'a> netgauze_parse_utils::ReadablePduWithTwoInputs<'a, &IE, u16, LocatedFieldParsingError<'a>>
        for Field {
            #[inline]
            fn from_wire(
                buf: netgauze_parse_utils::Span<'a>,
                ie: &IE,
                length: u16,
            ) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, LocatedFieldParsingError<'a>> {
                let (buf, value) = match ie {
                    #(#vendor_parsers,)*
                    #(#iana_parsers,)*
                    ie => {
                        // todo Handle unknown IEs
                        return Err(nom::Err::Error(LocatedFieldParsingError::new(buf, FieldParsingError::UnknownInformationElement(*ie))))
                    }
                };
                Ok((buf, value))
            }
        }
    }
}

pub(crate) fn generate_ie_ser_main(
    iana_ies: &[InformationElement],
    vendor_prefixes: &[(String, String, u32)],
) -> TokenStream {
    let vendor_errors = vendor_prefixes.iter().map(|(name, pkg, _)| {
        let name = Ident::new(&format!("{name}Error"), Span::call_site());
        let pkg = Ident::new(pkg, Span::call_site());
        quote! { #name(#[from] #pkg::FieldWritingError) }
    });

    let vendor_display_errors = vendor_prefixes.iter().map(|(name, _, _)| {
        let name = Ident::new(&format!("{name}Error"), Span::call_site());
        quote! {  Self::#name(err) => write!(f, "writing error of #pkg: {err}") }
    });

    let vendor_len = vendor_prefixes.iter().map(|(name, _, _)| {
        let name = Ident::new(name, Span::call_site());
        quote! { Self::#name(value) => value.len(length) }
    });

    let vendor_ser = vendor_prefixes.iter().map(|(name, _, _)| {
        let name = Ident::new(name, Span::call_site());
        quote! {
            Self::#name(value) => {
                value.write(writer, length)?
            }
        }
    });

    let iana_ser = iana_ies.iter().map(|ie|{
        let ie_name = ie.name.clone();
        let ident = Ident::new(&ie_name, Span::call_site());
        match ie.data_type.as_str() {
            "octetArray" => {
                quote! {
                    Self::#ident(value) => {
                        writer.write_all(value.as_ref())?
                    }
                }
            }
            "unsigned8" => {
                if ie.subregistry.is_some() {
                    quote! {
                        Self::#ident(value) => {
                            let num_val = u8::from(*value);
                            writer.write_u8(num_val)?
                        }
                    }
                } else {
                    quote! {
                        Self::#ident(value) => {
                            writer.write_u8(*value)?
                        }
                    }
                }
            }
            "unsigned16" => {
                let value = if ie.subregistry.is_some() || ie.name == "tcpControlBits" {
                    quote! { let value = u16::from(*value); }
                } else {
                    quote! { let value = *value; }
                };
                quote! {
                    Self::#ident(value) => {
                        #value
                        match length {
                            None => writer.write_u16::<byteorder::NetworkEndian>(value)?,
                            Some(len) => {
                                let be_bytes = value.to_be_bytes();
                                if usize::from(len) > be_bytes.len() {
                                   return Err(FieldWritingError::InvalidLength{ie_name: #ie_name.to_string(), length: len});
                                }
                                let begin_offset = be_bytes.len() - len as usize;
                                writer.write_all(&be_bytes[begin_offset..])?
                            }
                        }
                    }
                }
            }
            "unsigned32" => {
                let value = if ie.subregistry.is_some() {
                    quote! { let value = u32::from(*value); }
                } else {
                    quote! { let value = *value; }
                };
                quote! {
                    Self::#ident(value) => {
                        #value
                        match length {
                            None => writer.write_u32::<byteorder::NetworkEndian>(value)?,
                            Some(len) => {
                                let be_bytes = value.to_be_bytes();
                                if usize::from(len) > be_bytes.len() {
                                   return Err(FieldWritingError::InvalidLength{ie_name: #ie_name.to_string(), length: len});
                                }
                                let begin_offset = be_bytes.len() - len as usize;
                                writer.write_all(&be_bytes[begin_offset..])?
                            }
                        }
                    }
                }
            }
            "unsigned64" => {
                let value = if ie.subregistry.is_some() {
                    quote! { let value = u64::from(*value); }
                } else {
                    quote! { let value = *value; }
                };
                quote! {
                    Self::#ident(value) => {
                        #value
                        match length {
                            None => writer.write_u64::<byteorder::NetworkEndian>(value)?,
                            Some(len) => {
                                let be_bytes = value.to_be_bytes();
                                if usize::from(len) > be_bytes.len() {
                                   return Err(FieldWritingError::InvalidLength{ie_name: #ie_name.to_string(), length: len});
                                }
                                let begin_offset = be_bytes.len() - len as usize;
                                writer.write_all(&be_bytes[begin_offset..])?
                            }
                        }
                    }
                }
            }
            "signed8" => {
                if ie.subregistry.is_some() {
                    quote! {
                        Self::#ident(value) => {
                            let num_val = i8::from(*value);
                            writer.write_i8(num_val)?
                        }
                    }
                } else {
                    quote! {
                        Self::#ident(value) => {
                            writer.write_i8(*value)?
                        }
                    }
                }
            }
            "signed16" => {
                let value = if ie.subregistry.is_some(){
                    quote! { let value = i16::from(*value); }
                } else {
                    quote! { let value = *value; }
                };
                quote! {
                    Self::#ident(value) => {
                        #value
                        match length {
                            None => writer.write_i16::<byteorder::NetworkEndian>(value)?,
                            Some(len) => {
                                let be_bytes = value.to_be_bytes();
                                if usize::from(len) > be_bytes.len() {
                                   return Err(FieldWritingError::InvalidLength{ie_name: #ie_name.to_string(), length: len});
                                }
                                let begin_offset = be_bytes.len() - len as usize;
                                writer.write_all(&be_bytes[begin_offset..])?
                            }
                        }
                    }
                }
            }
            "signed32" => {
                let value = if ie.subregistry.is_some(){
                    quote! { let value = i32::from(*value); }
                } else {
                    quote! { let value = *value; }
                };
                quote! {
                    Self::#ident(value) => {
                        #value
                        match length {
                            None => writer.write_i32::<byteorder::NetworkEndian>(value)?,
                            Some(len) => {
                                let be_bytes = value.to_be_bytes();
                                if usize::from(len) > be_bytes.len() {
                                   return Err(FieldWritingError::InvalidLength{ie_name: #ie_name.to_string(), length: len});
                                }
                                let begin_offset = be_bytes.len() - len as usize;
                                writer.write_all(&be_bytes[begin_offset..])?
                            }
                        }
                    }
                }
            }
            "signed64" => {
                let value = if ie.subregistry.is_some(){
                    quote! { let value = i64::from(*value); }
                } else {
                    quote! { let value = *value; }
                };
                quote! {
                    Self::#ident(value) => {
                        #value
                        match length {
                            None => writer.write_i32::<byteorder::NetworkEndian>(value)?,
                            Some(len) => {
                                let be_bytes = value.to_be_bytes();
                                if usize::from(len) > be_bytes.len() {
                                   return Err(FieldWritingError::InvalidLength{ie_name: #ie_name.to_string(), length: len});
                                }
                                let begin_offset = be_bytes.len() - len as usize;
                                writer.write_all(&be_bytes[begin_offset..])?
                            }
                        }
                    }
                }
            }
            "float32" => {
                quote! {
                    Self::#ident(value) => {
                        let value = f32::from(*value);
                        match length {
                            None => writer.write_f32::<byteorder::NetworkEndian>(value)?,
                            Some(len) => {
                                let be_bytes = value.to_be_bytes();
                                if usize::from(len) > be_bytes.len() {
                                   return Err(FieldWritingError::InvalidLength{ie_name: #ie_name.to_string(), length: len});
                                }
                                let begin_offset = be_bytes.len() - len as usize;
                                writer.write_all(&be_bytes[begin_offset..])?
                            }
                        }
                    }
                }
            }
            "float64" => {
                quote! {
                    Self::#ident(value) => {
                        let value = f64::from(*value);
                        match length {
                            None => writer.write_f64::<byteorder::NetworkEndian>(value)?,
                            Some(len) => {
                                let be_bytes = value.to_be_bytes();
                                if usize::from(len) > be_bytes.len() {
                                   return Err(FieldWritingError::InvalidLength{ie_name: #ie_name.to_string(), length: len});
                                }
                                let begin_offset = be_bytes.len() - len as usize;
                                writer.write_all(&be_bytes[begin_offset..])?
                            }
                        }
                    }
                }
            }
            "boolean" => {
                quote! {
                    Self::#ident(value) => {
                        writer.write_u8(*value as u8)?
                    }
                }
            }
            "macAddress" => {
                quote! {
                    Self::#ident(value) => {
                        writer.write_all(value)?
                    }
                }
            }
            "string" => {
                quote! {
                    Self::#ident(value) => {
                        match length {
                            Some(u16::MAX) | None => {
                                let bytes = value.as_bytes();
                                if bytes.len() < u8::MAX as usize {
                                    writer.write_u8(bytes.len() as u8)?;
                                } else {
                                    writer.write_u8(u8::MAX)?;
                                    writer.write_all(&bytes.len().to_be_bytes()[1..])?;
                                }
                                writer.write_all(value.as_bytes())?;
                            }
                            Some(len) => {
                                writer.write_all(value.as_bytes())?;
                                // fill the rest with zeros
                                for _ in value.len()..(len as usize) {
                                    writer.write_u8(0)?
                                }
                            }
                        }
                    }
                }
            }
            "dateTimeSeconds" => {
                quote! {
                    Self::#ident(value) => {
                        writer.write_u32::<byteorder::NetworkEndian>(value.timestamp() as u32)?
                    }
                }
            }
            "dateTimeMilliseconds" => {
                quote! {
                    Self::#ident(value) => {
                        writer.write_u64::<byteorder::NetworkEndian>(value.timestamp_millis() as u64)?;
                    }
                }
            }
            "dateTimeMicroseconds" | "dateTimeNanoseconds" => {
                quote! {
                    Self::#ident(value) => {
                        writer.write_u32::<byteorder::NetworkEndian>(value.timestamp() as u32)?;
                        let nanos = value.timestamp_subsec_nanos();
                        // Convert 1/2**32 of a second to a fraction of a nano second
                        let fraction = (nanos as u64 * u32::MAX as u64) / 1_000_000_000;
                        writer.write_u32::<byteorder::NetworkEndian>(fraction as u32)?;
                    }
                }
            }
            "ipv4Address" => {
                quote! {
                    Self::#ident(value) => {
                        writer.write_all(&value.octets())?
                    }
                }
            }
            "ipv6Address" => {
                quote! {
                    Self::#ident(value) => {
                        writer.write_all(&value.octets())?
                    }
                }
            }
            "basicList" => {
                quote! {
                    Self::#ident(value) => {
                        writer.write_all(value)?
                    }
                }
            }
            "subTemplateList" => {
                quote! {
                    Self::#ident(value) => {
                        writer.write_all(value)?
                    }
                }
            }
            "subTemplateMultiList" => {
                quote! {
                    Self::#ident(value) => {
                        writer.write_all(value)?
                    }
                }
            }
            "unsigned256" => {
                quote! {
                    Self::#ident(value) => {
                        let len = match length {
                            None => value.len(),
                            Some(len) => len as usize,
                        };
                        writer.write_all(value[..len].as_ref())?
                    }
                }
            }
            ty => todo!("Unsupported serialization for type: {}", ty),
        }
    });

    let iana_len = iana_ies.iter().map(|ie| {
        let name = Ident::new(&ie.name, Span::call_site());
        match ie.data_type.as_str() {
            "octetArray"
            | "macAddress"
            | "basicList"
            | "subTemplateList"
            | "subTemplateMultiList" => {
                quote! {
                    Self::#name(value) => {
                        value.len()
                    }
                }
            }
            "unsigned8" | "signed8" | "boolean" => {
                quote! {
                    Self::#name(_value) => {
                        1
                    }
                }
            }
            "unsigned16" | "signed16" => {
                quote! {
                    Self::#name(_value) => {
                        match length {
                            None => 2,
                            Some(len) => len as usize
                        }
                    }
                }
            }
            "unsigned32" | "signed32" | "float32" => {
                quote! {
                    Self::#name(_value) => {
                        match length {
                            None => 4,
                            Some(len) => len as usize
                        }
                    }
                }
            }
            "unsigned64" | "signed64" | "float64" => {
                quote! {
                    Self::#name(_value) => {
                        match length {
                            None => 8,
                            Some(len) => len as usize
                        }
                    }
                }
            }
            "string" => {
                quote! {
                    Self::#name(value) => {
                        match length {
                            None => value.len(),
                            Some(len) => if len == u16::MAX {
                                if value.len() < u8::MAX as usize {
                                    // One octet for the length field
                                    value.len() + 1
                                } else {
                                    // 4 octets for the length field, first is 255 and other three carries the len
                                    value.len() + 4
                                }
                            } else {
                                len as usize
                            }
                        }
                    }
                }
            }
            "dateTimeSeconds" | "ipv4Address" => {
                quote! {
                    Self::#name(_value) => {
                        4
                    }
                }
            }
            "dateTimeMilliseconds" | "dateTimeMicroseconds" | "dateTimeNanoseconds" => {
                quote! {
                    Self::#name(_value) => {
                        8
                    }
                }
            }
            "ipv6Address" => {
                quote! {
                    Self::#name(_value) => {
                        16
                    }
                }
            }
            "unsigned256" => {
                quote! {
                    Self::#name(value) => {
                        match length {
                            None => value.len(),
                            Some(len) => len as usize
                        }
                    }
                }
            }
            ty => todo!("Unsupported serialization for type: {}", ty),
        }
    });

    quote! {
        use byteorder::WriteBytesExt;

        #[allow(non_camel_case_types)]
        #[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
        pub enum FieldWritingError {
            StdIOError(#[from_std_io_error] String),
            #(#vendor_errors,)*
            InvalidLength{ie_name: String, length: u16},
        }

        impl std::fmt::Display for FieldWritingError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    Self::StdIOError(err) => write!(f, "{err}"),
                    #(#vendor_display_errors,)*
                    Self::InvalidLength{ie_name, length} => write!(f, "writing error of {ie_name} invalid length {length}"),
                }
            }
        }

        impl std::error::Error for FieldWritingError {}

        impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, FieldWritingError> for Field {
            const BASE_LENGTH: usize = 0;
            fn len(&self, length: Option<u16>) -> usize {
                match self {
                    Self::Unknown{pen: _pen, id: _id, value} => value.len(),
                    #(#vendor_len,)*
                    #(#iana_len,)*
                }
            }

            fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), FieldWritingError> {
                match self {
                    Self::Unknown{pen: _pen, id: _id, value} => writer.write_all(value)?,
                    #(#vendor_ser)*
                    #(#iana_ser)*
                }
                Ok(())
            }
        }
    }
}

pub fn format_tokens(token_stream: TokenStream) -> String {
    // Convert to string
    let code = token_stream.to_string();
    // Parse as a syn::File and format
    match syn::parse_file(&code) {
        Ok(file) => prettyplease::unparse(&file),
        Err(e) => {
            // Handle parsing error
            eprintln!("Error parsing generated code: {e}");
            eprintln!("Generated code was: {code}");
            code // Return unformatted code as fallback
        }
    }
}
