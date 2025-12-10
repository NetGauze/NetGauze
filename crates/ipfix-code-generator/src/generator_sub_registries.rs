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

use crate::{
    InformationElementSubRegistry, generator::generate_xref_link,
    xml_parsers::sub_registries::SubRegistry,
};
use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;

/// Generate code (enum and implementations) for IE Subregistries
pub fn generate_subregistry_enum_and_impl(
    ie_name: &String,
    rust_type: &String,
    ie_subregistry: &[InformationElementSubRegistry],
) -> TokenStream {
    let mut tokens = TokenStream::new();
    tokens.extend(generate_enum(ie_name, rust_type, ie_subregistry));
    tokens.extend(generate_from_impl_for_rust_type(
        ie_name,
        rust_type,
        ie_subregistry,
    ));
    tokens.extend(generate_from_impl_for_enum_type(
        ie_name,
        rust_type,
        ie_subregistry,
    ));

    // Add structs and type converters for reason-code registries
    for rec in ie_subregistry {
        if let InformationElementSubRegistry::ReasonCodeNestedRegistry(rec) = rec {
            let enum_name = format!("{}{}Reason", ie_name, rec.name);
            let derive = if rust_type != "Vec<u8>" && rust_type != "String" {
                quote! { #[derive(strum_macros::Display, Copy, Eq, Hash, PartialOrd, Ord, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)] }
            } else {
                quote! { #[derive(strum_macros::Display, Eq, Hash, PartialOrd, Ord, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)] }
            };
            let header = quote! {
                #[allow(non_camel_case_types)]
                #derive
            };
            tokens.extend(header);
            tokens.extend(generate_enum(&enum_name, rust_type, &rec.reason_code_reg));
            tokens.extend(generate_from_impl_for_rust_type(
                &enum_name,
                rust_type,
                &rec.reason_code_reg,
            ));
            tokens.extend(generate_from_impl_for_enum_type(
                &enum_name,
                rust_type,
                &rec.reason_code_reg,
            ));
        }
    }
    tokens
}

/// Generate Description and Ref for a given Subregistry
pub fn generate_desc_and_refs_common(rec: &dyn SubRegistry) -> TokenStream {
    let mut doc_comments = Vec::new();
    for line in SubRegistry::description(rec).lines() {
        let line = format!(" {}", line.trim());
        doc_comments.push(quote! { #[doc = #line] });
    }
    if !SubRegistry::description(rec).is_empty() && !SubRegistry::xrefs(rec).is_empty() {
        let empty = "";
        doc_comments.push(quote! { #[doc = #empty] });
    }
    for xref in SubRegistry::xrefs(rec)
        .iter()
        .filter_map(generate_xref_link)
    {
        let ref_link = format!(" Reference: {xref}");
        doc_comments.push(quote! { #[doc = #ref_link] });
    }
    quote! {
        #(#doc_comments)*
    }
}

/// Generate Enum Type for Subregistry
pub fn generate_enum(
    enum_name: &str,
    rust_type: &str,
    registry: &[InformationElementSubRegistry],
) -> TokenStream {
    let ty = syn::parse_str::<syn::Type>(rust_type).unwrap();
    let unit_type = registry
        .iter()
        .any(|x| matches!(x, InformationElementSubRegistry::ValueNameDescRegistry(_)));
    let unit_type = if unit_type {
        quote! { #[repr(#ty)] }
    } else {
        quote! {}
    };
    let variants = registry.iter().map(|rec| match rec {
        InformationElementSubRegistry::ValueNameDescRegistry(rec) => {
            let doc = generate_desc_and_refs_common(rec);
            let display_name = &rec.display_name;
            let name = Ident::new(&rec.name, Span::call_site());
            let value = get_quote_value(rust_type, rec.value);
            quote! {
                #doc
                #[strum(to_string = #display_name)]
                #name = #value
            }
        }
        InformationElementSubRegistry::ReasonCodeNestedRegistry(rec) => {
            let doc = generate_desc_and_refs_common(rec);
            let display_name = format!("{} {{0}}", &rec.display_name);
            let name = Ident::new(&rec.name, Span::call_site());
            let reason = Ident::new(&format!("{enum_name}{}Reason", rec.name), Span::call_site());
            quote! {
                #doc
                #[strum(to_string = #display_name)]
                #name(#reason)
            }
        }
    });
    let enum_name_ident = Ident::new(enum_name, Span::call_site());
    quote! {
        #unit_type
        #[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
        pub enum #enum_name_ident {
            #(#variants,)*
            Unassigned(#ty)
        }
    }
}

fn get_quote_value(rust_type: &str, value: u8) -> TokenStream {
    match rust_type {
        "u8" => {
            let v = value;
            quote! { #v }
        }
        "u16" => {
            let v = value as u16;
            quote! { #v }
        }
        "u32" => {
            let v = value as u32;
            quote! { #v }
        }
        "u64" => {
            let v = value as u64;
            quote! { #v }
        }
        "i8" => {
            let v = value as i8;
            quote! { #v }
        }
        "i16" => {
            let v = value as i16;
            quote! { #v }
        }
        "i32" => {
            let v = value as i32;
            quote! { #v }
        }
        "i64" => {
            let v = value as i64;
            quote! { #v }
        }
        _ => panic!("Not supported"),
    }
}

/// Generate From trait implementation from subregistry to rust_type
pub fn generate_from_impl_for_rust_type(
    enum_name: &str,
    rust_type: &str,
    registry: &[InformationElementSubRegistry],
) -> TokenStream {
    let enum_name = Ident::new(enum_name, Span::call_site());
    let ty = syn::parse_str::<syn::Type>(rust_type).unwrap();
    let recs = registry.iter().map(|rec| match rec {
        InformationElementSubRegistry::ValueNameDescRegistry(rec) => {
            let value = get_quote_value(rust_type, rec.value);
            let rec = Ident::new(&rec.name, Span::call_site());
            quote! { #enum_name::#rec => #value}
        }
        InformationElementSubRegistry::ReasonCodeNestedRegistry(rec) => {
            let rec = Ident::new(&rec.name, Span::call_site());
            quote! { #enum_name::#rec(x) => #ty::from(x)}
        }
    });

    quote! {
        impl From<#enum_name> for #ty {
            fn from(value: #enum_name) -> Self {
                match value {
                    #(#recs,)*
                    #enum_name::Unassigned(x) => x,
                }
            }
        }
    }
}

/// Generate From trait implementation from rust_type to subregistry
pub fn generate_from_impl_for_enum_type(
    enum_name: &str,
    rust_type: &str,
    registry: &[InformationElementSubRegistry],
) -> TokenStream {
    let ty = syn::parse_str::<syn::Type>(rust_type).unwrap();
    let enum_name = Ident::new(enum_name, Span::call_site());
    let inner = if registry.is_empty() {
        quote! {
            let x = value;
            #enum_name::Unassigned(x)
        }
    } else if matches!(
        registry.first(),
        Some(InformationElementSubRegistry::ValueNameDescRegistry(_))
    ) {
        let variants = registry
            .iter()
            .filter_map(|x| match x {
                InformationElementSubRegistry::ValueNameDescRegistry(rec) => Some(rec),
                _ => None,
            })
            .map(|rec| {
                let value = get_quote_value(rust_type, rec.value);
                let name = Ident::new(&rec.name, Span::call_site());
                quote! { #value => #enum_name::#name }
            });
        quote! {
            match value {
                #(#variants,)*
                x => #enum_name::Unassigned(x)
            }
        }
    } else if matches!(
        registry.first(),
        Some(InformationElementSubRegistry::ReasonCodeNestedRegistry(_))
    ) {
        let variants = registry
            .iter()
            .filter_map(|x| match x {
                InformationElementSubRegistry::ReasonCodeNestedRegistry(rec) => Some(rec),
                _ => None,
            })
            .enumerate()
            .map(|(idx, rec)| {
                let start = 64 * idx;
                let end = 64 * (idx + 1) - 1;
                let start = syn::Lit::Int(syn::LitInt::new(&format!("{start}"), Span::call_site()));
                let end = syn::Lit::Int(syn::LitInt::new(&format!("{end}"), Span::call_site()));
                let name = Ident::new(&rec.name, Span::call_site());
                let reason =
                    Ident::new(&format!("{enum_name}{}Reason", rec.name), Span::call_site());
                quote! { (#start..=#end) => #enum_name::#name(#reason::from(value)) }
            });
        quote! {
            match value {
                #(#variants,)*
                x => #enum_name::Unassigned(x)
            }
        }
    } else {
        panic!("Not supported");
    };
    let code = quote! {
        impl From<#ty> for #enum_name {
            fn from(value: #ty) -> Self {
                #inner
            }
        }

        impl std::ops::BitOr<#enum_name> for #enum_name {
            type Output = #enum_name;
            fn bitor(self, rhs: #enum_name) -> Self::Output {
                let a: #ty = self.into();
                let b: #ty = rhs.into();
                Self::from(a | b)
            }
        }

        impl std::ops::BitOrAssign<#enum_name> for #enum_name {
            fn bitor_assign(&mut self, rhs: #enum_name) {
                let a: #ty = (*self).into();
                let b: #ty = rhs.into();
                *self = Self::from(a | b)
            }
        }
    };
    code
}
