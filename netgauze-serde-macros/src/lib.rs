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

extern crate proc_macro;

use quote::{format_ident, quote, TokenStreamExt};
use syn::spanned::Spanned;

#[derive(Debug)]
struct AttributeNameValue {
    ident: syn::Ident,
    value: String,
}

struct Attribute {
    value: Vec<AttributeNameValue>,
}

fn parse_nested_meta(
    span: proc_macro2::Span,
    nested_meta: syn::NestedMeta,
) -> Result<AttributeNameValue, syn::Error> {
    let meta = match nested_meta {
        syn::NestedMeta::Meta(meta) => meta,
        syn::NestedMeta::Lit(lit) => {
            return Err(syn::Error::new(lit.span(), "Unsupported literal attribute"))
        }
    };

    let named_value = match meta {
        syn::Meta::Path(ref path) => {
            return Err(syn::Error::new(
                path.segments[0].ident.span(),
                "Path attribute is not supported!",
            ));
        }
        syn::Meta::List(ref lst) => {
            return Err(syn::Error::new(
                lst.path.segments[0].ident.span(),
                "List attribute is not supported!",
            ));
        }
        syn::Meta::NameValue(name_value) => name_value,
    };

    let ident: syn::Ident = match named_value.path.get_ident() {
        Some(ident) => ident.clone(),
        None => return Err(syn::Error::new(span, "Expected ident")),
    };
    let lit = named_value.lit;
    let value = match lit {
        syn::Lit::Str(str) => str.value(),
        _ => return Err(syn::Error::new(span, "Unsupported value type")),
    };

    Ok(AttributeNameValue { ident, value })
}

fn parse_attribute(
    span: proc_macro2::Span,
    attr: &syn::Attribute,
) -> Result<Option<Attribute>, syn::Error> {
    let meta = attr.parse_meta()?;
    match meta {
        syn::Meta::Path(_) => Ok(Some(Attribute { value: vec![] })),
        syn::Meta::NameValue(_) => Err(syn::Error::new(
            span,
            "Cannot parse syn::Meta::NameValue at",
        )),
        syn::Meta::List(lst) => {
            let mut attrs = vec![];
            for nested in lst.nested {
                let x = parse_nested_meta(span, nested)?;
                attrs.push(x);
            }
            Ok(Some(Attribute { value: attrs }))
        }
    }
}

#[derive(Debug)]
struct LocatedError {}

impl LocatedError {
    fn get_from_nom(enum_data: &syn::DataEnum) -> syn::Result<Vec<syn::Ident>> {
        let mut from_nom_variants = vec![];
        for variant in enum_data.variants.iter() {
            for field in variant.fields.iter() {
                for _ in field.attrs.iter().filter(|attr| {
                    attr.path
                        .segments
                        .iter()
                        .any(|seg| seg.ident == syn::Ident::new("from_nom", seg.span()))
                }) {
                    if let syn::Type::Path(_) = &field.ty {
                        from_nom_variants.push(variant.ident.clone());
                    }
                }
            }
        }
        Ok(from_nom_variants)
    }

    fn get_from_external(
        enum_data: &syn::DataEnum,
    ) -> syn::Result<(Vec<syn::Ident>, Vec<syn::Ident>)> {
        let mut from_external_variants = vec![];
        let mut from_external_ident = vec![];
        for variant in enum_data.variants.iter() {
            for field in variant.fields.iter() {
                for attr in field.attrs.iter().filter(|attr| {
                    attr.path
                        .segments
                        .iter()
                        .any(|seg| seg.ident == syn::Ident::new("from_external", seg.span()))
                }) {
                    if let syn::Type::Path(path) = &field.ty {
                        from_external_variants.push(variant.ident.clone());
                        let ident = path.path.get_ident();
                        match ident {
                            Some(ident) => from_external_ident.push(ident.clone()),
                            None => {
                                return Err(syn::Error::new(
                                    attr.span(),
                                    "Couldn't find identifier for this attribute",
                                ))
                            }
                        }
                    }
                }
            }
        }
        Ok((from_external_variants, from_external_ident))
    }

    fn get_from_located(
        enum_data: &syn::DataEnum,
    ) -> syn::Result<Vec<(syn::Ident, syn::Ident, Vec<syn::Ident>)>> {
        let mut ret = vec![];
        for variant in enum_data.variants.iter() {
            for field in variant.fields.iter() {
                for attr in field.attrs.iter().filter(|attr| {
                    attr.path
                        .segments
                        .iter()
                        .any(|seg| seg.ident == syn::Ident::new("from_located", seg.span()))
                }) {
                    if let syn::Type::Path(path) = &field.ty {
                        let located_variants = variant.ident.clone();
                        let ident = path.path.get_ident();
                        let located_ident = match ident {
                            Some(ident) => format_ident!("Located{}", ident.clone()),
                            None => {
                                return Err(syn::Error::new(
                                    attr.span(),
                                    "Couldn't find identifier for this attribute",
                                ))
                            }
                        };

                        let located_module = match parse_attribute(variant.ident.span(), attr)? {
                            None => {
                                return Err(syn::Error::new(
                                    attr.span(),
                                    "'module' must be defined",
                                ))
                            }
                            Some(parsed_attr) => {
                                match parsed_attr.value.get(0) {
                                    None => {
                                        return Err(syn::Error::new(
                                            attr.span(),
                                            "'module' of the Located error is not defined defined",
                                        ))
                                    }
                                    Some(name_value) => {
                                        if name_value.ident != format_ident!("module") {
                                            return Err(syn::Error::new(
                                                    attr.span(),
                                                    format!("Only accepts one attribute 'module', found {:?}", name_value.ident),
                                                ));
                                        }
                                        name_value
                                            .value
                                            .split("::")
                                            .map(|part| format_ident!("{}", part))
                                            .collect()
                                    }
                                }
                            }
                        };
                        ret.push((located_variants, located_ident, located_module))
                    }
                }
            }
        }
        Ok(ret)
    }

    fn from(input: &syn::DeriveInput) -> Result<proc_macro::TokenStream, syn::Error> {
        let en = match &input.data {
            syn::Data::Enum(en) => en,
            _ => {
                return Err(syn::Error::new(
                    input.span(),
                    "Works only with enum error types",
                ))
            }
        };
        let ident = input.ident.clone();
        let located_struct_name: syn::Ident = format_ident!("Located{}", ident);

        let from_nom_variants = LocatedError::get_from_nom(en)?;
        let (from_external_variants, from_external_ident) = LocatedError::get_from_external(en)?;
        let from_located = LocatedError::get_from_located(en)?;

        let mut output = quote! {
            #[derive(Eq, PartialEq, Clone, Debug)]
            #[automatically_derived]
            pub struct #located_struct_name<'a> {
                span: netgauze_parse_utils::Span<'a>,
                error: #ident,
            }

            #[automatically_derived]
            impl<'a> #located_struct_name<'a> {
                pub const fn new(span: netgauze_parse_utils::Span<'a>, error: #ident) -> Self {
                    Self { span, error }
                }
            }

            #[automatically_derived]
            impl<'a> From<#located_struct_name<'a>> for (netgauze_parse_utils::Span<'a>, #ident) {
                fn from(input: #located_struct_name<'a>) -> Self {
                    (input.span, input.error)
                }
            }

            #[automatically_derived]
            impl<'a> netgauze_parse_utils::LocatedParsingError for #located_struct_name<'a> {
                type Span = netgauze_parse_utils::Span<'a>;
                type Error = #ident;

                fn span(&self) -> &Self::Span {
                    &self.span
                }

                fn error(&self) -> &Self::Error {
                    &self.error
                }
            }

            #[automatically_derived]
            impl<'a> nom::error::FromExternalError<netgauze_parse_utils::Span<'a>, #ident> for #located_struct_name<'a> {
                fn from_external_error(input: netgauze_parse_utils::Span<'a>, _kind: nom::error::ErrorKind, error:  #ident) -> Self {
                    #located_struct_name::new(input, error)
                }
            }

            #(
                #[automatically_derived]
                impl<'a> nom::error::FromExternalError<netgauze_parse_utils::Span<'a>, #from_external_ident> for #located_struct_name<'a> {
                    fn from_external_error(input: netgauze_parse_utils::Span<'a>, _kind: nom::error::ErrorKind, error:  #from_external_ident) -> Self {
                        #located_struct_name::new(input, #ident::#from_external_variants(error))
                    }
                }
            )*

            #(
                #[automatically_derived]
                impl<'a> nom::error::ParseError<netgauze_parse_utils::Span<'a>> for #located_struct_name<'a> {
                    fn from_error_kind(input: netgauze_parse_utils::Span<'a>, kind: nom::error::ErrorKind) -> Self {
                        #located_struct_name::new(input, #ident::#from_nom_variants(kind))
                    }

                    fn append(_input: netgauze_parse_utils::Span<'a>, _kind: nom::error::ErrorKind, other: Self) -> Self {
                        other
                    }
                }
            )*
        };

        for (located_variant, located_ident, located_module) in from_located.iter() {
            let tmp = quote! {
                #[automatically_derived]
                impl<'a> From<#(#located_module)::*::#located_ident<'a>> for #located_struct_name<'a> {
                    fn from(input: #(#located_module)::*::#located_ident<'a>) -> Self {
                        let (span, error) = input.into();
                        #located_struct_name::new(span, #ident::#located_variant(error))
                    }
                }
            };
            output.append_all(tmp);
        }
        Ok(proc_macro::TokenStream::from(output))
    }
}

#[proc_macro_derive(LocatedError, attributes(from_nom, from_external, from_located))]
pub fn located_error(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ast = syn::parse_macro_input!(input as syn::DeriveInput);
    match LocatedError::from(&ast) {
        Ok(tokens) => tokens,
        Err(err) => proc_macro::TokenStream::from(err.to_compile_error()),
    }
}
