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

use std::fmt;

pub mod parser;

/// Positive or negative integer value
#[derive(pest_ast::FromPest)]
#[pest_ast(rule(parser::Rule::integer_value))]
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct IntegerValue<'a> {
    #[pest_ast(outer())]
    pub span: pest::Span<'a>,
}

/// Value statement for positive or negative integer value
#[derive(pest_ast::FromPest)]
#[pest_ast(rule(parser::Rule::value_stmt))]
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ValueStmt<'a> {
    #[pest_ast(outer())]
    pub span: pest::Span<'a>,
    value: IntegerValue<'a>,
}

/// YANG version (1.0 or 1.1)
#[derive(Debug, Eq, PartialEq, Copy, Clone, Hash)]
pub enum YangVersion {
    V1_0,
    V1_1,
}

#[derive(pest_ast::FromPest)]
#[pest_ast(rule(parser::Rule::yang_version_stmt))]
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct YangVersionStmt<'a> {
    #[pest_ast(outer())]
    pub span: pest::Span<'a>,

    #[pest_ast(inner(
        rule(parser::Rule::yang_version_arg),
        with(str_from_span),
        with(parse_yang_version),
        with(Result::unwrap)
    ))]
    pub version: YangVersion,
}

fn parse_yang_version(s: &str) -> Result<YangVersion, ParseError> {
    match s {
        "1.1" => Ok(YangVersion::V1_1),
        "1.0" => Ok(YangVersion::V1_0),
        _ => Err(ParseError::InvalidValue {
            field: "yang-version",
            value: s.to_string(),
        }),
    }
}

#[derive(pest_ast::FromPest)]
#[pest_ast(rule(parser::Rule::prefix_stmt))]
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct PrefixStmt<'a> {
    #[pest_ast(outer())]
    pub span: pest::Span<'a>,

    #[pest_ast(inner(rule(parser::Rule::prefix), with(str_from_span)))]
    pub prefix: &'a str,
}

#[derive(pest_ast::FromPest)]
#[pest_ast(rule(parser::Rule::description_stmt))]
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct DescriptionStmt<'a> {
    #[pest_ast(outer())]
    pub span: pest::Span<'a>,
    pub value: YangString<'a>,
}

#[derive(pest_ast::FromPest)]
#[pest_ast(rule(parser::Rule::reference_stmt))]
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ReferenceStmt<'a> {
    #[pest_ast(outer())]
    pub span: pest::Span<'a>,
    pub value: YangString<'a>,
}

#[derive(pest_ast::FromPest)]
#[pest_ast(rule(parser::Rule::organization_stmt))]
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct OrganizationStmt<'a> {
    #[pest_ast(outer())]
    pub span: pest::Span<'a>,
    pub value: YangString<'a>,
}

#[derive(pest_ast::FromPest)]
#[pest_ast(rule(parser::Rule::contact_stmt))]
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ContactStmt<'a> {
    #[pest_ast(outer())]
    pub span: pest::Span<'a>,
    pub value: YangString<'a>,
}

/// Double-quoted string with escape sequences
#[derive(pest_ast::FromPest)]
#[pest_ast(rule(parser::Rule::dstring_inner))]
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct DStringInner<'a> {
    #[pest_ast(outer())]
    pub span: pest::Span<'a>,
}

/// List of DStringInner with plus sign separator
#[derive(pest_ast::FromPest)]
#[pest_ast(rule(parser::Rule::dstring))]
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct DString<'a> {
    #[pest_ast(outer())]
    pub span: pest::Span<'a>,
    pub inner: Vec<DStringInner<'a>>,
}

/// Single-quoted string with escape sequences
#[derive(pest_ast::FromPest)]
#[pest_ast(rule(parser::Rule::sstring_inner))]
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct SStringInner<'a> {
    #[pest_ast(outer())]
    pub span: pest::Span<'a>,
}

/// List of SStringInner with plus sign separator
#[derive(pest_ast::FromPest)]
#[pest_ast(rule(parser::Rule::sstring))]
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct SString<'a> {
    #[pest_ast(outer())]
    pub span: pest::Span<'a>,
    pub inner: Vec<SStringInner<'a>>,
}

/// Unquoted string
#[derive(pest_ast::FromPest)]
#[pest_ast(rule(parser::Rule::unquoted))]
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Unquoted<'a> {
    #[pest_ast(outer())]
    pub span: pest::Span<'a>,
}

#[derive(pest_ast::FromPest)]
#[pest_ast(rule(parser::Rule::string))]
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum YangString<'a> {
    DoubleQuoted(DString<'a>),
    SingleQuoted(SString<'a>),
    Unquoted(Unquoted<'a>),
}

#[derive(pest_ast::FromPest)]
#[pest_ast(rule(parser::Rule::identifier))]
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Identifier<'a> {
    #[pest_ast(outer())]
    pub span: pest::Span<'a>,
}

#[derive(pest_ast::FromPest)]
#[pest_ast(rule(parser::Rule::namespace_stmt))]
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct NamespaceStmt<'a> {
    #[pest_ast(outer())]
    pub span: pest::Span<'a>,
    pub ns: YangString<'a>,
}

#[derive(pest_ast::FromPest)]
#[pest_ast(rule(parser::Rule::revision_stmt))]
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct RevisionStmt<'a> {
    #[pest_ast(outer())]
    pub span: pest::Span<'a>,
    #[pest_ast(inner(
        rule(parser::Rule::date_arg),
        with(str_from_span),
        with(parse_date),
        with(Result::unwrap)
    ))]
    pub date: chrono::NaiveDate,
    pub description: Option<DescriptionStmt<'a>>,
    pub reference: Option<ReferenceStmt<'a>>,
}

/// Status of a YANG statement
#[derive(Debug, Eq, PartialEq, Copy, Clone, Hash)]
pub enum Status {
    Current,
    Deprecated,
    Obsolete,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, Hash)]
pub struct StatusStmt<'a> {
    span: pest::Span<'a>,
    status: Status,
}

impl<'a> from_pest::FromPest<'a> for StatusStmt<'a> {
    type Rule = parser::Rule;
    type FatalError = ParseError;
    fn from_pest(
        pest: &mut pest::iterators::Pairs<'a, parser::Rule>,
    ) -> Result<Self, from_pest::ConversionError<Self::FatalError>> {
        let mut clone = pest.clone();
        let pair = clone.next().ok_or(from_pest::ConversionError::NoMatch)?;
        if pair.as_rule() != parser::Rule::status_stmt {
            return Err(from_pest::ConversionError::NoMatch);
        }
        let span = pair.as_span();
        let mut inner = pair.into_inner();
        let inner = &mut inner;
        let status_value = inner.next().ok_or(from_pest::ConversionError::NoMatch)?;
        let status = match status_value.as_rule() {
            parser::Rule::current_keyword => Status::Current,
            parser::Rule::deprecated_keyword => Status::Deprecated,
            parser::Rule::obsolete_keyword => Status::Obsolete,
            _ => return Err(from_pest::ConversionError::NoMatch),
        };
        let this = StatusStmt { span, status };
        if inner.clone().next().is_some() {
            from_pest::log::trace!(
                "when converting {}, found extraneous {:?}",
                stringify!(StatusStmt),
                inner
            );
            Err(from_pest::ConversionError::Extraneous {
                current_node: stringify!(StatusStmt),
            })?;
        }
        *pest = clone;
        Ok(this)
    }
}

/// Config property (true/false)
#[derive(Debug, Eq, PartialEq, Copy, Clone, Hash)]
pub struct ConfigStmt<'a> {
    span: pest::Span<'a>,
    is_config: bool,
}

impl<'a> from_pest::FromPest<'a> for ConfigStmt<'a> {
    type Rule = parser::Rule;
    type FatalError = from_pest::Void;
    fn from_pest(
        pest: &mut pest::iterators::Pairs<'a, parser::Rule>,
    ) -> Result<Self, from_pest::ConversionError<Self::FatalError>> {
        let mut clone = pest.clone();
        let pair = clone.next().ok_or(from_pest::ConversionError::NoMatch)?;
        if pair.as_rule() != parser::Rule::config_stmt {
            return Err(from_pest::ConversionError::NoMatch);
        }
        let span = pair.as_span();
        let mut inner = pair.into_inner();
        let inner = &mut inner;
        let config_arg = inner.next().ok_or(from_pest::ConversionError::NoMatch)?;
        if config_arg.as_rule() != parser::Rule::config_arg {
            return Err(from_pest::ConversionError::NoMatch);
        }
        let true_false_keyword = config_arg
            .into_inner()
            .next()
            .ok_or(from_pest::ConversionError::NoMatch)?;
        let is_config = match true_false_keyword.as_rule() {
            parser::Rule::true_keyword => true,
            parser::Rule::false_keyword => false,
            _ => return Err(from_pest::ConversionError::NoMatch),
        };
        let this = ConfigStmt { span, is_config };
        if inner.clone().next().is_some() {
            from_pest::log::trace!(
                "when converting {}, found extraneous {:?}",
                stringify!(ConfigStmt),
                inner
            );
            Err(from_pest::ConversionError::Extraneous {
                current_node: stringify!(ConfigStmt),
            })?;
        }
        *pest = clone;
        Ok(this)
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, Hash)]
pub struct MandatoryStmt<'a> {
    span: pest::Span<'a>,
    is_mandatory: bool,
}

impl<'a> from_pest::FromPest<'a> for MandatoryStmt<'a> {
    type Rule = parser::Rule;
    type FatalError = from_pest::Void;
    fn from_pest(
        pest: &mut pest::iterators::Pairs<'a, parser::Rule>,
    ) -> Result<Self, from_pest::ConversionError<Self::FatalError>> {
        let mut clone = pest.clone();
        let pair = clone.next().ok_or(from_pest::ConversionError::NoMatch)?;
        if pair.as_rule() != parser::Rule::mandatory_stmt {
            return Err(from_pest::ConversionError::NoMatch);
        }
        let span = pair.as_span();
        let mut inner = pair.into_inner();
        let inner = &mut inner;
        let mandatory_arg = inner.next().ok_or(from_pest::ConversionError::NoMatch)?;
        if mandatory_arg.as_rule() != parser::Rule::mandatory_arg {
            return Err(from_pest::ConversionError::NoMatch);
        }
        let true_false_keyword = mandatory_arg
            .into_inner()
            .next()
            .ok_or(from_pest::ConversionError::NoMatch)?;
        let is_mandatory = match true_false_keyword.as_rule() {
            parser::Rule::true_keyword => true,
            parser::Rule::false_keyword => false,
            _ => return Err(from_pest::ConversionError::NoMatch),
        };
        let this = MandatoryStmt { span, is_mandatory };
        if inner.clone().next().is_some() {
            from_pest::log::trace!(
                "when converting {}, found extraneous {:?}",
                stringify!(MandatoryStmt),
                inner
            );
            Err(from_pest::ConversionError::Extraneous {
                current_node: stringify!(MandatoryStmt),
            })?;
        }
        *pest = clone;
        Ok(this)
    }
}

#[derive(pest_ast::FromPest)]
#[pest_ast(rule(parser::Rule::presence_stmt))]
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct PresenceStmt<'a> {
    #[pest_ast(outer())]
    pub span: pest::Span<'a>,
    pub value: YangString<'a>,
}

#[derive(pest_ast::FromPest)]
#[pest_ast(rule(parser::Rule::error_message_stmt))]
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ErrorMessageStmt<'a> {
    #[pest_ast(outer())]
    pub span: pest::Span<'a>,
    pub value: YangString<'a>,
}

#[derive(pest_ast::FromPest)]
#[pest_ast(rule(parser::Rule::error_app_tag_stmt))]
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ErrorAppTagStmt<'a> {
    #[pest_ast(outer())]
    pub span: pest::Span<'a>,
    pub value: YangString<'a>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct WhenStmt<'a> {
    pub span: pest::Span<'a>,
    pub condition: YangString<'a>,
    pub description: Option<DescriptionStmt<'a>>,
    pub reference: Option<ReferenceStmt<'a>>,
}

impl<'a> from_pest::FromPest<'a> for WhenStmt<'a> {
    type Rule = parser::Rule;
    type FatalError = from_pest::Void;
    fn from_pest(
        pest: &mut pest::iterators::Pairs<'a, parser::Rule>,
    ) -> Result<Self, from_pest::ConversionError<from_pest::Void>> {
        let mut clone = pest.clone();
        let pair = clone.next().ok_or(from_pest::ConversionError::NoMatch)?;
        if pair.as_rule() != parser::Rule::when_stmt {
            return Err(from_pest::ConversionError::NoMatch);
        }
        let span = pair.as_span();
        let mut inner = pair.into_inner();
        let inner = &mut inner;
        let condition = from_pest::FromPest::from_pest(inner)?;
        let mut description = None;
        let mut reference = None;
        while let Some(clone) = inner.peek() {
            match clone.as_rule() {
                parser::Rule::description_stmt if description.is_none() => {
                    description = Some(from_pest::FromPest::from_pest(inner)?);
                }
                parser::Rule::reference_stmt if reference.is_none() => {
                    reference = Some(from_pest::FromPest::from_pest(inner)?);
                }
                _ => break,
            }
        }
        let this = WhenStmt {
            span,
            condition,
            description,
            reference,
        };
        if inner.clone().next().is_some() {
            from_pest::log::trace!(
                "when converting {}, found extraneous {:?}",
                stringify!(WhenStmt),
                inner
            );
            Err(from_pest::ConversionError::Extraneous {
                current_node: stringify!(WhenStmt),
            })?;
        }
        *pest = clone;
        Ok(this)
    }
}

/// Ordered-by property
#[derive(Debug, Eq, PartialEq, Copy, Clone, Hash)]
pub enum OrderedBy {
    System,
    User,
}

/// Yin-element property
#[derive(Debug, Eq, PartialEq, Copy, Clone, Hash)]
pub enum YinElement {
    True,
    False,
}

/// Deviate operation
#[derive(Debug, Eq, PartialEq, Copy, Clone, Hash)]
pub enum DeviateOperation {
    NotSupported,
    Add,
    Replace,
    Delete,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ModuleStmt<'a> {
    pub span: pest::Span<'a>,
    pub name: Identifier<'a>,
    pub yang_version: YangVersionStmt<'a>,
    pub namespace: NamespaceStmt<'a>,
    pub prefix: PrefixStmt<'a>,
    pub linkage: Vec<LinkageStmt<'a>>,
    pub organization: Option<OrganizationStmt<'a>>,
    pub contact: Option<ContactStmt<'a>>,
    pub description: Option<DescriptionStmt<'a>>,
    pub reference: Option<ReferenceStmt<'a>>,
    pub revisions: Vec<RevisionStmt<'a>>,
    //     pub body: Vec<BodyStatement>,
}

impl<'a> from_pest::FromPest<'a> for ModuleStmt<'a> {
    type Rule = parser::Rule;
    type FatalError = from_pest::Void;
    fn from_pest(
        pest: &mut pest::iterators::Pairs<'a, parser::Rule>,
    ) -> Result<Self, from_pest::ConversionError<Self::FatalError>> {
        let mut clone = pest.clone();
        let pair = clone.next().ok_or(from_pest::ConversionError::NoMatch)?;
        if pair.as_rule() != parser::Rule::module_stmt {
            return Err(from_pest::ConversionError::NoMatch);
        }
        let span = pair.as_span();
        let mut inner = pair.into_inner();
        let inner = &mut inner;
        let name = from_pest::FromPest::from_pest(inner)?;
        let mut namespace = None;
        let mut prefix = None;
        let mut yang_version = None;
        while let Some(clone) = inner.peek() {
            match clone.as_rule() {
                parser::Rule::namespace_stmt if namespace.is_none() => {
                    namespace = Some(from_pest::FromPest::from_pest(inner)?);
                }
                parser::Rule::prefix_stmt if prefix.is_none() => {
                    prefix = Some(from_pest::FromPest::from_pest(inner)?);
                }
                parser::Rule::yang_version_stmt if yang_version.is_none() => {
                    yang_version = Some(from_pest::FromPest::from_pest(inner)?);
                }
                _ => break,
            }
        }
        // The unwrapping is safe because it is checked at the PEST rule level
        let namespace = namespace.ok_or(from_pest::ConversionError::NoMatch)?;
        let prefix = prefix.ok_or(from_pest::ConversionError::NoMatch)?;
        let yang_version = yang_version.ok_or(from_pest::ConversionError::NoMatch)?;
        let linkage = from_pest::FromPest::from_pest(inner)?;

        let mut organization = None;
        let mut contact = None;
        let mut description = None;
        let mut reference = None;
        let mut revisions = vec![];
        while let Some(clone) = inner.peek().clone() {
            match clone.as_rule() {
                parser::Rule::organization_stmt if organization.is_none() => {
                    organization = Some(from_pest::FromPest::from_pest(inner)?);
                }
                parser::Rule::contact_stmt if contact.is_none() => {
                    contact = Some(from_pest::FromPest::from_pest(inner)?);
                }
                parser::Rule::description_stmt if description.is_none() => {
                    description = Some(from_pest::FromPest::from_pest(inner)?);
                }
                parser::Rule::reference_stmt if reference.is_none() => {
                    reference = Some(from_pest::FromPest::from_pest(inner)?);
                }
                parser::Rule::revision_stmt => {
                    revisions.push(from_pest::FromPest::from_pest(inner)?);
                }
                _ => break,
            }
        }
        let this = ModuleStmt {
            span,
            name,
            yang_version,
            namespace,
            prefix,
            linkage,
            organization,
            contact,
            description,
            reference,
            revisions,
        };
        if inner.clone().next().is_some() {
            from_pest::log::trace!(
                "when converting {}, found extraneous {:?}",
                stringify!(ModuleStmt),
                inner
            );
            Err(from_pest::ConversionError::Extraneous {
                current_node: stringify!(ModuleStmt),
            })?;
        }
        *pest = clone;
        Ok(this)
    }
}

#[derive(pest_ast::FromPest)]
#[pest_ast(rule(parser::Rule::revision_date_stmt))]
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct RevisionDateStmt<'a> {
    #[pest_ast(outer())]
    pub span: pest::Span<'a>,

    #[pest_ast(inner(
        rule(parser::Rule::date_arg),
        with(str_from_span),
        with(parse_date),
        with(Result::unwrap)
    ))]
    pub revision_date: chrono::NaiveDate,
}

#[derive(pest_ast::FromPest)]
#[pest_ast(rule(parser::Rule::import_stmt))]
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ImportStmt<'a> {
    #[pest_ast(outer())]
    pub span: pest::Span<'a>,
    pub module: Identifier<'a>,
    pub prefix: PrefixStmt<'a>,
    pub revision_date: Option<RevisionDateStmt<'a>>,
    pub description: Option<DescriptionStmt<'a>>,
    pub reference: Option<ReferenceStmt<'a>>,
}

#[derive(pest_ast::FromPest)]
#[pest_ast(rule(parser::Rule::include_stmt))]
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct IncludeStmt<'a> {
    #[pest_ast(outer())]
    pub span: pest::Span<'a>,
    pub module: Identifier<'a>,
    pub revision_date: Option<RevisionDateStmt<'a>>,
    pub description: Option<DescriptionStmt<'a>>,
    pub reference: Option<ReferenceStmt<'a>>,
}

#[derive(pest_ast::FromPest)]
#[pest_ast(rule(parser::Rule::linkage_stmt))]
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum LinkageStmt<'a> {
    Import(ImportStmt<'a>),
    Include(IncludeStmt<'a>),
}

//
// #[derive(Debug, Clone, Eq, PartialEq, Hash)]
// pub struct Revision {
//     pub date: chrono::NaiveDate,
//     pub description: Option<Box<str>>,
//     pub reference: Option<Box<str>>,
// }
//
// #[derive(Debug, Clone, Eq, PartialEq, Hash)]
// pub enum BodyStatement {
//     Extension(ExtensionStmt),
//     Feature(FeatureStmt),
//     Identity(IdentityStmt),
//     Typedef(TypedefStmt),
//     Grouping(GroupingStmt),
//     DataDef(DataDefStatement),
//     Augment(AugmentStmt),
//     Rpc(RpcStmt),
//     Notification(NotificationStmt),
//     Deviation(DeviationStmt),
// }
//
// #[derive(Debug, Clone, Eq, PartialEq, Hash)]
// pub enum DataDefStatement {
//     Container(ContainerStmt),
//     Leaf(LeafStmt),
//     LeafList(LeafListStmt),
//     List(ListStmt),
//     Choice(ChoiceStmt),
//     Anydata(AnydataStmt),
//     Anyxml(AnyxmlStmt),
//     Uses(UsesStmt),
// }
//
// // Placeholder stub types for complex statements
// // These would be expanded with full parsing logic
//
// #[derive(Debug, Clone, Eq, PartialEq, Hash)]
// pub struct ExtensionStmt {
//     pub name: Box<str>,
//     pub argument: Option<Box<str>>,
//     pub status: Option<Status>,
//     pub description: Option<Box<str>>,
//     pub reference: Option<Box<str>>,
// }
//
// #[derive(Debug, Clone, Eq, PartialEq, Hash)]
// pub struct FeatureStmt {
//     pub name: Box<str>,
//     pub if_features: Vec<Box<str>>,
//     pub status: Option<Status>,
//     pub description: Option<Box<str>>,
//     pub reference: Option<Box<str>>,
// }
//
// #[derive(Debug, Clone, Eq, PartialEq, Hash)]
// pub struct IdentityStmt {
//     pub name: Box<str>,
//     pub bases: Vec<Box<str>>,
//     pub if_features: Vec<Box<str>>,
//     pub status: Option<Status>,
//     pub description: Option<Box<str>>,
//     pub reference: Option<Box<str>>,
// }
//
// #[derive(Debug, Clone, Eq, PartialEq, Hash)]
// pub struct TypedefStmt {
//     pub name: Box<str>,
//     pub type_: Box<str>, // Type identifier
//     pub units: Option<Box<str>>,
//     pub default: Option<Box<str>>,
//     pub status: Option<Status>,
//     pub description: Option<Box<str>>,
//     pub reference: Option<Box<str>>,
// }
//
// #[derive(Debug, Clone, Eq, PartialEq, Hash)]
// pub struct GroupingStmt {
//     pub name: Box<str>,
//     pub status: Option<Status>,
//     pub description: Option<Box<str>>,
//     pub reference: Option<Box<str>>,
//     // Contains typedefs, groupings, data definitions, actions, notifications
// }
//

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ContainerStmt<'a> {
    pub span: pest::Span<'a>,
    pub name: Identifier<'a>,
    pub when: Option<WhenStmt<'a>>,
    pub if_features: Vec<Box<str>>,
    pub must: Vec<MustStmt<'a>>,
    pub presence: Option<PresenceStmt<'a>>,
    pub config: Option<ConfigStmt<'a>>,
    pub status: Option<StatusStmt<'a>>,
    pub description: Option<DescriptionStmt<'a>>,
    pub reference: Option<ReferenceStmt<'a>>,
    // *(typedef-stmt / grouping-stmt)
    // *data-def-stmt
    // *action-stmt
    // *notification-stmts
}

impl<'a> from_pest::FromPest<'a> for ContainerStmt<'a> {
    type Rule = parser::Rule;
    type FatalError = ParseError;
    fn from_pest(
        pest: &mut pest::iterators::Pairs<'a, parser::Rule>,
    ) -> Result<Self, from_pest::ConversionError<Self::FatalError>> {
        let mut clone = pest.clone();
        let pair = clone.next().ok_or(from_pest::ConversionError::NoMatch)?;
        if pair.as_rule() != parser::Rule::container_stmt {
            return Err(from_pest::ConversionError::NoMatch);
        }

        let span = pair.as_span();
        let mut inner = pair.into_inner();
        let inner = &mut inner;
        let name = Identifier::from_pest(inner).map_err(map_error)?;
        let mut when = None;
        let mut if_features = vec![];
        let mut must = vec![];
        let mut presence = None;
        let mut config = None;
        let mut status = None;
        let mut description = None;
        let mut reference = None;
        while let Some(clone) = inner.peek() {
            match clone.as_rule() {
                parser::Rule::when_stmt => {
                    if when.is_some() {
                        return Err(from_pest::ConversionError::Extraneous {
                            current_node: stringify!(WhenStmt),
                        })?;
                    }
                    when = Some(WhenStmt::from_pest(inner).map_err(map_error)?);
                }
                parser::Rule::if_feature_stmt => todo!(),
                parser::Rule::must_stmt => {
                    must.push(MustStmt::from_pest(inner)?);
                }
                parser::Rule::presence_stmt => {
                    if presence.is_some() {
                        return Err(from_pest::ConversionError::Extraneous {
                            current_node: stringify!(PresenceStmt),
                        })?;
                    }
                    presence = Some(PresenceStmt::from_pest(inner).map_err(map_error)?);
                },
                parser::Rule::config_stmt => {
                    if config.is_some() {
                        return Err(from_pest::ConversionError::Extraneous {
                            current_node: stringify!(ConfigStmt),
                        })?;
                    }
                    config = Some(ConfigStmt::from_pest(inner).map_err(map_error)?);
                }
                parser::Rule::status_stmt => {
                    if status.is_some() {
                        return Err(from_pest::ConversionError::Extraneous {
                            current_node: stringify!(StatusStmt),
                        })?;
                    }
                    status = Some(from_pest::FromPest::from_pest(inner)?);
                }
                parser::Rule::description_stmt => {
                    if description.is_some() {
                        return Err(from_pest::ConversionError::Extraneous {
                            current_node: stringify!(DescriptionStmt),
                        })?;
                    }
                    description = Some(DescriptionStmt::from_pest(inner).map_err(map_error)?);
                }
                parser::Rule::reference_stmt => {
                    if reference.is_some() {
                        return Err(from_pest::ConversionError::Extraneous {
                            current_node: stringify!(ReferenceStmt),
                        })?;
                    }
                    reference = Some(ReferenceStmt::from_pest(inner).map_err(map_error)?);
                }
                _ => break,
            }
        }

        let this = ContainerStmt {
            span,
            name,
            when,
            if_features,
            must,
            presence,
            config,
            status,
            description,
            reference,
        };
        if inner.clone().next().is_some() {
            from_pest::log::trace!(
                "when converting {}, found extraneous {:?}",
                stringify!(ContainerStmt),
                inner
            );
            Err(from_pest::ConversionError::Extraneous {
                current_node: stringify!(ContainerStmt),
            })?;
        }
        *pest = clone;
        Ok(this)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct MustStmt<'a> {
    span: pest::Span<'a>,
    condition: YangString<'a>,
    error_message: Option<ErrorMessageStmt<'a>>,
    error_app_tag: Option<ErrorAppTagStmt<'a>>,
    description: Option<DescriptionStmt<'a>>,
    reference: Option<ReferenceStmt<'a>>,
}

impl<'a> from_pest::FromPest<'a> for MustStmt<'a> {
    type Rule = parser::Rule;
    type FatalError = ParseError;
    fn from_pest(
        pest: &mut pest::iterators::Pairs<'a, parser::Rule>,
    ) -> Result<Self, from_pest::ConversionError<Self::FatalError>> {
        let mut clone = pest.clone();
        let pair = clone.next().ok_or(from_pest::ConversionError::NoMatch)?;
        if pair.as_rule() != parser::Rule::must_stmt {
            return Err(from_pest::ConversionError::NoMatch);
        }
        let span = pair.as_span();
        let mut inner = pair.into_inner();
        let inner = &mut inner;
        let condition = YangString::from_pest(inner).map_err(map_error)?;
        let mut error_message = None;
        let mut error_app_tag = None;
        let mut description = None;
        let mut reference = None;
        while let Some(clone) = inner.peek() {
            match clone.as_rule() {
                parser::Rule::error_message_stmt => {
                    if error_message.is_some() {
                        return Err(from_pest::ConversionError::Extraneous {
                            current_node: stringify!(ErrorMessageStmt),
                        })?;
                    }
                    error_message = Some(ErrorMessageStmt::from_pest(inner).map_err(map_error)?);
                }
                parser::Rule::error_app_tag_stmt => {
                    if error_app_tag.is_some() {
                        return Err(from_pest::ConversionError::Extraneous {
                            current_node: stringify!(ErrorAppTagStmt),
                        })?;
                    }
                    error_app_tag = Some(ErrorAppTagStmt::from_pest(inner).map_err(map_error)?);
                }
                parser::Rule::description_stmt => {
                    if description.is_some() {
                        return Err(from_pest::ConversionError::Extraneous {
                            current_node: stringify!(DescriptionStmt),
                        })?;
                    }
                    description = Some(DescriptionStmt::from_pest(inner).map_err(map_error)?);
                }
                parser::Rule::reference_stmt => {
                    if reference.is_some() {
                        return Err(from_pest::ConversionError::Extraneous {
                            current_node: stringify!(ReferenceStmt),
                        })?;
                    }
                    reference = Some(ReferenceStmt::from_pest(inner).map_err(map_error)?);
                }
                _ => break,
            }
        }
        let this = MustStmt {
            span,
            condition,
            error_message,
            error_app_tag,
            description,
            reference,
        };
        if inner.clone().next().is_some() {
            from_pest::log::trace!(
                "when converting {}, found extraneous {:?}",
                stringify!(MustStmt),
                inner
            );
            Err(from_pest::ConversionError::Extraneous {
                current_node: stringify!(MustStmt),
            })?;
        }
        *pest = clone;
        Ok(this)
    }
}

// #[derive(Debug, Clone, Eq, PartialEq, Hash)]
// pub struct LeafStmt {
//     pub name: Box<str>,
//     pub type_: Box<str>, // Type identifier
//     pub when: Option<Box<str>>,
//     pub if_features: Vec<Box<str>>,
//     pub units: Option<Box<str>>,
//     pub default: Option<Box<str>>,
//     pub config: Option<Config>,
//     pub mandatory: Option<bool>,
//     pub status: Option<Status>,
//     pub description: Option<Box<str>>,
//     pub reference: Option<Box<str>>,
// }
//
// #[derive(Debug, Clone, Eq, PartialEq, Hash)]
// pub struct LeafListStmt {
//     pub name: Box<str>,
//     pub type_: Box<str>, // Type identifier
//     pub when: Option<Box<str>>,
//     pub if_features: Vec<Box<str>>,
//     pub units: Option<Box<str>>,
//     pub defaults: Vec<Box<str>>,
//     pub config: Option<Config>,
//     pub min_elements: Option<u32>,
//     pub max_elements: Option<u32>, // None means unbounded
//     pub ordered_by: Option<OrderedBy>,
//     pub status: Option<Status>,
//     pub description: Option<Box<str>>,
//     pub reference: Option<Box<str>>,
// }
//
// #[derive(Debug, Clone, Eq, PartialEq, Hash)]
// pub struct ListStmt {
//     pub name: Box<str>,
//     pub when: Option<Box<str>>,
//     pub if_features: Vec<Box<str>>,
//     pub key: Option<Vec<Box<str>>>,
//     pub unique: Vec<Vec<Box<str>>>,
//     pub config: Option<Config>,
//     pub min_elements: Option<u32>,
//     pub max_elements: Option<u32>,
//     pub ordered_by: Option<OrderedBy>,
//     pub status: Option<Status>,
//     pub description: Option<Box<str>>,
//     pub reference: Option<Box<str>>,
//     // Contains typedefs, groupings, data definitions, actions, notifications
// }
//
// #[derive(Debug, Clone, Eq, PartialEq, Hash)]
// pub struct ChoiceStmt {
//     pub name: Box<str>,
//     pub when: Option<Box<str>>,
//     pub if_features: Vec<Box<str>>,
//     pub default: Option<Box<str>>,
//     pub config: Option<Config>,
//     pub mandatory: Option<bool>,
//     pub status: Option<Status>,
//     pub description: Option<Box<str>>,
//     pub reference: Option<Box<str>>,
//     // Contains cases
// }
//
// #[derive(Debug, Clone, Eq, PartialEq, Hash)]
// pub struct AnydataStmt {
//     pub name: Box<str>,
//     pub when: Option<Box<str>>,
//     pub if_features: Vec<Box<str>>,
//     pub config: Option<Config>,
//     pub mandatory: Option<bool>,
//     pub status: Option<Status>,
//     pub description: Option<Box<str>>,
//     pub reference: Option<Box<str>>,
// }
//
// #[derive(Debug, Clone, Eq, PartialEq, Hash)]
// pub struct AnyxmlStmt {
//     pub name: Box<str>,
//     pub when: Option<Box<str>>,
//     pub if_features: Vec<Box<str>>,
//     pub config: Option<Config>,
//     pub mandatory: Option<bool>,
//     pub status: Option<Status>,
//     pub description: Option<Box<str>>,
//     pub reference: Option<Box<str>>,
// }
//
// #[derive(Debug, Clone, Eq, PartialEq, Hash)]
// pub struct UsesStmt {
//     pub grouping_ref: Box<str>,
//     pub when: Option<Box<str>>,
//     pub if_features: Vec<Box<str>>,
//     pub status: Option<Status>,
//     pub description: Option<Box<str>>,
//     pub reference: Option<Box<str>>,
//     // Contains refine and augment statements
// }
//
// #[derive(Debug, Clone, Eq, PartialEq, Hash)]
// pub struct AugmentStmt {
//     pub target: Box<str>,
//     pub when: Option<Box<str>>,
//     pub if_features: Vec<Box<str>>,
//     pub status: Option<Status>,
//     pub description: Option<Box<str>>,
//     pub reference: Option<Box<str>>,
//     // Contains data definitions, cases, actions, notifications
// }
//
// #[derive(Debug, Clone, Eq, PartialEq, Hash)]
// pub struct RpcStmt {
//     pub name: Box<str>,
//     pub if_features: Vec<Box<str>>,
//     pub status: Option<Status>,
//     pub description: Option<Box<str>>,
//     pub reference: Option<Box<str>>,
//     // Contains typedefs, groupings, input, output
// }
//
// #[derive(Debug, Clone, Eq, PartialEq, Hash)]
// pub struct NotificationStmt {
//     pub name: Box<str>,
//     pub if_features: Vec<Box<str>>,
//     pub status: Option<Status>,
//     pub description: Option<Box<str>>,
//     pub reference: Option<Box<str>>,
//     // Contains typedefs, groupings, data definitions
// }
//
// #[derive(Debug, Clone, Eq, PartialEq, Hash)]
// pub struct DeviationStmt {
//     pub target: Box<str>,
//     pub description: Option<Box<str>>,
//     pub reference: Option<Box<str>>,
//     // Contains deviate statements
// }

// ============================================================================
// Validation Errors
// ============================================================================

#[derive(Debug, Clone)]
pub enum ParseError {
    PestError(String),
    MissingRequired {
        field: &'static str,
    },
    DuplicateStatement {
        statement: &'static str,
    },
    InvalidCardinality {
        statement: &'static str,
        expected: &'static str,
        found: usize,
    },
    InvalidDate {
        value: String,
        error: String,
    },
    InvalidValue {
        field: &'static str,
        value: String,
    },
    ConflictingStatements {
        statements: Vec<&'static str>,
    },
    Custom(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::PestError(msg) => write!(f, "Parse error: {msg}"),
            ParseError::MissingRequired { field } => {
                write!(f, "Missing required statement: {field}")
            }
            ParseError::DuplicateStatement { statement } => {
                write!(f, "Duplicate statement: {statement}")
            }
            ParseError::InvalidCardinality {
                statement,
                expected,
                found,
            } => {
                write!(
                    f,
                    "Invalid cardinality for {statement}: expected {expected}, found {found}",
                )
            }
            ParseError::InvalidDate { value, error } => {
                write!(f, "Invalid date '{value}': {error}")
            }
            ParseError::InvalidValue { field, value } => {
                write!(f, "Invalid value for {field}: {value}")
            }
            ParseError::ConflictingStatements { statements } => {
                write!(f, "Conflicting statements: {}", statements.join(", "))
            }
            ParseError::Custom(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<pest::error::Error<parser::Rule>> for ParseError {
    fn from(err: pest::error::Error<parser::Rule>) -> Self {
        ParseError::PestError(err.to_string())
    }
}

impl From<from_pest::ConversionError<from_pest::Void>> for ParseError {
    fn from(value: from_pest::ConversionError<from_pest::Void>) -> Self {
        Self::PestError(value.to_string())
    }
}

// Helper functions

#[inline]
fn parse_date(date_str: &str) -> Result<chrono::NaiveDate, ParseError> {
    chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d").map_err(|e| ParseError::InvalidDate {
        value: date_str.to_string(),
        error: e.to_string(),
    })
}

#[inline]
fn str_from_span(span: pest::Span<'_>) -> &str {
    span.as_str()
}


#[inline]
fn map_error(err: from_pest::ConversionError<from_pest::Void>) -> from_pest::ConversionError<ParseError> {
    match err {
        from_pest::ConversionError::NoMatch => from_pest::ConversionError::NoMatch,
        from_pest::ConversionError::Malformed(fatal) => {
            from_pest::ConversionError::Malformed(ParseError::PestError(fatal.to_string()))
        }
        from_pest::ConversionError::Extraneous { current_node } => from_pest::ConversionError::Extraneous { current_node },

    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::parser::{Rule, Yang11Parser};
    use from_pest::FromPest;
    use pest::Parser;

    #[test]
    fn test_dstring_inner() {
        let input = "This is a multi-line\n string";
        let expected = DStringInner {
            span: pest::Span::new(input, 0, input.len()).unwrap(),
        };
        let mut parse_tree =
            Yang11Parser::parse(Rule::dstring_inner, input).expect("Failed to parse");
        let parsed = DStringInner::from_pest(&mut parse_tree)
            .expect("Failed to convert AST to DStringInner");
        assert_eq!(parsed, expected);
    }

    #[test]
    fn test_dstring() {
        let input = r#""This is multi-line
        string
        " + "another part
        " + "
        on new line
        ""#;
        let inner1 = DStringInner {
            span: pest::Span::new(input, 1, 43).unwrap(),
        };
        let inner2 = DStringInner {
            span: pest::Span::new(input, 48, 69).unwrap(),
        };
        let inner3 = DStringInner {
            span: pest::Span::new(input, 74, 103).unwrap(),
        };
        let expected = DString {
            span: pest::Span::new(input, 0, input.len()).unwrap(),
            inner: vec![inner1, inner2, inner3],
        };
        let mut parse_tree = Yang11Parser::parse(Rule::dstring, input).expect("Failed to parse");
        let parsed =
            DString::from_pest(&mut parse_tree).expect("Failed to convert AST to DStringInner");
        assert_eq!(parsed, expected);
    }

    #[test]
    fn test_sstring_inner() {
        let input = "This is a multi-line\n string";
        let expected = SStringInner {
            span: pest::Span::new(input, 0, input.len()).unwrap(),
        };
        let mut parse_tree =
            Yang11Parser::parse(Rule::sstring_inner, input).expect("Failed to parse");
        let parsed = SStringInner::from_pest(&mut parse_tree)
            .expect("Failed to convert AST to DStringInner");
        assert_eq!(parsed, expected);
    }

    #[test]
    fn test_sstring() {
        let input = r#"'This is multi-line
        string
        ' + 'another part
        ' + '
        on new line
        '"#;
        let inner1 = SStringInner {
            span: pest::Span::new(input, 1, 43).unwrap(),
        };
        let inner2 = SStringInner {
            span: pest::Span::new(input, 48, 69).unwrap(),
        };
        let inner3 = SStringInner {
            span: pest::Span::new(input, 74, 103).unwrap(),
        };
        let expected = SString {
            span: pest::Span::new(input, 0, input.len()).unwrap(),
            inner: vec![inner1, inner2, inner3],
        };
        let mut parse_tree = Yang11Parser::parse(Rule::sstring, input).expect("Failed to parse");
        let parsed =
            SString::from_pest(&mut parse_tree).expect("Failed to convert AST to DStringInner");
        assert_eq!(parsed, expected);
    }

    #[test]
    fn test_unquoted() {
        let input = "ThisIsUnquotedString";
        let expected = Unquoted {
            span: pest::Span::new(input, 0, input.len()).unwrap(),
        };
        let mut parse_tree = Yang11Parser::parse(Rule::unquoted, input).expect("Failed to parse");
        let parsed =
            Unquoted::from_pest(&mut parse_tree).expect("Failed to convert AST to DStringInner");
        assert_eq!(parsed, expected);
    }

    #[test]
    fn test_identifier() {
        let input = "yang-name";
        let expected = Identifier {
            span: pest::Span::new(input, 0, input.len()).unwrap(),
        };
        let mut parse_tree = Yang11Parser::parse(Rule::identifier, input).expect("Failed to parse");
        let parsed =
            Identifier::from_pest(&mut parse_tree).expect("Failed to convert AST to Identifier");
        assert_eq!(parsed, expected);
    }

    #[test]
    fn test_namespace_stmt() {
        let input = r#"namespace "https://example.com/example";"#;
        let expected = NamespaceStmt {
            span: pest::Span::new(input, 0, input.len()).unwrap(),
            ns: YangString::DoubleQuoted(DString {
                span: pest::Span::new(input, 10, 39).unwrap(),
                inner: vec![DStringInner {
                    span: pest::Span::new(input, 11, 38).unwrap(),
                }],
            }),
        };
        let mut parse_tree =
            Yang11Parser::parse(Rule::namespace_stmt, input).expect("Failed to parse");
        let parsed =
            NamespaceStmt::from_pest(&mut parse_tree).expect("Failed to convert AST to namespace");
        assert_eq!(parsed, expected);
    }

    #[test]
    fn test_description_stmt() {
        let input = r#"description
    "This module contains a collection of YANG definitions for
     managing network interfaces.

     Copyright (c) 2018 IETF Trust and the persons identified as
     authors of the code.  All rights reserved.
"
     +
     "
Redistribution and use in source and binary forms, with or
     without modification, is permitted pursuant to, and subject
     to the license terms contained in, the Simplified BSD License
     set forth in Section 4.c of the IETF Trust's Legal Provisions
     Relating to IETF Documents
     (https://trustee.ietf.org/license-info).

     This version of this YANG module is part of RFC 8343; see
     the RFC itself for full legal notices.";"#;
        let expected = DescriptionStmt {
            span: pest::Span::new(input, 0, input.len()).unwrap(),
            value: YangString::DoubleQuoted(DString {
                span: pest::Span::new(input, 16, 683).unwrap(),
                inner: vec![
                    DStringInner {
                        span: pest::Span::new(input, 17, 223).unwrap(),
                    },
                    DStringInner {
                        span: pest::Span::new(input, 238, 682).unwrap(),
                    },
                ],
            }),
        };
        let mut parse_tree =
            Yang11Parser::parse(Rule::description_stmt, input).expect("Failed to parse");
        let result = DescriptionStmt::from_pest(&mut parse_tree)
            .expect("Failed to convert AST to DescriptionStmt");
        assert_eq!(result, expected);
    }

    #[test]
    fn test_prefix_stmt() {
        let input = "prefix ex;";
        let expected = PrefixStmt {
            span: pest::Span::new("prefix ex;", 0, input.len()).unwrap(),
            prefix: "ex",
        };
        let mut parse_tree =
            Yang11Parser::parse(Rule::prefix_stmt, input).expect("Failed to parse");
        let result =
            PrefixStmt::from_pest(&mut parse_tree).expect("Failed to convert AST to PrefixStmt");
        assert_eq!(result, expected);
    }

    #[test]
    fn test_yang_version_stmt() {
        let input = "yang-version 1.1;";
        let expected = YangVersionStmt {
            span: pest::Span::new("yang-version 1.1;", 0, input.len()).unwrap(),
            version: YangVersion::V1_1,
        };
        let mut parse_tree =
            Yang11Parser::parse(Rule::yang_version_stmt, input).expect("Failed to parse");
        let result = YangVersionStmt::from_pest(&mut parse_tree)
            .expect("Failed to convert AST to YangVersion");
        assert_eq!(result, expected);
    }

    #[test]
    fn test_revision_date_stmt() {
        let input = r#"revision-date 2013-07-15;"#;
        let mut parse_tree =
            Yang11Parser::parse(Rule::revision_date_stmt, input).expect("Failed to parse");
        let result = RevisionDateStmt::from_pest(&mut parse_tree)
            .expect("Failed to convert AST to RevisionDateStmt");
        assert_eq!(
            result.revision_date,
            chrono::NaiveDate::from_ymd_opt(2013, 7, 15).unwrap()
        );
    }

    #[test]
    fn test_import_stmt() {
        let input = r#"import ietf-yang-types {
        prefix yang;
        revision-date 2013-07-15;
        }"#;
        let expected = ImportStmt {
            span: pest::Span::new(input, 0, input.len()).unwrap(),
            module: Identifier {
                span: pest::Span::new(input, 7, 22).unwrap(),
            },
            prefix: PrefixStmt {
                span: pest::Span::new(input, 33, 54).unwrap(),
                prefix: "yang",
            },
            revision_date: Some(RevisionDateStmt {
                span: pest::Span::new(input, 54, 88).unwrap(),
                revision_date: chrono::NaiveDate::from_ymd_opt(2013, 7, 15).unwrap(),
            }),
            description: None,
            reference: None,
        };
        let mut parse_tree =
            Yang11Parser::parse(Rule::import_stmt, input).expect("Failed to parse");
        let result =
            ImportStmt::from_pest(&mut parse_tree).expect("Failed to convert AST to Import");
        assert_eq!(result, expected);
    }

    #[test]
    fn test_parse_module_with_imports() {
        let input = r#"module example {
    prefix ex;
    yang-version 1.1;
    namespace "https://example.com/example";

    import ietf-yang-types {
        prefix yang;
        revision-date 2013-07-15;
    }

    import ietf-inet-types {
        prefix inet;
    }

    contact "example@example.com";

    organization "TestOrg";
}"#;
        let expected = ModuleStmt {
            span: pest::Span::new(input, 0, input.len()).unwrap(),
            name: Identifier {
                span: pest::Span::new(input, 7, 14).unwrap(),
            },
            yang_version: YangVersionStmt {
                span: pest::Span::new(input, 36, 58).unwrap(),
                version: YangVersion::V1_1,
            },
            namespace: NamespaceStmt {
                span: pest::Span::new(input, 58, 104).unwrap(),
                ns: YangString::DoubleQuoted(DString {
                    span: pest::Span::new(input, 68, 97).unwrap(),
                    inner: vec![DStringInner {
                        span: pest::Span::new(input, 69, 96).unwrap(),
                    }],
                }),
            },
            prefix: PrefixStmt {
                span: pest::Span::new(input, 21, 36).unwrap(),
                prefix: "ex",
            },
            linkage: vec![
                LinkageStmt::Import(ImportStmt {
                    span: pest::Span::new(input, 104, 195).unwrap(),
                    module: Identifier {
                        span: pest::Span::new(input, 111, 126).unwrap(),
                    },
                    prefix: PrefixStmt {
                        span: pest::Span::new(input, 137, 158).unwrap(),
                        prefix: "yang",
                    },
                    revision_date: Some(RevisionDateStmt {
                        span: pest::Span::new(input, 158, 188).unwrap(),
                        revision_date: chrono::NaiveDate::from_ymd_opt(2013, 7, 15).unwrap(),
                    }),
                    description: None,
                    reference: None,
                }),
                LinkageStmt::Import(ImportStmt {
                    span: pest::Span::new(input, 195, 252).unwrap(),
                    module: Identifier {
                        span: pest::Span::new(input, 202, 217).unwrap(),
                    },
                    prefix: PrefixStmt {
                        span: pest::Span::new(input, 228, 245).unwrap(),
                        prefix: "inet",
                    },
                    revision_date: None,
                    description: None,
                    reference: None,
                }),
            ],
            organization: Some(OrganizationStmt {
                span: pest::Span::new(input, 288, 312).unwrap(),
                value: YangString::DoubleQuoted(DString {
                    span: pest::Span::new(input, 301, 310).unwrap(),
                    inner: vec![DStringInner {
                        span: pest::Span::new(input, 302, 309).unwrap(),
                    }],
                }),
            }),
            contact: Some(ContactStmt {
                span: pest::Span::new(input, 252, 288).unwrap(),
                value: YangString::DoubleQuoted(DString {
                    span: pest::Span::new(input, 260, 281).unwrap(),
                    inner: vec![DStringInner {
                        span: pest::Span::new(input, 261, 280).unwrap(),
                    }],
                }),
            }),
            description: None,
            reference: None,
            revisions: vec![],
        };
        let mut parse_tree =
            Yang11Parser::parse(Rule::module_stmt, input).expect("Failed to parse");
        let result =
            ModuleStmt::from_pest(&mut parse_tree).expect("Failed to convert AST to ModuleStmt");
        assert_eq!(result, expected);
    }

    #[test]
    fn test_config_stmt() {
        let input_true = "config true;";
        let input_false = "config false;";
        let expected_true = ConfigStmt {
            span: pest::Span::new(input_true, 0, input_true.len()).unwrap(),
            is_config: true,
        };
        let expected_false = ConfigStmt {
            span: pest::Span::new(input_false, 0, input_false.len()).unwrap(),
            is_config: false,
        };

        let mut parse_tree_true =
            Yang11Parser::parse(Rule::config_stmt, input_true).expect("Failed to parse");
        let result_true = ConfigStmt::from_pest(&mut parse_tree_true)
            .expect("Failed to convert AST to ConfigStmt");
        let mut parse_tree_false =
            Yang11Parser::parse(Rule::config_stmt, input_false).expect("Failed to parse");
        let result_false = ConfigStmt::from_pest(&mut parse_tree_false)
            .expect("Failed to convert AST to ConfigStmt");

        assert_eq!(result_true, expected_true);
        assert_eq!(result_false, expected_false);
    }

    #[test]
    fn test_mandatory_stmt() {
        let input_true = "mandatory true;";
        let input_false = "mandatory false;";
        let expected_true = MandatoryStmt {
            span: pest::Span::new(input_true, 0, input_true.len()).unwrap(),
            is_mandatory: true,
        };
        let expected_false = MandatoryStmt {
            span: pest::Span::new(input_false, 0, input_false.len()).unwrap(),
            is_mandatory: false,
        };
        let mut parse_tree_true =
            Yang11Parser::parse(Rule::mandatory_stmt, input_true).expect("Failed to parse");
        let result_true = MandatoryStmt::from_pest(&mut parse_tree_true)
            .expect("Failed to convert AST to MandatoryStmt");
        let mut parse_tree_false =
            Yang11Parser::parse(Rule::mandatory_stmt, input_false).expect("Failed to parse");
        let result_false = MandatoryStmt::from_pest(&mut parse_tree_false)
            .expect("Failed to convert AST to MandatoryStmt");
        assert_eq!(result_true, expected_true);
        assert_eq!(result_false, expected_false);
    }

    #[test]
    fn test_status_stmt() {
        let input_current = "status current;";
        let input_deprecated = "status deprecated;";
        let input_obsolete = "status obsolete;";
        let expected_current = StatusStmt {
            span: pest::Span::new(input_current, 0, input_current.len()).unwrap(),
            status: Status::Current,
        };
        let expected_deprecated = StatusStmt {
            span: pest::Span::new(input_deprecated, 0, input_deprecated.len()).unwrap(),
            status: Status::Deprecated,
        };
        let expected_obsolete = StatusStmt {
            span: pest::Span::new(input_obsolete, 0, input_obsolete.len()).unwrap(),
            status: Status::Obsolete,
        };

        let mut parse_tree_current =
            Yang11Parser::parse(Rule::status_stmt, input_current).expect("Failed to parse");
        let result_current = StatusStmt::from_pest(&mut parse_tree_current)
            .expect("Failed to convert AST to StatusStmt");
        let mut parse_tree_deprecated =
            Yang11Parser::parse(Rule::status_stmt, input_deprecated).expect("Failed to parse");
        let result_deprecated = StatusStmt::from_pest(&mut parse_tree_deprecated)
            .expect("Failed to convert AST to StatusStmt");
        let mut parse_tree_obsolete =
            Yang11Parser::parse(Rule::status_stmt, input_obsolete).expect("Failed to parse");
        let result_obsolete = StatusStmt::from_pest(&mut parse_tree_obsolete)
            .expect("Failed to convert AST to StatusStmt");

        assert_eq!(result_current, expected_current);
        assert_eq!(result_deprecated, expected_deprecated);
        assert_eq!(result_obsolete, expected_obsolete);
    }

    #[test]
    fn test_value_stmt() {
        let input_positive = "value 100;";
        let input_negative = "value -50;";
        let input_positive_quoted = r#"value "3";"#;
        let input_negative_quoted = r#"value '-500';"#;
        let expected_positive = ValueStmt {
            span: pest::Span::new(input_positive, 0, input_positive.len()).unwrap(),
            value: IntegerValue {
                span: pest::Span::new(input_positive, 6, 9).unwrap(),
            },
        };
        let expected_negative = ValueStmt {
            span: pest::Span::new(input_negative, 0, input_negative.len()).unwrap(),
            value: IntegerValue {
                span: pest::Span::new(input_negative, 6, 9).unwrap(),
            },
        };
        let expected_positive_quoted = ValueStmt {
            span: pest::Span::new(input_positive_quoted, 0, input_positive_quoted.len()).unwrap(),
            value: IntegerValue {
                span: pest::Span::new(input_positive_quoted, 7, 8).unwrap(),
            },
        };
        let expected_negative_quoted = ValueStmt {
            span: pest::Span::new(input_negative_quoted, 0, input_negative_quoted.len()).unwrap(),
            value: IntegerValue {
                span: pest::Span::new(input_negative_quoted, 7, 11).unwrap(),
            },
        };
        let mut parse_tree_positive =
            Yang11Parser::parse(Rule::value_stmt, input_positive).expect("Failed to parse");
        let result_positive = ValueStmt::from_pest(&mut parse_tree_positive)
            .expect("Failed to convert AST to ValueStmt");
        let mut parse_tree_negative =
            Yang11Parser::parse(Rule::value_stmt, input_negative).expect("Failed to parse");
        let result_negative = ValueStmt::from_pest(&mut parse_tree_negative)
            .expect("Failed to convert AST to ValueStmt");
        let mut parse_tree_positive_quoted =
            Yang11Parser::parse(Rule::value_stmt, input_positive_quoted).expect("Failed to parse");
        let result_positive_quoted = ValueStmt::from_pest(&mut parse_tree_positive_quoted)
            .expect("Failed to convert AST to ValueStmt");
        let mut parse_tree_negative_quoted =
            Yang11Parser::parse(Rule::value_stmt, input_negative_quoted).expect("Failed to parse");
        let result_negative_quoted = ValueStmt::from_pest(&mut parse_tree_negative_quoted)
            .expect("Failed to convert AST to ValueStmt");

        assert_eq!(result_positive, expected_positive);
        assert_eq!(result_negative, expected_negative);
        assert_eq!(result_positive_quoted, expected_positive_quoted);
        assert_eq!(result_negative_quoted, expected_negative_quoted);
    }

    #[test]
    fn test_container_stmt() {
        let input = r#"container interfaces {
            description "A list of interfaces.";
            status current;
            config true;
            reference "RFC XXXX";
        }"#;
        let expected = ContainerStmt {
            span: pest::Span::new(input, 0, input.len()).unwrap(),
            name: Identifier {
                span: pest::Span::new(input, 10, 20).unwrap(),
            },
            when: None,
            if_features: vec![],
            must: vec![],
            presence: None,
            config: Some(ConfigStmt {
                span: pest::Span::new(input, 112, 137).unwrap(),
                is_config: true,
            }),
            status: Some(StatusStmt {
                span: pest::Span::new(input, 84, 112).unwrap(),
                status: Status::Current,
            }),
            description: Some(DescriptionStmt {
                span: pest::Span::new(input, 35, 84).unwrap(),
                value: YangString::DoubleQuoted(DString {
                    span: pest::Span::new(input, 47, 70).unwrap(),
                    inner: vec![DStringInner {
                        span: pest::Span::new(input, 48, 69).unwrap(),
                    }],
                }),
            }),
            reference: Some(ReferenceStmt {
                span: pest::Span::new(input, 137, 167).unwrap(),
                value: YangString::DoubleQuoted(DString {
                    span: pest::Span::new(input, 147, 157).unwrap(),
                    inner: vec![DStringInner {
                        span: pest::Span::new(input, 148, 156).unwrap(),
                    }],
                }),
            }),
        };

        let mut parse_tree =
            Yang11Parser::parse(Rule::container_stmt, input).expect("Failed to parse");
        let result = ContainerStmt::from_pest(&mut parse_tree)
            .expect("Failed to convert AST to ContainerStmt");
        assert_eq!(result, expected);
    }

    #[test]
    fn test_when_stmt() {
        let input_min = r#"when "min-elements > 0";"#;
        let input_full = r#"when "min-elements > 0" {
            description SomeDescription;
            reference RFC1234;
        }"#;

        let expected_min = WhenStmt {
            span: pest::Span::new(input_min, 0, input_min.len()).unwrap(),
            condition: YangString::DoubleQuoted(DString {
                span: pest::Span::new(input_min, 5, 23).unwrap(),
                inner: vec![DStringInner {
                    span: pest::Span::new(input_min, 6, 22).unwrap(),
                }],
            }),
            description: None,
            reference: None,
        };

        let expected_full = WhenStmt {
            span: pest::Span::new(input_full, 0, input_full.len()).unwrap(),
            condition: YangString::DoubleQuoted(DString {
                span: pest::Span::new(input_full, 5, 23).unwrap(),
                inner: vec![DStringInner {
                    span: pest::Span::new(input_full, 6, 22).unwrap(),
                }],
            }),
            description: Some(DescriptionStmt {
                span: pest::Span::new(input_full, 38, 79).unwrap(),
                value: YangString::Unquoted(Unquoted {
                    span: pest::Span::new(input_full, 50, 65).unwrap(),
                }),
            }),
            reference: Some(ReferenceStmt {
                span: pest::Span::new(input_full, 79, 106).unwrap(),
                value: YangString::Unquoted(Unquoted {
                    span: pest::Span::new(input_full, 89, 96).unwrap(),
                }),
            }),
        };

        let mut parse_tree_min =
            Yang11Parser::parse(Rule::when_stmt, input_min).expect("Failed to parse");
        let result_min =
            WhenStmt::from_pest(&mut parse_tree_min).expect("Failed to convert AST to WhenStmt");
        let mut parse_tree_full =
            Yang11Parser::parse(Rule::when_stmt, input_full).expect("Failed to parse");
        let result_full =
            WhenStmt::from_pest(&mut parse_tree_full).expect("Failed to convert AST to WhenStmt");
        assert_eq!(result_min, expected_min);
        assert_eq!(result_full, expected_full);
    }

    #[test]
    fn test_parse_date() {
        assert!(parse_date("2024-11-07").is_ok());
        assert!(parse_date("2024-01-01").is_ok());
        assert!(parse_date("invalid").is_err());
        assert!(parse_date("2024-13-01").is_err());
        assert!(parse_date("2024-02-30").is_err());
    }
}
