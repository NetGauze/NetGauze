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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YangImport {
    pub module_name: String,
    pub prefix: String,
    pub revision_date: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YangInclude {
    pub submodule_name: String,
    pub revision_date: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YangDependencies {
    pub imports: Vec<YangImport>,
    pub includes: Vec<YangInclude>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YangModuleMetadata {
    pub name: String,
    pub namespace: Option<String>,
    pub prefix: Option<String>,
    pub revision: Option<String>,
    // if Some, it's a submodule of the given parent module
    pub is_submodule_of: Option<String>,
}

impl fmt::Display for YangDependencies {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Imports ({}):", self.imports.len())?;
        for import in &self.imports {
            write!(f, "  - {} (prefix: {})", import.module_name, import.prefix)?;
            if let Some(rev) = &import.revision_date {
                write!(f, " @ {rev}")?;
            }
            writeln!(f)?;
        }
        writeln!(f, "\nIncludes ({}):", self.includes.len())?;
        for include in &self.includes {
            write!(f, "  - {}", include.submodule_name)?;
            if let Some(rev) = &include.revision_date {
                write!(f, " @ {rev}")?;
            }
            writeln!(f)?;
        }
        Ok(())
    }
}

/// Extract import and include statements from a YANG schema string
pub fn extract_yang_dependencies(yang_content: &str) -> Result<YangDependencies, String> {
    let mut parser = YangParser::new(yang_content);
    parser.parse()
}

/// Extract module metadata from a YANG schema string (without dependencies)
pub fn extract_yang_metadata(yang_content: &str) -> Result<YangModuleMetadata, String> {
    let mut parser = YangParser::new(yang_content);
    parser.parse_metadata()
}

struct YangParser<'a> {
    content: &'a str,
    position: usize,
}

impl<'a> YangParser<'a> {
    fn new(content: &'a str) -> Self {
        Self {
            content,
            position: 0,
        }
    }

    /// Parse module metadata (name, namespace, prefix, revision)
    fn parse_metadata(&mut self) -> Result<YangModuleMetadata, String> {
        let mut module_name = None;
        let mut namespace = None;
        let mut prefix = None;
        let mut revision = None;
        let mut is_submodule_of = None;

        while !self.is_eof() {
            self.skip_whitespace_and_comments();

            if self.is_eof() {
                break;
            }

            if self.match_keyword("module") {
                self.skip_whitespace_and_comments();
                module_name = Some(
                    self.read_string_or_identifier()
                        .ok_or("Expected module name")?,
                );
                self.skip_whitespace_and_comments();
                self.expect_char('{')?;
            } else if self.match_keyword("submodule") {
                self.skip_whitespace_and_comments();
                module_name = Some(
                    self.read_string_or_identifier()
                        .ok_or("Expected submodule name")?,
                );
                self.skip_whitespace_and_comments();
                self.expect_char('{')?;
            } else if self.match_keyword("belongs-to") {
                // Only in submodules
                self.skip_whitespace_and_comments();
                is_submodule_of = Some(
                    self.read_string_or_identifier()
                        .ok_or("Expected parent module name")?,
                );
                // Skip the rest of belongs-to statement (prefix declaration)
                self.skip_statement();
            } else if self.match_keyword("namespace") {
                self.skip_whitespace_and_comments();
                namespace = Some(
                    self.read_string_or_identifier()
                        .ok_or("Expected namespace value")?,
                );
                self.skip_whitespace_and_comments();
                self.expect_char(';')?;
            } else if self.match_keyword("prefix") {
                // Only capture the first module-level prefix
                if prefix.is_none() {
                    self.skip_whitespace_and_comments();
                    prefix = Some(
                        self.read_string_or_identifier()
                            .ok_or("Expected prefix value")?,
                    );
                    self.skip_whitespace_and_comments();
                    self.expect_char(';')?;
                } else {
                    // Skip prefix statements inside import blocks
                    self.skip_statement();
                }
            } else if self.match_keyword("yang-version") {
                self.skip_whitespace_and_comments();
                self.read_string_or_identifier();
                self.skip_whitespace_and_comments();
                self.expect_char(';')?;
            } else if self.match_keyword("revision") {
                self.skip_whitespace_and_comments();
                let rev = self
                    .read_string_or_identifier()
                    .ok_or("Expected revision date")?;
                // Only keep the first (latest) revision
                if revision.is_none() {
                    revision = Some(rev);
                }
                // Skip the revision body
                self.skip_whitespace_and_comments();
                if self.peek_char() == Some('{') {
                    self.skip_statement();
                } else {
                    self.expect_char(';')?;
                }
            } else if self.match_keyword("container")
                || self.match_keyword("list")
                || self.match_keyword("leaf")
                || self.match_keyword("grouping")
                || self.match_keyword("typedef")
                || self.match_keyword("identity")
                || self.match_keyword("augment")
                || self.match_keyword("rpc")
                || self.match_keyword("notification")
            {
                // Once we hit data definition statements, we can stop
                break;
            } else {
                // Skip other statements
                self.skip_one_token();
            }
        }

        let name = module_name.ok_or("Module/submodule name not found")?;

        Ok(YangModuleMetadata {
            name,
            namespace,
            prefix,
            revision,
            is_submodule_of,
        })
    }

    /// Parse YangDependencies
    fn parse(&mut self) -> Result<YangDependencies, String> {
        let mut imports = Vec::new();
        let mut includes = Vec::new();

        while !self.is_eof() {
            self.skip_whitespace_and_comments();

            if self.is_eof() {
                break;
            }

            // Try to match keywords
            if self.match_keyword("import") {
                imports.push(self.parse_import()?);
            } else if self.match_keyword("include") {
                includes.push(self.parse_include()?);
            } else if self.match_keyword("organization")
                || self.match_keyword("contact")
                || self.match_keyword("description")
                || self.match_keyword("reference")
            {
                // once we reach the meta-stmt we can stop parsing for imports/includes
                // since they are not allowed in meta-stmts or any statement after them.
                break;
            } else {
                // Skip one token at a time instead of entire statements
                self.skip_one_token();
            }
        }

        Ok(YangDependencies { imports, includes })
    }

    fn parse_import(&mut self) -> Result<YangImport, String> {
        self.skip_whitespace_and_comments();

        let module_name = self
            .read_string_or_identifier()
            .ok_or("Expected module name after 'import'")?;

        self.skip_whitespace_and_comments();
        self.expect_char('{')?;

        let mut prefix = None;
        let mut revision_date = None;

        // Parse the body of the import statement
        loop {
            self.skip_whitespace_and_comments();

            if self.peek_char() == Some('}') {
                self.advance();
                break;
            }

            if self.match_keyword("prefix") {
                self.skip_whitespace_and_comments();
                prefix = Some(
                    self.read_string_or_identifier()
                        .ok_or("Expected prefix value")?,
                );
                self.skip_whitespace_and_comments();
                self.expect_char(';')?;
            } else if self.match_keyword("revision-date") {
                self.skip_whitespace_and_comments();
                revision_date = Some(
                    self.read_string_or_identifier()
                        .ok_or("Expected revision-date value")?,
                );
                self.skip_whitespace_and_comments();
                self.expect_char(';')?;
            } else {
                // Skip unknown statements within import
                self.skip_statement();
            }
        }

        let prefix = prefix.ok_or("Missing required 'prefix' in import statement")?;

        Ok(YangImport {
            module_name,
            prefix,
            revision_date,
        })
    }

    fn parse_include(&mut self) -> Result<YangInclude, String> {
        self.skip_whitespace_and_comments();

        let submodule_name = self
            .read_string_or_identifier()
            .ok_or("Expected submodule name after 'include'")?;

        self.skip_whitespace_and_comments();

        let mut revision_date = None;

        // Include can be followed by either ';' or '{ ... }'
        match self.peek_char() {
            Some(';') => {
                self.advance();
            }
            Some('{') => {
                self.advance();

                loop {
                    self.skip_whitespace_and_comments();

                    if self.peek_char() == Some('}') {
                        self.advance();
                        break;
                    }

                    if self.match_keyword("revision-date") {
                        self.skip_whitespace_and_comments();
                        revision_date = Some(
                            self.read_string_or_identifier()
                                .ok_or("Expected revision-date value")?,
                        );
                        self.skip_whitespace_and_comments();
                        self.expect_char(';')?;
                    } else {
                        self.skip_statement();
                    }
                }
            }
            _ => return Err("Expected ';' or '{' after include statement".to_string()),
        }

        Ok(YangInclude {
            submodule_name,
            revision_date,
        })
    }

    fn skip_whitespace_and_comments(&mut self) {
        loop {
            // Skip whitespace
            while self.peek_char().is_some_and(|c| c.is_whitespace()) {
                self.advance();
            }

            // Skip comments
            if self.peek_chars(2) == Some("//") {
                // Line comment
                while self.peek_char().is_some_and(|c| c != '\n') {
                    self.advance();
                }
            } else if self.peek_chars(2) == Some("/*") {
                // Block comment
                self.advance_by(2);
                while self.peek_chars(2) != Some("*/") && !self.is_eof() {
                    self.advance();
                }
                if !self.is_eof() {
                    self.advance_by(2);
                }
            } else {
                break;
            }
        }
    }

    fn match_keyword(&mut self, keyword: &str) -> bool {
        let start = self.position;

        if let Some(ident) = self.peek_identifier()
            && ident == keyword
        {
            self.position += keyword.len();
            // Make sure it's followed by whitespace or separator
            if let Some(c) = self.peek_char() {
                if c.is_whitespace() || c == '{' || c == ';' || c == '"' || c == '\'' {
                    return true;
                }
            } else {
                return true; // EOF
            }
        }

        self.position = start;
        false
    }

    fn read_identifier(&mut self) -> Option<String> {
        let start = self.position;

        // YANG identifier: [a-zA-Z_][a-zA-Z0-9_.-]*
        // But dates are also read as identifiers: YYYY-MM-DD
        if let Some(c) = self.peek_char() {
            if c.is_alphabetic() || c == '_' {
                self.advance();
            } else if c.is_numeric() {
                // Allow starting with digit for dates like 2013-07-15
                self.advance();
            } else {
                return None;
            }
        } else {
            return None;
        }

        while let Some(c) = self.peek_char() {
            if c.is_alphanumeric() || c == '_' || c == '-' || c == '.' || c == ':' {
                self.advance();
            } else {
                break;
            }
        }

        Some(self.content[start..self.position].to_string())
    }

    fn peek_identifier(&self) -> Option<String> {
        let start = self.position;

        if start >= self.content.len() {
            return None;
        }

        let bytes = self.content.as_bytes();
        let first = bytes[start] as char;

        if !first.is_alphabetic() && first != '_' {
            return None;
        }

        let mut end = start + 1;
        while end < bytes.len() {
            let c = bytes[end] as char;
            if c.is_alphanumeric() || c == '_' || c == '-' || c == '.' {
                end += 1;
            } else {
                break;
            }
        }

        Some(self.content[start..end].to_string())
    }

    fn read_string_or_identifier(&mut self) -> Option<String> {
        self.skip_whitespace_and_comments();

        let mut result = match self.peek_char()? {
            '"' => self.read_double_quoted_string()?,
            '\'' => self.read_single_quoted_string()?,
            _ => return self.read_identifier(),
        };

        loop {
            self.skip_whitespace_and_comments();
            if self.peek_char() == Some('+') {
                self.advance(); // handle string concatenation (+)
                self.skip_whitespace_and_comments();
                match self.peek_char() {
                    Some('"') => {
                        if let Some(next_part) = self.read_double_quoted_string() {
                            result.push_str(&next_part);
                        }
                    }
                    Some('\'') => {
                        if let Some(next_part) = self.read_single_quoted_string() {
                            result.push_str(&next_part);
                        }
                    }
                    _ => break,
                }
            } else {
                break;
            }
        }

        Some(result)
    }

    fn read_double_quoted_string(&mut self) -> Option<String> {
        if self.peek_char()? != '"' {
            return None;
        }
        self.advance(); // Skip opening "

        let mut result = String::new();

        while let Some(c) = self.peek_char() {
            if c == '"' {
                self.advance();
                return Some(result);
            } else if c == '\\' {
                self.advance();
                if let Some(escaped) = self.peek_char() {
                    result.push(match escaped {
                        'n' => '\n',
                        't' => '\t',
                        '"' => '"',
                        '\\' => '\\',
                        _ => escaped,
                    });
                    self.advance();
                }
            } else {
                result.push(c);
                self.advance();
            }
        }

        None // Unterminated string
    }

    fn read_single_quoted_string(&mut self) -> Option<String> {
        if self.peek_char()? != '\'' {
            return None;
        }
        self.advance(); // Skip opening '

        let mut result = String::new();

        while let Some(c) = self.peek_char() {
            if c == '\'' {
                self.advance();
                return Some(result);
            } else {
                result.push(c);
                self.advance();
            }
        }

        None // Unterminated string
    }

    /// Skip one token - either an identifier, string, or single character
    fn skip_one_token(&mut self) {
        match self.peek_char() {
            Some('"') => {
                self.read_double_quoted_string();
            }
            Some('\'') => {
                self.read_single_quoted_string();
            }
            Some(c) if c.is_alphabetic() || c == '_' => {
                self.read_identifier();
            }
            Some('{') => {
                // Opening brace - just skip it, we'll process contents
                self.advance();
            }
            Some('}') => {
                // Closing brace - skip it
                self.advance();
            }
            Some(';') => {
                // Semicolon - skip it
                self.advance();
            }
            Some(_) => {
                // Any other character - just skip it
                self.advance();
            }
            None => {}
        }
    }

    fn skip_statement(&mut self) {
        // Skip to the end of a statement (semicolon or balanced braces)
        let mut brace_depth = 0;
        let mut in_string = false;
        let mut string_char = ' ';

        while !self.is_eof() {
            if in_string {
                if let Some(c) = self.peek_char() {
                    if c == string_char
                        && self.position > 0
                        && self.content.as_bytes()[self.position - 1] != b'\\'
                    {
                        in_string = false;
                    }
                    self.advance();
                }
            } else {
                self.skip_whitespace_and_comments();

                if let Some(c) = self.peek_char() {
                    match c {
                        '"' | '\'' => {
                            in_string = true;
                            string_char = c;
                            self.advance();
                        }
                        '{' => {
                            brace_depth += 1;
                            self.advance();
                        }
                        '}' => {
                            if brace_depth > 0 {
                                brace_depth -= 1;
                                self.advance();
                                if brace_depth == 0 {
                                    return;
                                }
                            } else {
                                return;
                            }
                        }
                        ';' => {
                            self.advance();
                            if brace_depth == 0 {
                                return;
                            }
                        }
                        _ => {
                            self.advance();
                        }
                    }
                }
            }
        }
    }

    fn expect_char(&mut self, expected: char) -> Result<(), String> {
        self.skip_whitespace_and_comments();

        match self.peek_char() {
            Some(c) if c == expected => {
                self.advance();
                Ok(())
            }
            Some(c) => Err(format!(
                "Expected '{expected}', found '{c}' at position: {}",
                self.position
            )),
            None => Err(format!("Expected '{expected}', found EOF")),
        }
    }

    fn peek_char(&self) -> Option<char> {
        self.content[self.position..].chars().next()
    }

    fn peek_chars(&self, n: usize) -> Option<&str> {
        if self.position + n <= self.content.len() {
            let start = self.position;
            let mut end = self.position;
            for _ in 0..n {
                // safe increment by char boundary
                end += 1;
                while end < self.content.len() && !self.content.is_char_boundary(end) {
                    end += 1;
                }
            }
            Some(&self.content[start..end])
        } else {
            None
        }
    }

    fn advance(&mut self) {
        self.position += 1;
        while self.position < self.content.len() && !self.content.is_char_boundary(self.position) {
            self.position += 1;
        }
    }

    fn advance_by(&mut self, n: usize) {
        for _ in 0..n {
            self.advance();
        }
    }

    fn is_eof(&self) -> bool {
        self.position >= self.content.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_import() {
        let yang = r#"
            module example {
                import ietf-inet-types {
                    prefix inet;
                }
            }
        "#;

        let deps = extract_yang_dependencies(yang).unwrap();
        assert_eq!(deps.imports.len(), 1);
        assert_eq!(deps.imports[0].module_name, "ietf-inet-types");
        assert_eq!(deps.imports[0].prefix, "inet");
        assert_eq!(deps.imports[0].revision_date, None);
    }

    #[test]
    fn test_import_with_revision() {
        let yang = r#"
            module example {
                import ietf-yang-types {
                    prefix yang;
                    revision-date 2013-07-15;
                }
            }
        "#;

        let deps = extract_yang_dependencies(yang).unwrap();
        assert_eq!(deps.imports.len(), 1);
        assert_eq!(deps.imports[0].module_name, "ietf-yang-types");
        assert_eq!(deps.imports[0].prefix, "yang");
        assert_eq!(
            deps.imports[0].revision_date,
            Some("2013-07-15".to_string())
        );
    }

    #[test]
    fn test_multiple_imports() {
        let yang = r#"
            module example {
                import ietf-inet-types {
                    prefix inet;
                }
                import ietf-yang-types {
                    prefix yang;
                    revision-date 2013-07-15;
                }
            }
        "#;

        let deps = extract_yang_dependencies(yang).unwrap();
        assert_eq!(deps.imports.len(), 2);
    }

    #[test]
    fn test_include_without_revision() {
        let yang = r#"
            module example {
                include example-submodule;
            }
        "#;

        let deps = extract_yang_dependencies(yang).unwrap();
        assert_eq!(deps.includes.len(), 1);
        assert_eq!(deps.includes[0].submodule_name, "example-submodule");
        assert_eq!(deps.includes[0].revision_date, None);
    }

    #[test]
    fn test_include_with_revision() {
        let yang = r#"
            module example {
                include example-submodule {
                    revision-date 2023-01-01;
                }
            }
        "#;

        let deps = extract_yang_dependencies(yang).unwrap();
        assert_eq!(deps.includes.len(), 1);
        assert_eq!(deps.includes[0].submodule_name, "example-submodule");
        assert_eq!(
            deps.includes[0].revision_date,
            Some("2023-01-01".to_string())
        );
    }

    #[test]
    fn test_with_comments() {
        let yang = r#"
            module example {
                // This is a comment
                import ietf-inet-types {
                    prefix inet; // inline comment
                }
                /* Block comment
                   across multiple lines */
                include example-submodule;
            }
        "#;

        let deps = extract_yang_dependencies(yang).unwrap();
        assert_eq!(deps.imports.len(), 1);
        assert_eq!(deps.includes.len(), 1);
    }

    #[test]
    fn test_quoted_strings() {
        let yang = r#"
            module example {
                import "ietf-inet-types" {
                    prefix "inet";
                }
            }
        "#;

        let deps = extract_yang_dependencies(yang).unwrap();
        assert_eq!(deps.imports.len(), 1);
        assert_eq!(deps.imports[0].module_name, "ietf-inet-types");
        assert_eq!(deps.imports[0].prefix, "inet");
    }

    #[test]
    fn test_complex_yang() {
        let yang = r#"
            module ietf-network-instance {
                namespace "urn:ietf:params:xml:ns:yang:ietf-network-instance";
                prefix ni;

                // Some comment

                import ietf-interfaces {
                    prefix if;
                }

                /*
                    Another comment
                */
                import ietf-ip {
                    prefix ip;
                    revision-date 2014-06-16;
                }

                include network-instance-types;
                include network-instance-policy {
                    revision-date 2023-05-01;
                }

                container network-instances {
                    list network-instance {
                        key name;
                        leaf name {
                            type string;
                        }
                    }
                }
            }
        "#;

        let deps = extract_yang_dependencies(yang).unwrap();
        assert_eq!(deps.imports.len(), 2);
        assert_eq!(deps.includes.len(), 2);

        assert_eq!(deps.imports[0].module_name, "ietf-interfaces");
        assert_eq!(deps.imports[1].module_name, "ietf-ip");
        assert_eq!(
            deps.imports[1].revision_date,
            Some("2014-06-16".to_string())
        );

        assert_eq!(deps.includes[0].submodule_name, "network-instance-types");
        assert_eq!(deps.includes[1].submodule_name, "network-instance-policy");
        assert_eq!(
            deps.includes[1].revision_date,
            Some("2023-05-01".to_string())
        );
    }

    #[test]
    fn test_extract_metadata_only() {
        let yang = r#"
            module ietf-yp-observation {
              yang-version 1.1;
              namespace "urn:ietf:params:xml:ns:yang:ietf-yp-observation";
              prefix ypot;

              import ietf-yang-types {
                prefix yang;
              }

              organization "IETF NETCONF Working Group";

              revision 2025-02-24 {
                description "First revision";
              }
            }
        "#;

        let metadata = extract_yang_metadata(yang).unwrap();
        assert_eq!(metadata.name, "ietf-yp-observation");
        assert_eq!(
            metadata.namespace,
            Some("urn:ietf:params:xml:ns:yang:ietf-yp-observation".to_string())
        );
        assert_eq!(metadata.prefix, Some("ypot".to_string()));
        assert_eq!(metadata.revision, Some("2025-02-24".to_string()));
    }

    #[test]
    fn test_metadata_with_imports() {
        let yang = r#"
            module test {
              namespace "urn:test";
              prefix test;

              import other {
                prefix other;
              }

              revision 2025-01-01 {
                description "Latest";
              }
            }
        "#;

        let metadata = extract_yang_metadata(yang).unwrap();
        assert_eq!(metadata.name, "test");
        assert_eq!(metadata.prefix, Some("test".to_string()));
        // Should not be confused by the prefix inside import
    }

    #[test]
    fn test_concatenated_double_quoted_strings() {
        let yang = r#"
            module example {
                import "ietf" + "-inet-types" {
                    prefix "inet";
                }
            }
        "#;

        let deps = extract_yang_dependencies(yang).unwrap();
        assert_eq!(deps.imports.len(), 1);
        assert_eq!(deps.imports[0].module_name, "ietf-inet-types");
        assert_eq!(deps.imports[0].prefix, "inet");
    }

    #[test]
    fn test_concatenated_single_quoted_strings() {
        let yang = r#"
            module example {
                import 'ietf'
                  + '-inet-types' {
                    prefix 'inet';
                }
            }
        "#;

        let deps = extract_yang_dependencies(yang).unwrap();
        assert_eq!(deps.imports.len(), 1);
        assert_eq!(deps.imports[0].module_name, "ietf-inet-types");
        assert_eq!(deps.imports[0].prefix, "inet");
    }

    #[test]
    fn test_multiple_concatenations() {
        let yang = r#"
            module example {
                import "ietf" + "-inet" + "-types" {
                    prefix "inet";
                }
            }
        "#;

        let deps = extract_yang_dependencies(yang).unwrap();
        assert_eq!(deps.imports.len(), 1);
        assert_eq!(deps.imports[0].module_name, "ietf-inet-types");
    }

    #[test]
    fn test_concatenation_with_spaces() {
        let yang = r#"
            module example {
                import "ietf" + " inet-types" {
                    prefix "inet";
                }
            }
        "#;

        let deps = extract_yang_dependencies(yang).unwrap();
        assert_eq!(deps.imports.len(), 1);
        assert_eq!(deps.imports[0].module_name, "ietf inet-types");
    }

    #[test]
    fn test_concatenation_in_include() {
        let yang = r#"
            module example {
                include "example" + "-submodule" {
                    revision-date 2023-01-01;
                }
            }
        "#;

        let deps = extract_yang_dependencies(yang).unwrap();
        assert_eq!(deps.includes.len(), 1);
        assert_eq!(deps.includes[0].submodule_name, "example-submodule");
        assert_eq!(
            deps.includes[0].revision_date,
            Some("2023-01-01".to_string())
        );
    }

    #[test]
    fn test_concatenation_in_metadata_namespace() {
        let yang = r#"
            module example {
                namespace "urn:ietf:params:xml:ns:yang:" + "ietf-example";
                prefix ex;
            }
        "#;

        let metadata = extract_yang_metadata(yang).unwrap();
        assert_eq!(metadata.name, "example");
        assert_eq!(
            metadata.namespace,
            Some("urn:ietf:params:xml:ns:yang:ietf-example".to_string())
        );
    }

    #[test]
    fn test_no_concatenation_for_identifiers() {
        // Ensure identifiers are not concatenated
        let yang = r#"
            module example {
                import ietf-inet-types {
                    prefix inet;
                }
            }
        "#;

        let deps = extract_yang_dependencies(yang).unwrap();
        assert_eq!(deps.imports.len(), 1);
        assert_eq!(deps.imports[0].module_name, "ietf-inet-types");
    }

    #[test]
    fn test_real_cisco_module_with_concatenation() {
        let yang = r#"
            module Cisco-IOS-XR-openconfig-platform-transceiver-ext{

              namespace "http://cisco.com/ns/yang/"+
                    "Cisco-IOS-XR-openconfig-platform-transceiver-ext";

              prefix oc-opt-trans-ext;

              import ietf-yang-types {
                prefix yang;
                }

              import openconfig-platform {
                      prefix oc-platform;
                }
               import openconfig-platform-transceiver {
                      prefix oc-transceiver;
                }

                import openconfig-platform-types {
                       prefix oc-platform-types;
                }

               organization "Cisco Systems, Inc.";

               contact
                "Cisco Systems, Inc.
                 Customer Service

                 Postal: 170 West Tasman Drive
                 San Jose, CA 95134

                 Tel: +1 800 553-NETS

                 E-mail: cs-yang@cisco.com";

                description
               "This module is an extension of optical transceiver model
                 and contains the definition of extended parameters for Physical
                 Channels in order to add the support of per lane FEC configuration and Performance monitoring.

                 This module contains definitions for the following management objects:
                 FEC Parameters

                 Copyright (c) 2023-2024 by Cisco Systems, Inc.
                 All rights reserved.";

             revision 2023-01-30 {
                  description
                      "Initial version of oc transceiver extended model";
                  reference "0.1.0";
              }

             grouping  transceiver-physical-channel-ext-info {
                 description "FEC parameters for physical channel";
                 leaf fec-mode {
                     type identityref {
                            base oc-platform-types:FEC_MODE_TYPE;
                      }
                      description
                        "The FEC mode indicates the mode of operation for the
                         transceiver's physical channel's FEC. This defines typical operational modes
                         and does not aim to specify more granular FEC capabilities.";
                 }

                 leaf fec-uncorrectable-words {
                     type yang:counter64;
                     description
                         "The number of words that were uncorrectable by the FEC";
                 }
                 leaf fec-corrected-words {
                      type yang:counter64;
                      description
                        "The number of words that were corrected by the FEC";
                 }
            }


            augment "/oc-platform:components/oc-platform:component/oc-transceiver:transceiver/oc-transceiver:physical-channels/oc-transceiver:channel" {
                container extended {
                    description
                        "Enclosing container for the state fec parameters for extended model";

                    container state {

                        config false;

                        description
                            "Extended Operational parameters";
                        leaf index {
                               type uint16 {
                             range 0..max;
                               }
                               description
                                "Index of the physical channnel or lane within a physical
                                client port";
                        }
                        uses transceiver-physical-channel-ext-info;
                    }
                }
                description
                   "This augment extends the operational data of
                   'oc-transceiver:physical-channel-top'";

                }
            }
        "#;

        // Test metadata extraction
        let metadata = extract_yang_metadata(yang).unwrap();
        let expected_metadata = YangModuleMetadata {
            name: "Cisco-IOS-XR-openconfig-platform-transceiver-ext".to_string(),
            namespace: Some(
                "http://cisco.com/ns/yang/Cisco-IOS-XR-openconfig-platform-transceiver-ext"
                    .to_string(),
            ),
            prefix: Some("oc-opt-trans-ext".to_string()),
            revision: Some("2023-01-30".to_string()),
            is_submodule_of: None,
        };
        assert_eq!(metadata, expected_metadata);

        // Test dependencies extraction
        let deps = extract_yang_dependencies(yang).unwrap();
        let expected_deps = YangDependencies {
            imports: vec![
                YangImport {
                    module_name: "ietf-yang-types".to_string(),
                    prefix: "yang".to_string(),
                    revision_date: None,
                },
                YangImport {
                    module_name: "openconfig-platform".to_string(),
                    prefix: "oc-platform".to_string(),
                    revision_date: None,
                },
                YangImport {
                    module_name: "openconfig-platform-transceiver".to_string(),
                    prefix: "oc-transceiver".to_string(),
                    revision_date: None,
                },
                YangImport {
                    module_name: "openconfig-platform-types".to_string(),
                    prefix: "oc-platform-types".to_string(),
                    revision_date: None,
                },
            ],
            includes: vec![],
        };
        assert_eq!(deps, expected_deps);
    }

    #[test]
    fn test_real_bbf_submodule() {
        let yang = r#"
            submodule bbf-xpongemtcont-traffic-descriptor-profile-body {
              yang-version 1.1;
              belongs-to bbf-xpongemtcont {
                prefix bbf-xpongemtcont;
              }

              include "bbf-xpongemtcont-base";

              organization "Broadband Forum";

              contact "info@broadband-forum.org";

              revision 2020-10-13 {
                description "Issue 2.";
                reference "TR-385i2";
              }
              revision 2019-02-25 {
                description "Initial revision.";
                reference "TR-385";
              }

              grouping traffic-descriptor-profile-data {
                description "Traffic descriptor profile data.";
                list traffic-descriptor-profile {
                  key "name";
                  leaf name {
                    type string;
                  }
                  leaf fixed-bandwidth {
                    type uint64;
                    units "bits/second";
                    default "0";
                  }
                  leaf assured-bandwidth {
                    type uint64;
                    units "bits/second";
                    default "0";
                  }
                  leaf maximum-bandwidth {
                    type uint64;
                    units "bits/second";
                    mandatory true;
                  }
                  leaf priority {
                    type uint8 {
                      range "1..8";
                    }
                  }
                  leaf weight {
                    type uint8;
                  }
                  leaf additional-bw-eligibility-indicator {
                    type enumeration {
                      enum "non-assured-sharing";
                      enum "best-effort-sharing";
                      enum "none";
                    }
                  }
                }
              }

              augment "/bbf-xpongemtcont:xpongemtcont" {
                container traffic-descriptor-profiles {
                  uses traffic-descriptor-profile-data;
                }
              }
            }
        "#;

        // Test metadata extraction
        let metadata = extract_yang_metadata(yang).unwrap();
        let expected_metadata = YangModuleMetadata {
            name: "bbf-xpongemtcont-traffic-descriptor-profile-body".to_string(),
            namespace: None,
            prefix: None,
            revision: Some("2020-10-13".to_string()),
            is_submodule_of: Some("bbf-xpongemtcont".to_string()),
        };
        assert_eq!(metadata, expected_metadata);

        // Test dependencies extraction
        let deps = extract_yang_dependencies(yang).unwrap();
        let expected_deps = YangDependencies {
            imports: vec![],
            includes: vec![YangInclude {
                submodule_name: "bbf-xpongemtcont-base".to_string(),
                revision_date: None,
            }],
        };
        assert_eq!(deps, expected_deps);
    }
}
