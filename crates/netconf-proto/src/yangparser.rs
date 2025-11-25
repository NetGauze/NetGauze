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

        if let Some(ident) = self.peek_identifier() {
            if ident == keyword {
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

        match self.peek_char()? {
            '"' => self.read_double_quoted_string(),
            '\'' => self.read_single_quoted_string(),
            _ => self.read_identifier(),
        }
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
}
