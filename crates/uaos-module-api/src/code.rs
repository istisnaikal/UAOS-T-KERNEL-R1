// SPDX-License-Identifier: Apache-2.0

//! Declared codes: the only words a module may put into a declaration, an event or a label. A code
//! is an identifier the manifest lists, so nothing a module says can smuggle payload into a log or
//! an event.

use std::fmt;

/// The longest code, in bytes.
pub const MAX_CODE_LEN: usize = 32;

/// A declared code: `[a-z][a-z0-9_]{1,31}`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Code(String);

/// A code that is not `[a-z][a-z0-9_]{1,31}`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("a code is a lowercase letter followed by 1 to 31 lowercase letters, digits or underscores")]
pub struct CodeError;

impl Code {
    /// Validates and wraps a code.
    ///
    /// # Errors
    /// [`CodeError`] unless `code` is `[a-z][a-z0-9_]{1,31}`.
    pub fn new(code: impl Into<String>) -> Result<Self, CodeError> {
        let code = code.into();
        let mut bytes = code.bytes();
        let ok = (2..=MAX_CODE_LEN).contains(&code.len())
            && bytes.next().is_some_and(|b| b.is_ascii_lowercase())
            && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if ok { Ok(Self(code)) } else { Err(CodeError) }
    }

    /// The code.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Code {
    // A code is a declared identifier, never content, so it may be shown.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Code({})", self.0)
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
