// SPDX-License-Identifier: Apache-2.0

//! Destination host names. An upstream is named by a DNS name and nothing else.
//!
//! Address literals are refused in every spelling resolvers and URL parsers accept: dotted,
//! decimal (`2130706433`), hexadecimal (`0x7f000001`), octal (`0177.0.0.1`), shortened
//! (`127.1`) and bracketed IPv6. Following the WHATWG URL rule, a name whose last label is a
//! number is an IPv4 address in disguise. An upstream that must reach a fixed address declares
//! it separately ([`crate::Upstream::pinned`]), where it is classified like any resolved one.

use std::fmt;

/// Maximum length of a DNS name in presentation form, without the trailing dot.
const MAX_NAME: usize = 253;
/// Maximum length of one label.
const MAX_LABEL: usize = 63;

/// A validated DNS host name: lowercase ASCII letters, digits, hyphens and dots.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostName(String);

/// Why a host name was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HostError {
    /// Empty, or longer than 253 characters.
    #[error("host name is empty or longer than 253 characters")]
    Length,
    /// A label is empty, longer than 63 characters, or starts or ends with a hyphen.
    #[error("a host name label is empty, too long, or starts or ends with a hyphen")]
    Label,
    /// A character other than ASCII letters, digits, `-` and `.`.
    #[error("host name contains a character other than a-z, 0-9, '-' and '.'")]
    Character,
    /// An address literal in some spelling.
    #[error("host name is an address literal; declare fixed addresses as pinned addresses instead")]
    Numeric,
}

impl HostName {
    /// Validates and lowercases `raw`. One trailing dot (an absolute name) is accepted.
    ///
    /// # Errors
    /// [`HostError`] naming the first rule `raw` breaks.
    pub fn parse(raw: &str) -> Result<Self, HostError> {
        let name = raw.strip_suffix('.').unwrap_or(raw).to_ascii_lowercase();
        if name.is_empty() || name.len() > MAX_NAME {
            return Err(HostError::Length);
        }
        if !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        {
            return Err(HostError::Character);
        }
        for label in name.split('.') {
            if label.is_empty() || label.len() > MAX_LABEL || label.starts_with('-') || label.ends_with('-') {
                return Err(HostError::Label);
            }
        }
        if name.rsplit('.').next().is_some_and(is_numeric_label) {
            return Err(HostError::Numeric);
        }
        Ok(Self(name))
    }

    /// The name, lowercase.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HostName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A label an IPv4 parser would read as a number: decimal (octal with a leading zero) or hex.
fn is_numeric_label(label: &str) -> bool {
    let hex = label
        .strip_prefix("0x")
        .is_some_and(|rest| rest.bytes().all(|b| b.is_ascii_hexdigit()));
    hex || (!label.is_empty() && label.bytes().all(|b| b.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_names_are_accepted_and_lowercased() {
        for (raw, want) in [
            ("api.anthropic.com", "api.anthropic.com"),
            ("API.OpenAI.com.", "api.openai.com"),
            ("xn--n3h.example", "xn--n3h.example"),
            ("localhost", "localhost"),
            ("mock.provider.test", "mock.provider.test"),
            ("1password.com", "1password.com"),
        ] {
            assert_eq!(HostName::parse(raw).unwrap().as_str(), want, "{raw}");
        }
    }

    #[test]
    fn address_literals_are_refused_in_every_spelling() {
        for raw in [
            "127.0.0.1",
            "2130706433",
            "0x7f000001",
            "0177.0.0.1",
            "127.1",
            "169.254.169.254",
            "0x7f.0.0.1",
            "evil.com.127",
            "evil.0x7f",
        ] {
            assert_eq!(
                HostName::parse(raw),
                Err(HostError::Numeric),
                "{raw} was accepted as a host name"
            );
        }
        for raw in [
            "[::1]",
            "::1",
            "fe80::1%eth0",
            "user@host",
            "host:443",
            "exa mple.com",
            "bücher.de",
        ] {
            assert_eq!(HostName::parse(raw), Err(HostError::Character), "{raw}");
        }
    }

    #[test]
    fn malformed_names_are_refused() {
        assert_eq!(HostName::parse(""), Err(HostError::Length));
        assert_eq!(HostName::parse(&"a".repeat(254)), Err(HostError::Length));
        assert_eq!(HostName::parse("a..b"), Err(HostError::Label));
        assert_eq!(HostName::parse("-a.com"), Err(HostError::Label));
        assert_eq!(HostName::parse("a-.com"), Err(HostError::Label));
        assert_eq!(
            HostName::parse(&format!("{}.com", "a".repeat(64))),
            Err(HostError::Label)
        );
    }
}
