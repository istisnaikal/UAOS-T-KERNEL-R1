// SPDX-License-Identifier: Apache-2.0

//! Detector sets: high-confidence secret formats.
//!
//! An Aho–Corasick search finds every anchor literal (`sk-ant-`, `AKIA`, `-----BEGIN `, …),
//! including anchors that overlap another anchor's literal. A per-format validator then confirms
//! the candidate. Overlapping detections merge into one span carrying the most specific class.
//!
//! Boundaries fail closed:
//! * an anchor glued on its left to an **alphanumeric** byte sits inside a longer token and is
//!   not reported; any other left neighbour (`_`, `-`, `$`, `:` …) is a separator;
//! * a format's body is the **whole** run of its characters: a run longer than the format
//!   allows, or one glued to more of the same characters, is covered whole, never skipped.
//!
//! Anchors inside a run or a private-key block already examined reuse that work, so a scan is
//! linear in its input with a bounded constant.
//!
//! A detector set is versioned as a whole and pinned per session: the bytes a session sends must
//! not change under it. Changing any rule below requires a new version once a release has shipped
//! the set.

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Range;

use aho_corasick::{AhoCorasick, Input, MatchKind};
use memchr::memmem;

use crate::RedactError;
use crate::class::DataClass;

/// A pinned detector set version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DetectorVersion(pub u16);

impl DetectorVersion {
    /// Detector set v1: 11 classes, measured by synthetic corpus v2.
    pub const V1: Self = Self(1);
    /// The version new sessions pin.
    pub const CURRENT: Self = Self::V1;
}

/// A detected secret: its class and byte range in the scanned text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The class.
    pub class: DataClass,
    /// Byte range in the scanned text.
    pub range: Range<usize>,
}

/// Placeholders start with this; no detector may match a placeholder (redaction is idempotent).
pub const PLACEHOLDER_PREFIX: &[u8] = b"[REDACTED:";
/// Hex digits in a placeholder's tag (64 bits).
pub(crate) const PLACEHOLDER_TAG_HEX: usize = 16;

/// Whether `bytes` is exactly one placeholder, `[REDACTED:<class>:<16 lowercase hex>]` with a class
/// this build knows. Anything looser would let crafted text pass as redacted.
#[must_use]
pub(crate) fn is_placeholder(bytes: &[u8]) -> bool {
    let Some(inner) = bytes
        .strip_prefix(PLACEHOLDER_PREFIX)
        .and_then(|b| b.strip_suffix(b"]"))
    else {
        return false;
    };
    let Some((class, tag)) = memchr::memchr(b':', inner).map(|at| inner.split_at(at)) else {
        return false;
    };
    let tag = tag.get(1..).unwrap_or_default();
    DataClass::ALL.iter().any(|c| c.as_str().as_bytes() == class)
        && tag.len() == PLACEHOLDER_TAG_HEX
        && tag.iter().all(|&b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The byte sets a format's body is made of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Chars {
    /// `[A-Za-z0-9]`
    Alnum,
    /// `[A-Za-z0-9_]`
    Word,
    /// `[A-Za-z0-9_-]`
    Token,
    /// `[A-Z0-9]`
    UpperDigit,
    /// `[A-Za-z0-9-]`
    AlnumDash,
    /// `[A-Za-z0-9/]`
    Path,
}

impl Chars {
    fn has(self, b: u8) -> bool {
        match self {
            Self::Alnum => b.is_ascii_alphanumeric(),
            Self::Word => b.is_ascii_alphanumeric() || b == b'_',
            Self::Token => b.is_ascii_alphanumeric() || b == b'_' || b == b'-',
            Self::UpperDigit => b.is_ascii_uppercase() || b.is_ascii_digit(),
            Self::AlnumDash => b.is_ascii_alphanumeric() || b == b'-',
            Self::Path => b.is_ascii_alphanumeric() || b == b'/',
        }
    }
}

/// How a candidate after an anchor is confirmed.
#[derive(Debug, Clone, Copy)]
enum Rule {
    /// The whole run of `chars` after the anchor (single dots between runs allowed when `dots`),
    /// at least `min` bytes, containing `marker` if set. The finding includes the anchor.
    Run {
        chars: Chars,
        min: usize,
        dots: bool,
        marker: Option<&'static [u8]>,
    },
    /// The whole run of `chars` after a public anchor, at least `min` bytes; only the run is
    /// secret.
    RunAfter { chars: Chars, min: usize },
    /// A PEM block whose label ends in `PRIVATE KEY` (or `PRIVATE KEY BLOCK`).
    PemPrivateKey,
    /// `header.payload.signature`, header and payload both JSON objects in base64url.
    Jwt,
    /// The password in `scheme://user:password@host`.
    UrlPassword,
}

/// An anchor literal, the class it signals, and how to confirm it.
#[derive(Debug, Clone, Copy)]
struct Anchor {
    literal: &'static str,
    class: DataClass,
    /// Whether an alphanumeric byte right before the anchor means it sits inside a longer token.
    glue: bool,
    rule: Rule,
}

const fn anchor(literal: &'static str, class: DataClass, glue: bool, rule: Rule) -> Anchor {
    Anchor {
        literal,
        class,
        glue,
        rule,
    }
}

const fn run(chars: Chars, min: usize) -> Rule {
    Rule::Run {
        chars,
        min,
        dots: false,
        marker: None,
    }
}

const ANTHROPIC: Rule = run(Chars::Token, 32);
const OPENAI_MARKED: Rule = Rule::Run {
    chars: Chars::Token,
    min: 40,
    dots: false,
    marker: Some(b"T3BlbkFJ"),
};
const OPENAI_SCOPED: Rule = run(Chars::Token, 40);
const GITHUB_CLASSIC: Rule = run(Chars::Alnum, 36);
const GITHUB_FINE_GRAINED: Rule = run(Chars::Word, 70);
const GITLAB: Rule = Rule::Run {
    chars: Chars::Token,
    min: 20,
    dots: true,
    marker: None,
};
const SLACK: Rule = run(Chars::AlnumDash, 20);
const SLACK_WEBHOOK: Rule = Rule::RunAfter {
    chars: Chars::Path,
    min: 20,
};
const STRIPE: Rule = run(Chars::Alnum, 24);
const GOOGLE: Rule = run(Chars::Token, 35);
const AWS: Rule = run(Chars::UpperDigit, 16);

/// Detector set v1. A longer anchor must precede any anchor that is its prefix (leftmost-first);
/// merge priority between classes comes from [`DataClass`].
fn v1() -> Vec<Anchor> {
    use DataClass as C;
    vec![
        anchor("-----BEGIN ", C::PrivateKey, false, Rule::PemPrivateKey),
        anchor("eyJ", C::Jwt, true, Rule::Jwt),
        anchor("sk-ant-", C::AnthropicApiKey, true, ANTHROPIC),
        anchor("sk-proj-", C::OpenaiApiKey, true, OPENAI_SCOPED),
        anchor("sk-svcacct-", C::OpenaiApiKey, true, OPENAI_SCOPED),
        anchor("sk-admin-", C::OpenaiApiKey, true, OPENAI_SCOPED),
        anchor("sk-", C::OpenaiApiKey, true, OPENAI_MARKED),
        anchor("ghp_", C::GithubToken, true, GITHUB_CLASSIC),
        anchor("gho_", C::GithubToken, true, GITHUB_CLASSIC),
        anchor("ghu_", C::GithubToken, true, GITHUB_CLASSIC),
        anchor("ghs_", C::GithubToken, true, GITHUB_CLASSIC),
        anchor("ghr_", C::GithubToken, true, GITHUB_CLASSIC),
        anchor("github_pat_", C::GithubToken, true, GITHUB_FINE_GRAINED),
        anchor("glpat-", C::GitlabToken, true, GITLAB),
        anchor("glrt-", C::GitlabToken, true, GITLAB),
        anchor("gldt-", C::GitlabToken, true, GITLAB),
        anchor("xoxb-", C::SlackToken, true, SLACK),
        anchor("xoxp-", C::SlackToken, true, SLACK),
        anchor("xoxa-", C::SlackToken, true, SLACK),
        anchor("xoxr-", C::SlackToken, true, SLACK),
        anchor("xoxs-", C::SlackToken, true, SLACK),
        anchor("xoxe-", C::SlackToken, true, SLACK),
        anchor("hooks.slack.com/services/", C::SlackToken, false, SLACK_WEBHOOK),
        anchor("sk_live_", C::StripeKey, true, STRIPE),
        anchor("sk_test_", C::StripeKey, true, STRIPE),
        anchor("rk_live_", C::StripeKey, true, STRIPE),
        anchor("rk_test_", C::StripeKey, true, STRIPE),
        anchor("AIza", C::GoogleApiKey, true, GOOGLE),
        anchor("AKIA", C::AwsAccessKeyId, true, AWS),
        anchor("ASIA", C::AwsAccessKeyId, true, AWS),
        anchor("ABIA", C::AwsAccessKeyId, true, AWS),
        anchor("ACCA", C::AwsAccessKeyId, true, AWS),
        anchor("://", C::UrlCredentials, false, Rule::UrlPassword),
    ]
}

/// A compiled detector set. `Debug` shows the version and the number of anchors only.
pub struct DetectorSet {
    version: DetectorVersion,
    anchors: Vec<Anchor>,
    automaton: AhoCorasick,
    url_scheme: memmem::Finder<'static>,
}

impl fmt::Debug for DetectorSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DetectorSet")
            .field("version", &self.version)
            .field("anchors", &self.anchors.len())
            .finish_non_exhaustive()
    }
}

impl DetectorSet {
    /// Compiles detector set `version`.
    ///
    /// # Errors
    /// [`RedactError::UnknownDetectorVersion`] for a version this build does not have (the
    /// session must not silently switch rules); [`RedactError::DetectorFailure`] if compiling
    /// fails.
    pub fn new(version: DetectorVersion) -> Result<Self, RedactError> {
        let anchors = match version {
            DetectorVersion::V1 => v1(),
            DetectorVersion(other) => return Err(RedactError::UnknownDetectorVersion(other)),
        };
        // Leftmost-first keeps the SIMD prefilter (several times faster on prose). Longer anchors
        // are listed before their prefixes (`sk-ant-` before `sk-`), so the most specific rule is
        // tried. `scan` restarts one byte after each match, so an anchor that overlaps another
        // anchor's literal is still found.
        let automaton = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .build(anchors.iter().map(|a| a.literal))
            .map_err(|_| RedactError::DetectorFailure("anchor automaton could not be built"))?;
        Ok(Self {
            version,
            anchors,
            automaton,
            url_scheme: memmem::Finder::new(b"://"),
        })
    }

    /// The version.
    #[must_use]
    pub fn version(&self) -> DetectorVersion {
        self.version
    }

    /// Every secret in `text`, as non-overlapping findings in order.
    ///
    /// # Errors
    /// [`RedactError::DetectorFailure`]: the caller must block, never pass content unscanned.
    pub fn scan(&self, text: &[u8]) -> Result<Vec<Finding>, RedactError> {
        self.scan_with(text, &mut Memo::default())
    }

    fn scan_with(&self, text: &[u8], memo: &mut Memo) -> Result<Vec<Finding>, RedactError> {
        let mut found = Vec::new();
        let mut from = 0;
        while from < text.len() {
            let m = self
                .automaton
                .try_find(Input::new(text).span(from..text.len()))
                .map_err(|_| RedactError::DetectorFailure("anchor search failed"))?;
            let Some(m) = m else { break };
            from = m.start() + 1;
            let Some(anchor) = self.anchors.get(m.pattern().as_usize()) else {
                return Err(RedactError::DetectorFailure("unknown anchor"));
            };
            if anchor.glue && glued(text, m.start()) {
                continue;
            }
            if let Some(range) = self.confirm(anchor.rule, text, m.start(), m.end(), memo) {
                found.push(Finding {
                    class: anchor.class,
                    range,
                });
            }
        }
        Ok(merge(found))
    }

    /// The secret's range, given an anchor at `start..after`; `None` if this is not one.
    fn confirm(&self, rule: Rule, text: &[u8], start: usize, after: usize, memo: &mut Memo) -> Option<Range<usize>> {
        match rule {
            Rule::Run {
                chars,
                min,
                dots,
                marker,
            } => {
                let end = memo.run_end(text, after, chars, dots);
                let long_enough = end - after >= min;
                let marked = marker.is_none_or(|m| memo.has_marker(text, after, end, chars, m));
                (long_enough && marked).then_some(start..end)
            }
            Rule::RunAfter { chars, min } => {
                let end = memo.run_end(text, after, chars, false);
                (end - after >= min).then_some(after..end)
            }
            Rule::PemPrivateKey => pem_private_key(text, start, after, memo),
            Rule::Jwt => jwt(text, start, memo),
            Rule::UrlPassword => self.url_password(text, start, after, memo),
        }
    }

    /// The password of `scheme://user:password@host`.
    ///
    /// * The userinfo window runs from the anchor to the first hard stop (whitespace, control,
    ///   `"`, `<`, `>`, backtick), at most [`USERINFO_MAX`] bytes, and never into the next `://`.
    /// * An authority that starts with an IPv6 literal has no userinfo.
    /// * The user ends at the first `:`, skipping over placeholders (a user redacted in an
    ///   earlier round still has its password found); a `/`, `?` or `#` before it means there is
    ///   no userinfo.
    /// * The password ends at the **last** `@` in the window that a host follows, so `/`, `#`,
    ///   `?`, `'`, `\` and `@` inside a password are covered. A path containing `@` is covered too:
    ///   over-redaction, never a leak.
    /// * Not a password: `host:port/path@x` (see [`port_then_path`]), an scp-style path after an
    ///   email-like user (`git@host:org/repo.git@v1`), and a template reference
    ///   (`${DB_PASSWORD}`, `$DB_PASSWORD`, `%(password)s`, `{{db_password}}`).
    fn url_password(&self, text: &[u8], start: usize, after: usize, memo: &mut Memo) -> Option<Range<usize>> {
        let has_scheme = start
            .checked_sub(1)
            .and_then(|i| text.get(i))
            .is_some_and(u8::is_ascii_alphanumeric);
        if !has_scheme {
            return None;
        }
        let mut end = memo.stop(text, after).min(after.saturating_add(USERINFO_MAX));
        let window = text.get(after..end)?;
        if let Some(next) = self.url_scheme.find(window) {
            end = after + next;
        }
        let window = text.get(after..end)?;
        memo.charge(window.len());
        if starts_with_ipv6_literal(window) {
            return None;
        }
        let user_end = user_end(window)?;
        let user = window.get(..user_end)?;
        let pass_from = user_end + 1;
        let at = memchr::memrchr_iter(b'@', window.get(pass_from..)?)
            .map(|i| pass_from + i)
            .find(|&at| {
                window
                    .get(at + 1)
                    .is_some_and(|&b| b.is_ascii_alphanumeric() || b == b'[' || b == b'_')
            })?;
        let candidate = window.get(pass_from..at)?;
        let not_a_password = candidate.is_empty()
            || is_placeholder(candidate)
            || port_then_path(user, candidate)
            || scp_path(user, candidate)
            || is_template(candidate);
        (!not_a_password).then_some(after + pass_from..after + at)
    }
}

/// Longest userinfo we inspect.
const USERINFO_MAX: usize = 512;

/// A URL never contains these unencoded in text: they end it. A backslash does not: a
/// JSON-escaped `\/` inside a password must not end it early.
fn hard_stop(b: u8) -> bool {
    b.is_ascii_whitespace() || b.is_ascii_control() || matches!(b, b'"' | b'<' | b'>' | b'`')
}

/// Whether the byte before an anchor at `start` glues it into a longer token: an alphanumeric byte,
/// unless it is the tail of an escape still encoded in this view (`\n`, `%20`, `\u0041`), which a
/// deeper view decodes.
fn glued(text: &[u8], start: usize) -> bool {
    let before = |k: usize| start.checked_sub(k).and_then(|i| text.get(i)).copied();
    if !before(1).is_some_and(|b| b.is_ascii_alphanumeric()) {
        return false;
    }
    let hex = |k: usize| before(k).is_some_and(|b| b.is_ascii_hexdigit());
    let escape_tail = before(2) == Some(b'\\')
        || (before(3) == Some(b'%') && hex(2) && hex(1))
        || (before(6) == Some(b'\\') && before(5) == Some(b'u') && (1..=4).all(hex));
    !escape_tail
}

/// `[hex:.]` at the start of the authority: an IPv6 host, so there is no userinfo.
fn starts_with_ipv6_literal(window: &[u8]) -> bool {
    window.first() == Some(&b'[')
        && memchr::memchr(b']', window)
            .and_then(|close| window.get(1..close))
            .is_some_and(|inner| {
                !inner.is_empty() && inner.iter().all(|&b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
            })
}

/// End of the user: the first `:`, skipping whole placeholders. `None` if a `/`, `?` or `#`
/// comes first, or there is no `:`.
fn user_end(window: &[u8]) -> Option<usize> {
    let mut i = 0;
    loop {
        match *window.get(i)? {
            b':' => return Some(i),
            b'/' | b'?' | b'#' => return None,
            b'[' => i += placeholder_len(window.get(i..)?).unwrap_or(1),
            _ => i += 1,
        }
    }
}

/// Length of the placeholder at the start of `bytes`, if one is there.
fn placeholder_len(bytes: &[u8]) -> Option<usize> {
    let longest = PLACEHOLDER_PREFIX.len() + 32 + PLACEHOLDER_TAG_HEX + 2;
    let head = bytes.get(..bytes.len().min(longest))?;
    let close = memchr::memchr(b']', head)?;
    is_placeholder(head.get(..=close)?).then_some(close + 1)
}

/// Bytes of a lowercase path or query: what follows `host:port` in a service URL.
fn path_like(rest: &[u8]) -> bool {
    rest.iter().all(|&b| {
        b.is_ascii_lowercase()
            || b.is_ascii_digit()
            || matches!(
                b,
                b'/' | b'.' | b'_' | b'~' | b'-' | b'?' | b'=' | b'&' | b'#' | b'%' | b'@'
            )
    })
}

/// Whether `user:candidate` is really `host:port/path` (`localhost:3000/@user`,
/// `web:8000/?email=a@b.c`): the candidate starts with a port number and a `/`, `?` or `#`, and
/// either the user is host-like (dotted, contains `@`, or `localhost`) or the rest is a lowercase
/// path. A random candidate rarely starts with a port and a slash and almost never continues as a
/// lowercase path, so recall holds; what is missed is stated.
fn port_then_path(user: &[u8], candidate: &[u8]) -> bool {
    let digits = candidate.iter().take_while(|b| b.is_ascii_digit()).count();
    let port_ok = (1..=5).contains(&digits)
        && candidate
            .get(..digits)
            .and_then(|d| std::str::from_utf8(d).ok())
            .and_then(|d| d.parse::<u32>().ok())
            .is_some_and(|port| port <= 65_535);
    if !port_ok || !matches!(candidate.get(digits), Some(b'/' | b'?' | b'#')) {
        return false;
    }
    let host_like = user.contains(&b'.') || user.contains(&b'@') || user.eq_ignore_ascii_case(b"localhost");
    host_like || candidate.get(digits..).is_some_and(path_like)
}

/// Whether `user:candidate` is really an scp-style `git@host:org/repo.git` path.
fn scp_path(user: &[u8], candidate: &[u8]) -> bool {
    user.contains(&b'@') && candidate.contains(&b'/') && path_like(candidate)
}

/// Whether the candidate is a template reference, not a value: `${NAME}`, `$NAME` (upper case),
/// `%(name)s`, `{{name}}`.
fn is_template(candidate: &[u8]) -> bool {
    let ident = |b: &[u8], upper: bool| {
        !b.is_empty()
            && b.iter().all(|&c| {
                (if upper {
                    c.is_ascii_uppercase()
                } else {
                    c.is_ascii_alphabetic()
                }) || c.is_ascii_digit()
                    || c == b'_'
            })
            && !b.first().is_some_and(u8::is_ascii_digit)
    };
    let inner = |open: &[u8], close: &[u8]| candidate.strip_prefix(open).and_then(|r| r.strip_suffix(close));
    inner(b"${", b"}").is_some_and(|n| ident(n, false))
        || candidate.strip_prefix(b"$").is_some_and(|n| ident(n, true))
        || inner(b"%(", b")s").is_some_and(|n| ident(n, false))
        || inner(b"{{", b"}}").is_some_and(|n| ident(n, false))
}

/// Work shared by the anchors of one scan: anchors inside a run, a private-key block or a userinfo
/// window already examined reuse the result instead of rescanning it, which keeps a scan linear (1
/// MB of repeated PEM headers took 860 ms).
#[derive(Default)]
struct Memo {
    /// Per char class and dot rule, every run computed, by end: `end → from`. Maximal runs of one
    /// class never overlap, so the first entry ending after a position is the only one that can
    /// contain it. (One entry per class was not enough: the JWT rule's payload and signature runs
    /// evicted its header run, and the scan went quadratic)
    runs: Vec<(Chars, bool, BTreeMap<usize, usize>)>,
    /// The last marker search: `(chars, from, end, start of the marker's last occurrence)`.
    marker: Option<(Chars, usize, usize, Option<usize>)>,
    /// The last hard-stop search: no hard stop in `from..end`, and one at `end` (or the end).
    stop: Option<(usize, usize)>,
    /// End of the last private-key block.
    pem_end: usize,
    /// Bytes examined, so tests can prove the bound.
    #[cfg(test)]
    work: usize,
}

impl Memo {
    #[cfg_attr(not(test), allow(clippy::unused_self, reason = "work is counted in tests only"))]
    fn charge(&mut self, bytes: usize) {
        #[cfg(test)]
        {
            self.work += bytes;
        }
        #[cfg(not(test))]
        let _ = bytes;
    }

    /// End of the run of `chars` from `from` (see [`run_end`]).
    fn run_end(&mut self, text: &[u8], from: usize, chars: Chars, dots: bool) -> usize {
        if !text.get(from).is_some_and(|&b| chars.has(b)) {
            return from;
        }
        let index = self
            .runs
            .iter()
            .position(|r| r.0 == chars && r.1 == dots)
            .unwrap_or_else(|| {
                self.runs.push((chars, dots, BTreeMap::new()));
                self.runs.len() - 1
            });
        let Some((_, _, runs)) = self.runs.get_mut(index) else {
            return run_end(text, from, chars, dots);
        };
        if let Some((&e, &f)) = runs.range(from + 1..).next()
            && f <= from
        {
            return e;
        }
        let end = run_end(text, from, chars, dots);
        let earliest = runs.get(&end).map_or(from, |&f| f.min(from));
        runs.insert(end, earliest);
        self.charge(end - from);
        end
    }

    /// Whether `marker` occurs in `from..end`, the tail of a run of `chars`.
    fn has_marker(&mut self, text: &[u8], from: usize, end: usize, chars: Chars, marker: &[u8]) -> bool {
        let last = match self.marker {
            Some((c, f, e, last)) if c == chars && e == end && f <= from => last,
            _ => {
                let body = text.get(from..end).unwrap_or_default();
                self.charge(body.len());
                let last = memmem::rfind(body, marker).map(|i| from + i);
                self.marker = Some((chars, from, end, last));
                last
            }
        };
        last.is_some_and(|at| at >= from)
    }

    /// The first hard stop at or after `from`, or the end of `text`.
    fn stop(&mut self, text: &[u8], from: usize) -> usize {
        if let Some((f, e)) = self.stop
            && f <= from
            && from <= e
        {
            return e;
        }
        let rest = text.get(from..).unwrap_or_default();
        let end = from + rest.iter().position(|&b| hard_stop(b)).unwrap_or(rest.len());
        self.charge(end - from);
        self.stop = Some((from, end));
        end
    }
}

/// End of the maximal run of `chars` from `from`; with `dots`, a single `.` between two runs
/// continues it (`a.b`), a trailing `.` (end of sentence) does not.
fn run_end(text: &[u8], from: usize, chars: Chars, dots: bool) -> usize {
    let mut end = from;
    loop {
        while text.get(end).is_some_and(|&b| chars.has(b)) {
            end += 1;
        }
        let continues =
            dots && end > from && text.get(end) == Some(&b'.') && text.get(end + 1).is_some_and(|&b| chars.has(b));
        if !continues {
            return end;
        }
        end += 1;
    }
}

/// Longest label we accept between `-----BEGIN ` and `-----`.
const PEM_LABEL_MAX: usize = 48;
/// How far we look for the matching `-----END` line.
const PEM_BODY_MAX: usize = 64 * 1024;

fn pem_private_key(text: &[u8], start: usize, after: usize, memo: &mut Memo) -> Option<Range<usize>> {
    // A header inside a block already found ends at that block's END line (or the text end),
    // which the earlier finding covers.
    if start < memo.pem_end {
        return None;
    }
    let window = text.get(after..text.len().min(after + PEM_LABEL_MAX + 5))?;
    let label_len = memmem::find(window, b"-----")?;
    let label = window.get(..label_len)?;
    let well_formed = label
        .iter()
        .all(|&b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b' ');
    if !well_formed || !(label.ends_with(b"PRIVATE KEY") || label.ends_with(b"PRIVATE KEY BLOCK")) {
        return None;
    }
    let header_end = after + label_len + 5;
    let body = text.get(header_end..text.len().min(header_end.saturating_add(PEM_BODY_MAX)))?;
    // Without its END line (truncated, or too far away), everything after BEGIN is treated as
    // key material: fail closed.
    let end = memmem::find(body, b"-----END ")
        .and_then(|i| {
            memo.charge(i);
            let label_from = header_end + i + 9;
            let tail = text.get(label_from..text.len().min(label_from + PEM_LABEL_MAX + 5))?;
            memmem::find(tail, b"-----").map(|j| label_from + j + 5)
        })
        .unwrap_or_else(|| {
            memo.charge(body.len());
            text.len()
        });
    memo.pem_end = end;
    Some(start..end)
}

/// Minimum header and payload lengths (base64url of `{"alg":…}` and of a claims object).
const JWT_PART_MIN: usize = 10;
/// Minimum signature length: shorter ones are not credentials (an `alg: none` token has none).
const JWT_SIGNATURE_MIN: usize = 16;

fn jwt(text: &[u8], start: usize, memo: &mut Memo) -> Option<Range<usize>> {
    let header_end = memo.run_end(text, start, Chars::Token, false);
    if header_end - start < JWT_PART_MIN || text.get(header_end) != Some(&b'.') {
        return None;
    }
    let payload = header_end + 1;
    if text.get(payload..payload + 3) != Some(b"eyJ".as_slice()) {
        return None;
    }
    let payload_end = memo.run_end(text, payload, Chars::Token, false);
    if payload_end - payload < JWT_PART_MIN || text.get(payload_end) != Some(&b'.') {
        return None;
    }
    let signature = payload_end + 1;
    let end = memo.run_end(text, signature, Chars::Token, false);
    (end - signature >= JWT_SIGNATURE_MIN).then_some(start..end)
}

/// Sorts findings and merges overlaps into one span with the most specific class.
fn merge(mut found: Vec<Finding>) -> Vec<Finding> {
    found.sort_by(|a, b| a.range.start.cmp(&b.range.start).then(b.range.end.cmp(&a.range.end)));
    let mut out: Vec<Finding> = Vec::with_capacity(found.len());
    for f in found {
        match out.last_mut() {
            Some(last) if f.range.start < last.range.end => {
                last.range.end = last.range.end.max(f.range.end);
                last.class = last.class.min(f.class);
            }
            _ => out.push(f),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set() -> DetectorSet {
        DetectorSet::new(DetectorVersion::V1).unwrap()
    }

    fn classes(text: &str) -> Vec<(DataClass, &str)> {
        set()
            .scan(text.as_bytes())
            .unwrap()
            .into_iter()
            .map(|f| (f.class, &text[f.range]))
            .collect()
    }

    fn url(text: &str) -> Vec<&str> {
        classes(text)
            .into_iter()
            .filter(|(c, _)| *c == DataClass::UrlCredentials)
            .map(|(_, s)| s)
            .collect()
    }

    #[test]
    fn alphanumeric_left_glue_is_a_longer_token_and_right_glue_is_covered() {
        let key = format!("AKIA{}", "Q".repeat(16));
        assert_eq!(
            classes(&format!("id={key};")),
            [(DataClass::AwsAccessKeyId, key.as_str())]
        );
        assert!(classes(&format!("x{key}")).is_empty(), "inside a longer token");
        // Glue on the right, or a longer run, used to hide the key.
        let longer = format!("{key}ZZ");
        assert_eq!(classes(&longer), [(DataClass::AwsAccessKeyId, longer.as_str())]);
        assert_eq!(
            classes(&format!("{key}abc")),
            [(DataClass::AwsAccessKeyId, key.as_str())]
        );
    }

    #[test]
    fn separators_on_the_left_are_not_glue() {
        let gh = format!("ghp_{}", "a".repeat(36));
        let ant = format!("sk-ant-api03-{}", "b".repeat(40));
        let stripe = format!("sk_live_{}", "c".repeat(30));
        for (text, class, secret) in [
            (format!("_{gh}_"), DataClass::GithubToken, gh.as_str()),
            (
                format!("${{ANTHROPIC_API_KEY:-{ant}}}"),
                DataClass::AnthropicApiKey,
                ant.as_str(),
            ),
            (format!("STRIPE_KEY_{stripe}"), DataClass::StripeKey, stripe.as_str()),
        ] {
            assert!(classes(&text) == [(class, secret)], "{class}");
        }
    }

    #[test]
    fn runs_longer_than_the_format_are_covered_whole() {
        let long = format!("sk_live_{}", "d".repeat(400));
        assert_eq!(classes(&long), [(DataClass::StripeKey, long.as_str())]);
        let gh = format!("ghp_{}", "e".repeat(50));
        assert_eq!(classes(&gh), [(DataClass::GithubToken, gh.as_str())]);
    }

    #[test]
    fn overlapping_detections_merge_to_the_specific_class() {
        let token = format!("ghp_{}", "a".repeat(36));
        let text = format!("https://user:{token}@github.com/org/repo");
        assert_eq!(classes(&text), [(DataClass::GithubToken, token.as_str())]);
    }

    #[test]
    fn an_anchor_overlapping_another_anchor_is_still_found() {
        // `sk-` consumed the first dashes of the PEM header. Split so the source never holds a full
        // PEM header.
        let text = concat!("sk-----BEGIN RSA PRIVATE", " KEY-----\nMIIabc");
        assert_eq!(classes(text), [(DataClass::PrivateKey, &text[2..])]);
    }

    #[test]
    fn url_passwords_cover_every_byte_a_password_can_hold() {
        // `/`, `#`, `?` and `'` used to end the password early.
        for (case, expected) in ["a/b+c=", "x#y", "q?r", "it's", "p@ss", "a:b", "(x),[y];z"]
            .into_iter()
            .enumerate()
        {
            let text = format!("postgres://app:{expected}@db.example.com:5432/app");
            assert!(url(&text) == [expected], "case {case}");
        }
        assert_eq!(url("redis://:p@ss@cache.local:6379"), ["p@ss"]);
        assert_eq!(url("key = 'mysql://u:pw@h'"), ["pw"]);
        assert_eq!(
            url("smtp://me@example.com:pw@mail.example.com"),
            ["pw"],
            "an unencoded email as the user"
        );
        // Two URLs glued by a comma stay two passwords.
        assert_eq!(url("a://u:p1@h,b://v:p2@k"), ["p1", "p2"]);
        // A backslash (a JSON-escaped `\/`), a bracketed user, a host starting with `_`.
        assert_eq!(url(r"s3a://app:wJal\/K7MD@bucket/path"), [r"wJal\/K7MD"]);
        assert_eq!(url("https://[svc]:hunter2hunter2@host.example.com"), ["hunter2hunter2"]);
        assert_eq!(url("postgres://app:s3cretpw@_db.local/x"), ["s3cretpw"]);
        // A user already redacted in an earlier round still has its password found.
        let user = "[REDACTED:aws_access_key_id:0123456789abcdef]";
        assert_eq!(url(&format!("s3a://{user}:wJalrXUtnFEMI@bucket")), ["wJalrXUtnFEMI"]);
        // A port-like start followed by more than a lowercase path is a password.
        assert_eq!(url("postgres://app:2024/Winter!@db.example.com/x"), ["2024/Winter!"]);
    }

    #[test]
    fn urls_without_userinfo_are_not_passwords() {
        for text in [
            "http://localhost:3000/@user/profile",
            "https://registry.example.com:8443/@scope/pkg@1.0",
            "http://example.com:80/path?email=a@b.com",
            "https://user@example.com",
            "https://user@host.example.com:8443/x",
            "postgres://user:@db",
            "ssh://git@github.com/org/repo.git",
            "http://[::1]:8080/@x",
            "https://registry.example.com/@scope/pkg:1.0@latest",
            // Single-label service hosts, scp paths, templates.
            "docker://registry:5000/app@sha256:4d2b1f0c9e8a7b6c5d4e3f2a1b0c9d8e",
            "http://verdaccio:4873/@babel/core",
            "http://web:3000/@alice",
            "http://web:8000/?email=bob@example.com",
            "http://api:8080/users/@me",
            "http://minio:9000/bucket/a@b.txt",
            "jdbc:mysql://db:3306/app?user=bob@corp.com",
            "http://keycloak:8080/admin/users?email=a@b.com",
            "git+ssh://git@github.com:org/repo.git@v1.0",
            "ssh://git@github.com:org/repo.git#egg=pkg@v1",
            "http://LOCALHOST:3000/@x",
            "postgres://app:${POSTGRES_PASSWORD}@db:5432/app",
            "redis://:$REDIS_PASSWORD@redis:6379/0",
            "mysql://root:%(password)s@localhost/db",
            "amqp://guest:{{rabbit_password}}@mq:5672/",
            "postgresql://{user}:{password}@{host}/{db}",
        ] {
            assert!(url(text).is_empty(), "{text}");
        }
    }

    /// The tail of an escape still encoded in a view (`n` of a backslash-n, `0` of `%20`) is not
    /// glue.
    #[test]
    fn an_escape_tail_on_the_left_is_not_glue() {
        let key = format!("AKIA{}", "Q".repeat(16));
        // `~` stands for a backslash.
        for left in ["x~~n", "x~n", "id=%20", "~u0020"] {
            let text = format!("{}{key}", left.replace('~', "\\"));
            assert!(
                classes(&text) == [(DataClass::AwsAccessKeyId, key.as_str())],
                "left neighbour {left:?}"
            );
        }
        assert!(classes(&format!("xn{key}")).is_empty(), "plain glue still counts");
    }

    #[test]
    fn placeholders_are_recognised_exactly() {
        let tag = "0123456789abcdef";
        assert!(is_placeholder(format!("[REDACTED:jwt:{tag}]").as_bytes()));
        for loose in [
            format!("[REDACTED:jwt:{tag}"),
            format!("[REDACTED:nope:{tag}]"),
            format!("[REDACTED:jwt:{}]", tag.to_uppercase()),
            format!("[REDACTED:jwt:{tag}0]"),
            "[REDACTED:]".to_owned(),
            "[REDACTED:jwt:x]-and-more]".to_owned(),
        ] {
            assert!(!is_placeholder(loose.as_bytes()), "{loose}");
        }
        // A password that only looks like a placeholder is still a password.
        assert_eq!(url("https://u:[REDACTED:secret]@h"), ["[REDACTED:secret]"]);
        assert!(url(&format!("https://u:[REDACTED:url_credentials:{tag}]@h")).is_empty());
    }

    #[test]
    fn pem_without_end_is_redacted_to_the_end() {
        // Split so the source never holds a full PEM header (secret scanning stays meaningful).
        let text = concat!("x -----BEGIN RSA PRIVATE", " KEY-----\nMIIabc");
        assert_eq!(classes(text), [(DataClass::PrivateKey, &text[2..])]);
        assert!(classes("-----BEGIN PUBLIC KEY-----\nMIIabc\n-----END PUBLIC KEY-----").is_empty());
    }

    /// Anchors that each rescanned a long window made a scan quadratic.
    #[test]
    fn adversarial_inputs_are_scanned_in_linear_work() {
        let header = concat!("-----BEGIN RSA PRIVATE", " KEY-----\n");
        let patterns = [
            header.to_owned(),
            "sk-ant-".to_owned(),
            "sk-".to_owned(),
            concat!("sk-", "T3Blbk", "FJ").to_owned(),
            "eyJ".to_owned(),
            "eyJaaaaaaaaaaaa.".to_owned(),
            "a://".to_owned(),
            "a://b:@".to_owned(),
            "a://b:c@@".to_owned(),
            "glpat-a.".to_owned(),
            "hooks.slack.com/services/".to_owned(),
            "_eyJ".to_owned(),
            "-eyJ".to_owned(),
            "eyJx.eyJx.".to_owned(),
            "a://b:".to_owned(),
            "%25".to_owned(),
        ];
        // A long JWT header run followed by a payload and a signature evicted the header from a
        // one-entry cache, and every later `eyJ` inside the header rescanned it.
        let tails = ["", ".eyJaaaaaaaaaa.b", ".eyJaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbb"];
        let set = set();
        for (pattern, tail) in patterns.iter().flat_map(|p| tails.iter().map(move |t| (p, t))) {
            let text = pattern.repeat(256 * 1024 / pattern.len()) + tail;
            let mut memo = Memo::default();
            set.scan_with(text.as_bytes(), &mut memo).unwrap();
            assert!(
                memo.work <= 8 * text.len() + PEM_BODY_MAX,
                "{pattern:?}: {} bytes examined for {} bytes of input",
                memo.work,
                text.len()
            );
        }
    }

    #[test]
    fn unknown_versions_are_refused() {
        assert_eq!(
            DetectorSet::new(DetectorVersion(2)).unwrap_err(),
            RedactError::UnknownDetectorVersion(2)
        );
    }
}
