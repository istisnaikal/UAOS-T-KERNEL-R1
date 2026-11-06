// SPDX-License-Identifier: Apache-2.0

//! Synthetic corpus v2: generators for secrets of every claimed class, the contexts and evasion
//! forms they appear in, and hard negatives in named families.
//!
//! Everything is generated at test time from a seed: no secret-shaped string is ever committed, so
//! secret scanning of the repository stays meaningful. The generator code plus the seed *is* the
//! corpus version; changing either changes the corpus and must be recorded.
//!
//! URL passwords draw from every printable byte a URL can carry; positives come in five forms
//! (plain, glued, nested JSON, double-nested JSON, percent-encoded); negatives carry a family name
//! so false positives are counted per family, not diluted across all of them.

#![allow(dead_code, reason = "shared by several test crates; each uses a subset")]

use std::fmt::Write as _;

use uaos_redact::DataClass;

/// Seed of corpus v2 (merge runs). Nightly runs override it to explore further.
pub(crate) const CORPUS_SEED: u64 = 0x5541_4F53_5244_0002;

/// `SplitMix64`: tiny, deterministic, good enough for corpus generation (not for cryptography).
#[derive(Debug, Clone)]
pub(crate) struct Prng(u64);

impl Prng {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub(crate) fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next_u64() % u64::try_from(n).unwrap()).unwrap()
    }

    /// Inclusive range.
    pub(crate) fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + self.below(hi - lo + 1)
    }

    pub(crate) fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }

    pub(crate) fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }

    pub(crate) fn chars(&mut self, set: &[u8], len: usize) -> String {
        (0..len).map(|_| char::from(self.pick(set))).collect()
    }

    pub(crate) fn chars_in(&mut self, set: &[u8], lo: usize, hi: usize) -> String {
        let n = self.range(lo, hi);
        self.chars(set, n)
    }

    pub(crate) fn chars_of(&mut self, set: &[u8], lens: &[usize]) -> String {
        let n = self.pick(lens);
        self.chars(set, n)
    }
}

pub(crate) const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub(crate) const LOWER_DIGIT: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
pub(crate) const DIGITS: &[u8] = b"0123456789";
pub(crate) const HEX: &[u8] = b"0123456789abcdef";
pub(crate) const UPPER_DIGIT: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
pub(crate) const BASE32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
pub(crate) const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
pub(crate) const TOKEN: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
pub(crate) const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/// Every printable byte a password in an unencoded URL can hold: all of them except whitespace,
/// `"`, `<`, `>` and the backtick, which end a URL in text (`@` is inserted separately).
pub(crate) const PASSWORD: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'()*+,-./:;=?[]^_{|}~\\";

/// A secret as it appears (`text`) and the part that must not survive redaction (`secret`).
#[derive(Debug, Clone)]
pub(crate) struct Sample {
    pub(crate) class: DataClass,
    pub(crate) text: String,
    pub(crate) secret: String,
}

fn whole(class: DataClass, text: String) -> Sample {
    Sample {
        class,
        secret: text.clone(),
        text,
    }
}

/// Base64url without padding.
pub(crate) fn b64url(bytes: &[u8]) -> String {
    const SET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..=chunk.len() {
            let index = usize::try_from((n >> (18 - 6 * i)) & 0x3F).unwrap();
            out.push(char::from(SET[index]));
        }
    }
    out
}

pub(crate) const WORDS: &[&str] = &[
    "the",
    "agent",
    "budget",
    "request",
    "token",
    "secret",
    "password",
    "deploy",
    "build",
    "cache",
    "journal",
    "pocket",
    "session",
    "error",
    "retry",
    "stream",
    "model",
    "tool",
    "call",
    "policy",
    "config",
    "value",
    "server",
    "client",
    "database",
    "migration",
    "rollback",
    "kernel",
    "module",
    "github",
    "gitlab",
    "slack",
    "stripe",
    "google",
    "amazon",
    "anthropic",
    "openai",
    "key",
    "id",
    "BEGIN",
    "PRIVATE",
    "KEY",
    "Bearer",
    "Authorization",
    "header",
    "payload",
    "sk-learn",
    "task-ant",
    "desk-antenna",
    "AKIAN",
    "ghost",
    "glpat",
    "xoxo",
    "AIza",
    "eyJ",
    "risk",
    "skill",
    "asking",
    "localhost",
    "example.com",
    "user@example.com",
    "git@github.com:org/repo.git",
    "v1.2.3",
    "çalışma",
    "güvenlik",
    "ışık",
    "şifre",
    "anahtar",
    "bütçe",
    "değer",
    "İstanbul",
    "ğ",
    "ü",
    "fn",
    "let",
    "mut",
    "impl",
    "struct",
    "async",
    "await",
    "return",
    "Ok(())",
    "None",
    "Some(x)",
];

/// Lowercase words for generated paths.
pub(crate) const WORDS_LOWER: &[&str] = &["org", "repo", "tools", "kernel", "app", "lib", "web", "infra"];

pub(crate) fn prose(rng: &mut Prng) -> String {
    let n = rng.range(3, 20);
    let mut out = String::new();
    for i in 0..n {
        if i > 0 {
            out.push_str(rng.pick(&[" ", " ", " ", ", ", ". ", "\n", " - ", ": "]));
        }
        out.push_str(rng.pick(WORDS));
    }
    out
}

/// Contexts a secret (or a negative) is embedded in; `%S%` marks the spot.
pub(crate) const CONTEXTS: &[&str] = &[
    "%S%",
    "export API_KEY=%S%",
    "API_KEY=\"%S%\"",
    "Authorization: Bearer %S%",
    "  token: %S%\n",
    "key = '%S%'",
    "{\"api_key\": \"%S%\", \"x\": 1}",
    "curl -H \"Authorization: Bearer %S%\" https://api.example.com/v1/models",
    "Here is my key `%S%`, why does it fail?",
    "https://api.example.com/v1/data?key=%S%&format=json",
    "(%S%)",
    "[%S%]",
    "<%S%>",
    "%S%,",
    "%S%.",
    "%S%;",
    "line one\n%S%\nline three",
    "\t%S%\t",
    "os.environ[\"SECRET\"] = \"%S%\"",
    "const token = `%S%`;",
    "<value>%S%</value>",
    "- %S%",
    "error: invalid credentials %S% (401)",
    "%S%\r\n",
    "| prod | %S% | rotated |",
    "Merhaba, anahtarım %S% — çalışmıyor.",
];

pub(crate) fn embed(rng: &mut Prng, text: &str) -> String {
    rng.pick(CONTEXTS).replace("%S%", text)
}

/// Whether `user:password` is one of the URL rule's stated misses (limits), which the generator
/// leaves out so the properties claim what the rule does. It covers the detector's exclusions a
/// random password can reach:
/// - a `://` in the password, which ends it, or `//` at its start, where the user's `:` and the
///   `//` read as `://`. CI seed 4814893562051029426 drew one;
/// - `host:port/path` (`port_then_path`): a port of 1 to 5 digits up to 65535, then `/`, `?` or
///   `#`, after a host-like user or before a lowercase path. Stress seed 3677357430622100055
///   drew `svc2:3/#5pi.m`, a miss stated since Amendment 1;
/// - a template reference (`is_template`): `${name}`, `$NAME`, `%(name)s`, `{{name}}`.
///
/// For URLs as written, as the property tests present them, its verdicts are a superset of the
/// misses: a `host:port/path` password whose path holds a percent escape (`47039/%47`) is left out
/// although the nested view finds it. In the corpus's slash-escaped form, a password holding a
/// percent escape can still be missed (limits); the corpus measures it.
///
/// A password the generator draws ends at the URL's own `@`, so the detector's candidate is the
/// whole password.
/// `candidate` is that password; a test passes synthetic ones.
pub(crate) fn stated_miss(user: &str, candidate: &str) -> bool {
    let bytes = candidate.as_bytes();
    let path_like = |rest: &[u8]| {
        rest.iter().all(|&b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(
                    b,
                    b'/' | b'.' | b'_' | b'~' | b'-' | b'?' | b'=' | b'&' | b'#' | b'%' | b'@'
                )
        })
    };
    let digits = bytes.iter().take_while(|b| b.is_ascii_digit()).count();
    let port_ok = (1..=5).contains(&digits)
        && candidate
            .get(..digits)
            .and_then(|d| d.parse::<u32>().ok())
            .is_some_and(|port| port <= 65_535);
    let host_like = user.contains('.') || user.contains('@') || user.eq_ignore_ascii_case("localhost");
    let port_then_path = port_ok
        && matches!(bytes.get(digits), Some(b'/' | b'?' | b'#'))
        && (host_like || bytes.get(digits..).is_some_and(path_like));
    let ident = |b: &str, upper: bool| {
        !b.is_empty()
            && b.bytes().all(|c| {
                (if upper {
                    c.is_ascii_uppercase()
                } else {
                    c.is_ascii_alphabetic()
                }) || c.is_ascii_digit()
                    || c == b'_'
            })
            && !b.bytes().next().is_some_and(|c| c.is_ascii_digit())
    };
    let inner = |open: &str, close: &str| candidate.strip_prefix(open).and_then(|r| r.strip_suffix(close));
    let template = inner("${", "}").is_some_and(|n| ident(n, false))
        || candidate.strip_prefix('$').is_some_and(|n| ident(n, true))
        || inner("%(", ")s").is_some_and(|n| ident(n, false))
        || inner("{{", "}}").is_some_and(|n| ident(n, false));
    candidate.contains("://") || candidate.starts_with("//") || port_then_path || template
}

/// A secret of `class`.
#[allow(clippy::too_many_lines, reason = "one generator per class, side by side")]
pub(crate) fn secret(rng: &mut Prng, class: DataClass) -> Sample {
    match class {
        DataClass::AnthropicApiKey => {
            let kind = rng.pick(&["api03", "api03", "admin01"]);
            whole(class, format!("sk-ant-{kind}-{}AA", rng.chars(TOKEN, 93)))
        }
        DataClass::OpenaiApiKey => {
            let text = if rng.chance(75) {
                let scope = rng.pick(&["proj", "svcacct", "admin"]);
                let n = rng.pick(&[58, 74]);
                format!("sk-{scope}-{}T3BlbkFJ{}", rng.chars(TOKEN, n), rng.chars(TOKEN, n))
            } else {
                format!("sk-{}T3BlbkFJ{}", rng.chars(ALNUM, 20), rng.chars(ALNUM, 20))
            };
            whole(class, text)
        }
        DataClass::AwsAccessKeyId => {
            let prefix = rng.pick(&["AKIA", "ASIA", "ABIA", "ACCA"]);
            whole(class, format!("{prefix}{}", rng.chars(BASE32, 16)))
        }
        DataClass::GithubToken => {
            let text = if rng.chance(80) {
                let prefix = rng.pick(&["ghp", "gho", "ghu", "ghs", "ghr"]);
                format!("{prefix}_{}", rng.chars(ALNUM, 36))
            } else {
                format!("github_pat_{}_{}", rng.chars(ALNUM, 22), rng.chars(ALNUM, 59))
            };
            whole(class, text)
        }
        DataClass::GitlabToken => {
            let text = if rng.chance(25) {
                format!("glpat-{}.01.{}", rng.chars(TOKEN, 27), rng.chars(LOWER_DIGIT, 9))
            } else {
                let prefix = rng.pick(&["glpat", "glrt", "gldt"]);
                format!("{prefix}-{}", rng.chars(TOKEN, 20))
            };
            whole(class, text)
        }
        DataClass::SlackToken => match rng.below(3) {
            0 => {
                let (a, b) = (rng.range(10, 13), rng.range(10, 13));
                let text = format!(
                    "xoxb-{}-{}-{}",
                    rng.chars(DIGITS, a),
                    rng.chars(DIGITS, b),
                    rng.chars(ALNUM, 24)
                );
                whole(class, text)
            }
            1 => {
                let prefix = rng.pick(&["xoxp", "xoxa", "xoxr", "xoxs", "xoxe"]);
                let (a, b, c) = (rng.range(10, 13), rng.range(10, 13), rng.range(10, 13));
                let text = format!(
                    "{prefix}-{}-{}-{}-{}",
                    rng.chars(DIGITS, a),
                    rng.chars(DIGITS, b),
                    rng.chars(DIGITS, c),
                    rng.chars(HEX, 32)
                );
                whole(class, text)
            }
            _ => {
                let (a, b) = (rng.range(8, 11), rng.range(8, 11));
                let path = format!(
                    "T{}/B{}/{}",
                    rng.chars(UPPER_DIGIT, a),
                    rng.chars(UPPER_DIGIT, b),
                    rng.chars(ALNUM, 24)
                );
                Sample {
                    class,
                    text: format!("https://hooks.slack.com/services/{path}"),
                    secret: path,
                }
            }
        },
        DataClass::StripeKey => {
            let kind = rng.pick(&["sk", "rk"]);
            let mode = rng.pick(&["live", "test"]);
            let n = rng.range(24, 99);
            whole(class, format!("{kind}_{mode}_{}", rng.chars(ALNUM, n)))
        }
        DataClass::GoogleApiKey => whole(class, format!("AIza{}", rng.chars(TOKEN, 35))),
        DataClass::PrivateKey => whole(class, pem(rng, true)),
        DataClass::Jwt => {
            let header = match rng.below(3) {
                0 => "{\"alg\":\"HS256\",\"typ\":\"JWT\"}".to_owned(),
                1 => format!(
                    "{{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"{}\"}}",
                    rng.chars(HEX, 8)
                ),
                _ => "{\"typ\":\"JWT\",\"alg\":\"ES256\"}".to_owned(),
            };
            let iat = 1_700_000_000 + rng.below(100_000_000);
            let payload = format!(
                "{{\"sub\":\"{}\",\"name\":\"{}\",\"iat\":{iat},\"exp\":{}}}",
                rng.chars_in(DIGITS, 6, 12),
                rng.pick(WORDS),
                iat + 3600
            );
            let signature = rng.chars_of(TOKEN, &[43, 86, 342]);
            whole(
                class,
                format!(
                    "{}.{}.{signature}",
                    b64url(header.as_bytes()),
                    b64url(payload.as_bytes())
                ),
            )
        }
        DataClass::UrlCredentials => {
            let scheme = rng.pick(&[
                "postgres",
                "postgresql",
                "mysql",
                "mongodb",
                "mongodb+srv",
                "redis",
                "rediss",
                "amqp",
                "amqps",
                "https",
                "http",
                "ftp",
                "smtp",
                "sqlserver",
                "clickhouse",
            ]);
            let user = if scheme.starts_with("redis") && rng.chance(50) {
                String::new()
            } else {
                format!(
                    "{}{}",
                    rng.pick(&["app", "admin", "svc", "deploy", "root", "u"]),
                    rng.chars_in(DIGITS, 0, 2)
                )
            };
            let password = loop {
                let mut password = rng.chars_in(PASSWORD, 8, 32);
                if rng.chance(10) {
                    let at = rng.range(1, password.len() - 1);
                    password.insert(at, '@');
                }
                if !stated_miss(&user, &password) {
                    break password;
                }
            };
            let host = rng.pick(&[
                "db.example.com",
                "localhost",
                "10.0.0.5",
                "[::1]",
                "cache.internal",
                "mq.example.org",
            ]);
            let port = if rng.chance(50) {
                format!(":{}", rng.range(1024, 65535))
            } else {
                String::new()
            };
            let path = rng.pick(&["", "/app_db", "/0", "/vhost", "/inbox?ssl=true"]);
            Sample {
                class,
                text: format!("{scheme}://{user}:{password}@{host}{port}{path}"),
                secret: password,
            }
        }
        other => unreachable!("no generator for {other}"),
    }
}

/// A PEM block: a private key when `private`, otherwise a public object of the same shape.
pub(crate) fn pem(rng: &mut Prng, private: bool) -> String {
    let label = if private {
        rng.pick(&[
            "RSA PRIVATE KEY",
            "EC PRIVATE KEY",
            "DSA PRIVATE KEY",
            "OPENSSH PRIVATE KEY",
            "ENCRYPTED PRIVATE KEY",
            "PRIVATE KEY",
            "PGP PRIVATE KEY BLOCK",
        ])
    } else {
        rng.pick(&[
            "PUBLIC KEY",
            "RSA PUBLIC KEY",
            "CERTIFICATE",
            "CERTIFICATE REQUEST",
            "X509 CRL",
            "PGP PUBLIC KEY BLOCK",
        ])
    };
    let nl = if rng.chance(20) { "\r\n" } else { "\n" };
    let mut body = String::new();
    if label.starts_with("PGP") {
        body.push_str("Version: GnuPG v2");
        body.push_str(nl);
        body.push_str(nl);
    }
    for _ in 0..rng.range(3, 25) {
        body.push_str(&rng.chars(B64, 64));
        body.push_str(nl);
    }
    body.push_str(&rng.chars_in(B64, 4, 60));
    body.push_str(rng.pick(&["", "=", "=="]));
    format!("-----BEGIN {label}-----{nl}{body}{nl}-----END {label}-----")
}

/// How a positive is presented (corpus v2). Plain and glued forms test the detectors' boundaries;
/// the nested and percent forms test the decoded views.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Form {
    /// Embedded in a context as it is.
    Plain,
    /// With separator glue on the left and word glue on the right (`${KEY:-…}`, `KEY_…_prod`).
    Glued,
    /// Inside a JSON document carried as a string (a tool call's arguments), with the secret's
    /// characters `\u`-escaped at that inner level.
    Nested,
    /// The nested document again inside a JSON string (a double-escaped `partial_json` delta).
    DoubleNested,
    /// Percent-encoded (a query string), or form-encoded with `+` for a space (a form body).
    Percent,
    /// Every `/` JSON-escaped as `\/` (and every backslash as two), as PHP's `json_encode`
    /// writes it.
    SlashEscaped,
}

impl Form {
    pub(crate) fn pick(rng: &mut Prng) -> Self {
        match rng.below(10) {
            0..=2 => Self::Plain,
            3..=4 => Self::Glued,
            5..=6 => Self::Nested,
            7 => Self::DoubleNested,
            8 => Self::Percent,
            _ => Self::SlashEscaped,
        }
    }
}

/// Left glue that is not part of a token: a separator, so the secret must still be found.
const GLUE_LEFT: &[&str] = &["_", "-", "$", "=", ":-", "${KEY:-", "KEY_", "x.", "/", "+"];
/// Right glue: more of the same characters (covered with the secret) or a separator.
const GLUE_RIGHT: &[&str] = &["_prod", "xyz", "}", "_", "ZZ9", "-1", ";", ".", "+x"];
/// Stands in for the secret while a nested document is built.
const MARK: &str = "@@SECRET@@";

/// `text` presented in `form`.
pub(crate) fn present(rng: &mut Prng, text: &str, form: Form) -> String {
    match form {
        Form::Plain => embed(rng, text),
        Form::Glued => {
            let left = rng.pick(GLUE_LEFT);
            let right = rng.pick(GLUE_RIGHT);
            embed(rng, &format!("{left}{text}{right}"))
        }
        Form::Nested => nested_json(rng, text),
        Form::DoubleNested => {
            let inner = nested_json(rng, text);
            serde_json::to_string(&serde_json::json!({ "type": "input_json_delta", "partial_json": inner })).unwrap()
        }
        Form::Percent => {
            let encoded = if rng.chance(50) {
                percent_encoded(text)
            } else {
                form_encoded(text)
            };
            embed(rng, &encoded)
        }
        Form::SlashEscaped => {
            // A JSON encoder escapes the backslash itself first, then the slash.
            let escaped = text.replace('\\', "\\\\").replace('/', "\\/");
            embed(rng, &escaped)
        }
    }
}

/// A tool call's arguments as JSON text, with `text` inside a string and escaped there.
fn nested_json(rng: &mut Prng, text: &str) -> String {
    let context = embed(rng, MARK);
    let tool = rng.pick(&["bash", "write_file", "http_request"]);
    let doc = serde_json::json!({ "tool": tool, "arguments": { "input": context } });
    let escaped = escaped_for_json(rng, text);
    serde_json::to_string(&doc).unwrap().replace(MARK, &escaped)
}

/// `text` as JSON string content with characters `\u`-escaped: all of them, or every
/// non-alphanumeric one and a random half of the rest.
fn escaped_for_json(rng: &mut Prng, text: &str) -> String {
    let all = rng.chance(50);
    let mut out = String::new();
    for c in text.chars() {
        if all || !c.is_ascii_alphanumeric() || rng.chance(50) {
            for unit in c.encode_utf16(&mut [0; 2]) {
                let _infallible = write!(out, "\\u{unit:04x}");
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Every byte that is not alphanumeric as `%XX`.
pub(crate) fn percent_encoded(text: &str) -> String {
    let mut out = String::new();
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() {
            out.push(char::from(b));
        } else {
            let _infallible = write!(out, "%{b:02X}");
        }
    }
    out
}

/// Form encoding: every byte that is not alphanumeric or `*-._` as `%XX`, a space as `+`.
pub(crate) fn form_encoded(text: &str) -> String {
    let mut out = String::new();
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || b"*-._".contains(&b) {
            out.push(char::from(b));
        } else if b == b' ' {
            out.push('+');
        } else {
            let _infallible = write!(out, "%{b:02X}");
        }
    }
    out
}

/// Test oracle, independent of the crate: `%XX` decoded (any byte), everything else kept.
pub(crate) fn percent_decoded(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = bytes
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match (bytes[i], hex) {
            (b'%', Some(byte)) => {
                out.push(byte);
                i += 3;
            }
            (b, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Test oracle, independent of the crate: what a reader can recover from `text`. That is the
/// text, its percent- and form-decoding, its JSON string unescaping, and, when it is JSON,
/// every string in it, recursively.
pub(crate) fn visible(text: &str, out: &mut Vec<String>) {
    out.push(text.to_owned());
    out.push(percent_decoded(text));
    out.push(percent_decoded(&text.replace('+', " ")));
    out.push(text.replace("\\/", "/"));
    if let Ok(serde_json::Value::String(s)) = serde_json::from_str(&format!("\"{text}\"")) {
        out.push(s);
    }
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
        visible_value(&v, out);
    }
}

/// [`visible`] for every key and string of a JSON value.
pub(crate) fn visible_value(v: &serde_json::Value, out: &mut Vec<String>) {
    use serde_json::Value;
    match v {
        Value::String(s) => visible(s, out),
        Value::Array(items) => items.iter().for_each(|i| visible_value(i, out)),
        Value::Object(map) => {
            for (k, v) in map {
                visible(k, out);
                visible_value(v, out);
            }
        }
        _ => {}
    }
}

/// Whether `secret` can be recovered from `text` (see [`visible`]).
pub(crate) fn leaks(text: &str, secret: &str) -> bool {
    let mut out = Vec::new();
    visible(text, &mut out);
    out.iter().any(|s| s.contains(secret))
}

/// A string that contains no secret of any claimed class, built to look as close to one as
/// possible, and the name of its family (false positives are counted per family).
#[allow(clippy::too_many_lines, reason = "one near-miss family per arm")]
pub(crate) fn negative(rng: &mut Prng) -> (&'static str, String) {
    let (family, core) = match rng.below(47) {
        0..=5 => return ("prose", prose(rng)),
        6..=7 => ("code", code_line(rng)),
        8 => ("anthropic-short", format!("sk-ant-{}", rng.chars_in(TOKEN, 5, 31))),
        9 => ("openai-unmarked", format!("sk-{}", rng.chars_in(ALNUM, 20, 80))),
        10 => (
            "openai-sk-learn",
            "sk-learn-pipeline-estimator-transformer-grid-search-cross-validation".to_owned(),
        ),
        11 => (
            "aws-short",
            format!("{}{}", rng.pick(&["AKIA", "ASIA"]), rng.chars_of(BASE32, &[12, 15])),
        ),
        // The run of `[A-Z0-9]` breaks before 16 characters.
        12 => (
            "aws-broken-run",
            format!(
                "{}{}{}{}",
                rng.pick(&["AKIA", "ASIA"]),
                rng.chars_in(BASE32, 4, 15),
                rng.pick(&["a", "_", "-", "."]),
                rng.chars(BASE32, 16)
            ),
        ),
        13 => ("aws-lowercase", format!("akia{}", rng.chars(BASE32, 16))),
        14 => ("aws-wrong-prefix", format!("AKIB{}", rng.chars(BASE32, 16))),
        15 => ("github-short", format!("ghp_{}", rng.chars_of(ALNUM, &[20, 35]))),
        16 => (
            "github-broken-run",
            format!(
                "ghp_{}{}{}",
                rng.chars_in(ALNUM, 10, 35),
                rng.pick(&["_", "-", "."]),
                rng.chars(ALNUM, 20)
            ),
        ),
        17 => (
            "github-wrong-prefix",
            format!("{}_{}", rng.pick(&["ghx", "GHP", "ghq"]), rng.chars(ALNUM, 36)),
        ),
        18 => ("github-pat-short", format!("github_pat_{}", rng.chars(ALNUM, 30))),
        19 => ("gitlab-short", format!("glpat-{}", rng.chars_in(TOKEN, 5, 19))),
        20 => (
            "gitlab-wrong-prefix",
            format!("{}{}", rng.pick(&["glpat_", "glxat-"]), rng.chars(TOKEN, 20)),
        ),
        21 => ("slack-short", format!("xoxb-{}", rng.chars_in(ALNUM, 5, 14))),
        22 => (
            "slack-wrong-prefix",
            format!("{}{}", rng.pick(&["xoxz-", "xox-"]), rng.chars(ALNUM, 30)),
        ),
        23 => ("stripe-short", format!("sk_live_{}", rng.chars_in(ALNUM, 5, 23))),
        24 => ("stripe-publishable", format!("pk_live_{}", rng.chars_in(ALNUM, 24, 99))),
        25 => ("stripe-wrong-mode", format!("sk_prod_{}", rng.chars(ALNUM, 30))),
        26 => ("google-short", format!("AIza{}", rng.chars_of(ALNUM, &[20, 34]))),
        27 => (
            "google-wrong-prefix",
            format!("{}{}", rng.pick(&["aiza", "AIzb"]), rng.chars(TOKEN, 35)),
        ),
        28 => ("pem-public", pem(rng, false)),
        29 => ("jwt-one-part", format!("eyJ{}", rng.chars_in(TOKEN, 20, 60))),
        30 => (
            "jwt-two-parts",
            format!("eyJ{}.eyJ{}", rng.chars(TOKEN, 20), rng.chars(TOKEN, 30)),
        ),
        31 => (
            "jwt-short-signature",
            format!(
                "eyJ{}.eyJ{}.{}",
                rng.chars(TOKEN, 20),
                rng.chars(TOKEN, 30),
                rng.chars(TOKEN, 8)
            ),
        ),
        32 => (
            "jwt-payload-not-json",
            format!(
                "eyJ{}.{}.{}",
                rng.chars(TOKEN, 20),
                rng.chars(TOKEN, 30),
                rng.chars(TOKEN, 43)
            ),
        ),
        33 => (
            "url-no-password",
            rng.pick(&[
                "https://example.com/path?x=1",
                "https://user@host.example.com/repo",
                "https://host.example.com:8443/x",
                "http://localhost:3000/@user/profile",
                "ssh://git@github.com/org/repo.git",
                "mailto:user@example.com",
                "postgres://user:@localhost/db",
                "https://registry.example.com/@scope/pkg:1.0@latest",
                "ftp://anonymous@ftp.example.com/pub",
            ])
            .to_owned(),
        ),
        34 => ("uuid", uuid(rng)),
        35 => ("hex-digest", rng.chars_of(HEX, &[40, 64])),
        36 => ("base64", rng.chars_in(B64, 16, 200)),
        37 => ("upper-digit", rng.chars_in(UPPER_DIGIT, 10, 40)),
        38 => {
            let n = rng.range(20, 200);
            let noise = (0..n)
                .map(|_| char::from(u8::try_from(rng.range(32, 126)).unwrap()))
                .collect();
            ("printable-noise", noise)
        }
        39 => (
            "pem-prose",
            format!("the {} header starts with BEGIN PRIVATE KEY", rng.pick(WORDS)),
        ),
        // A host and port followed by a path containing `@`: not userinfo ('s rule).
        40 => {
            let host = rng.pick(&[
                "localhost",
                "api.example.com",
                "10.0.0.5",
                "[::1]",
                "registry.npmjs.org",
            ]);
            let path = format!("{}/@{}", rng.pick(WORDS), rng.pick(&["user", "scope", "me", "v2"]));
            let tail = rng.pick(&["", "/profile", "?tab=repos", "#top"]);
            (
                "url-port-path",
                format!(
                    "{}://{host}:{}/{path}{tail}",
                    rng.pick(&["http", "https"]),
                    rng.range(1, 65535)
                ),
            )
        }
        // Escaped text with no secret in any view.
        41 => {
            let doc = serde_json::json!({ "path": "C:\\new\\tools", "text": prose(rng), "regex": "\\d+\\s*" });
            let text = serde_json::to_string(&doc).unwrap();
            let twice = serde_json::to_string(&serde_json::json!({ "partial_json": text })).unwrap();
            ("escaped-text", if rng.chance(50) { text } else { twice })
        }
        // A percent-encoded query string with no secret.
        42 => (
            "percent-query",
            format!(
                "https://example.com/search?q={}&redirect={}",
                percent_encoded(&prose(rng)),
                percent_encoded("https://example.com/a?b=c@d")
            ),
        ),
        // Single-label service hosts with a port and a lowercase path containing `@`, scp-style git
        // URLs.
        43 => {
            let svc = rng.pick(&["web", "api", "db", "verdaccio", "minio", "keycloak", "my-svc"]);
            let path = rng.pick(&[
                "/@alice",
                "/@babel/core",
                "/users/@me",
                "/?email=bob@example.com",
                "/app?user=bob@corp.com",
                "/bucket/a@b.txt",
                "/app@sha256:4d2b1f0c9e8a",
            ]);
            let url = if rng.chance(15) {
                format!(
                    "git+ssh://git@github.com:{}/{}.git@v1.{}",
                    rng.pick(WORDS_LOWER),
                    rng.pick(WORDS_LOWER),
                    rng.below(9)
                )
            } else {
                format!(
                    "{}://{svc}:{}{path}",
                    rng.pick(&["http", "https", "jdbc:mysql"]),
                    rng.range(1, 65535)
                )
            };
            ("url-service-path", url)
        }
        // Templated passwords in configuration files.
        44 => {
            let var = rng.pick(&["POSTGRES_PASSWORD", "DB_PASS", "REDIS_PASSWORD", "MQ_SECRET"]);
            let password = match rng.below(4) {
                0 => format!("${{{var}}}"),
                1 => format!("${var}"),
                2 => format!("%({})s", var.to_lowercase()),
                _ => format!("{{{{{}}}}}", var.to_lowercase()),
            };
            let scheme = rng.pick(&["postgres", "redis", "mysql", "amqp"]);
            (
                "url-template-password",
                format!("{scheme}://app:{password}@db:5432/app"),
            )
        }
        // Two URLs joined by a separator, the second with a user and no password: neither holds a
        // password.
        45 => {
            let first = rng.pick(&[
                "http://mirror.example.com",
                "https://pypi.org/simple",
                "http://gitea:3000/org/repo.git",
                "http://web:8080/x",
                "http://localhost:8000/",
                "https://ci.example.com:8443/job",
                "http://localhost:8080",
                "http://web:8080",
            ]);
            let glue = rng.pick(&["\\n", "#", ")", "%0A", "!", "\u{2192}", ","]);
            let second = rng.pick(&[
                "ssh://git@github.com/org/repo.git",
                "https://git@github.com/org/repo",
                "git+ssh://git@gitlab.example.com/group/project.git",
                "jdbc:mysql://db:3306/app?user=bob@corp.com",
            ]);
            ("url-glued", format!("{first}{glue}{second}"))
        }
        // Already redacted: an exact placeholder is never a finding.
        _ => (
            "placeholder",
            format!(
                "postgres://app:[REDACTED:url_credentials:{}]@db.example.com/app [REDACTED:jwt:{}]",
                rng.chars(HEX, 16),
                rng.chars(HEX, 16)
            ),
        ),
    };
    (family, embed(rng, &core))
}

fn uuid(rng: &mut Prng) -> String {
    format!(
        "{}-{}-{}-{}-{}",
        rng.chars(HEX, 8),
        rng.chars(HEX, 4),
        rng.chars(HEX, 4),
        rng.chars(HEX, 4),
        rng.chars(HEX, 12)
    )
}

fn code_line(rng: &mut Prng) -> String {
    let ident = rng.pick(&[
        "value",
        "config_path",
        "retryCount",
        "user_id",
        "digest",
        "version",
        "endpoint",
    ]);
    let value = match rng.below(8) {
        0 => rng.range(0, 1_000_000).to_string(),
        1 => format!("\"{}\"", rng.pick(WORDS)),
        2 => format!("\"{}\"", uuid(rng)),
        3 => format!("\"sha256:{}\"", rng.chars(HEX, 64)),
        4 => format!("\"{}\"", rng.chars_in(B64, 16, 88)),
        5 => "\"/usr/local/bin/uaos\"".to_owned(),
        6 => "\"https://docs.example.com/api#auth\"".to_owned(),
        _ => format!("\"{}.{}.{}\"", rng.below(10), rng.below(30), rng.below(100)),
    };
    format!("let {ident} = {value};")
}
