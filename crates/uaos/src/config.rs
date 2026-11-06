// SPDX-License-Identifier: Apache-2.0

//! The configuration: what it holds, the order its sources win in, and how it is refused.
//!
//! It holds no secrets. Before anything is parsed, the final scan reads the file's bytes and every
//! `UAOS_*` value this module reads, and any detection refuses the whole configuration. Messages
//! name a key, a line or a class, and never repeat a value: a secret no detector knows still does
//! not reach the terminal or a captured `--json` output.

use std::collections::BTreeMap;

use toml::{Table, Value};
use uaos_contracts::cli::{ConfigEntry, ConfigSource, ConfigValue};
use uaos_redact::{DetectorVersion, FinalScanner};
use uaos_runtime::LocaleTag;

/// The configuration file's name inside the data directory.
pub const FILE_NAME: &str = "config.toml";

/// The configuration `init` writes. It parses to the defaults (a test checks).
pub const DEFAULT_TEXT: &str = r#"# UAOS configuration. It holds no secrets: provider keys live in the OS keychain, and this
# file refers to them only by name. `uaos config show` prints the effective values.
config_version = 1

[kernel]
# The locale messages are rendered in, pinned per Operation.
locale = "en"

[admission]
# Operations, and request bytes, in flight at once.
max_operations = 64
max_bytes = 268435456

[journal]
# "balanced" flushes within 50 ms; "strict" flushes before every acknowledgement.
durability = "balanced"
"#;

/// What a key holds.
#[derive(Debug, Clone, Copy)]
enum Kind {
    /// `config_version`: exactly this number.
    Version(u64),
    /// A locale tag the runtime accepts.
    Locale,
    /// A whole number in a range.
    Integer { min: u64, max: u64 },
    /// One of a few words.
    Choice(&'static [&'static str]),
}

/// One configuration key.
#[derive(Debug, Clone, Copy)]
struct Key {
    /// The dotted name: a table and a field, or a top-level field.
    name: &'static str,
    /// The environment variable that overrides it, if any.
    env: Option<&'static str>,
    kind: Kind,
    default: Fallback,
}

/// A key's built-in value.
#[derive(Debug, Clone, Copy)]
enum Fallback {
    Integer(u64),
    Text(&'static str),
}

/// Every key, in the order `config show` prints them.
const KEYS: [Key; 5] = [
    Key {
        name: "config_version",
        env: None,
        kind: Kind::Version(1),
        default: Fallback::Integer(1),
    },
    Key {
        name: "kernel.locale",
        env: Some("UAOS_LOCALE"),
        kind: Kind::Locale,
        default: Fallback::Text("en"),
    },
    Key {
        name: "admission.max_operations",
        env: Some("UAOS_ADMISSION_MAX_OPERATIONS"),
        kind: Kind::Integer { min: 1, max: 65_536 },
        default: Fallback::Integer(64),
    },
    Key {
        name: "admission.max_bytes",
        env: Some("UAOS_ADMISSION_MAX_BYTES"),
        kind: Kind::Integer {
            min: 1 << 20,
            max: 64 << 30,
        },
        default: Fallback::Integer(256 << 20),
    },
    Key {
        name: "journal.durability",
        env: Some("UAOS_JOURNAL_DURABILITY"),
        kind: Kind::Choice(&["balanced", "strict"]),
        default: Fallback::Text("balanced"),
    },
];

/// Every environment variable this module reads, so the composition root can pass exactly these.
pub fn variables() -> impl Iterator<Item = &'static str> {
    KEYS.iter().filter_map(|k| k.env)
}

/// Why a configuration was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The final scan found what looks like a secret in `place` (the file, or a variable's
    /// name). `classes` are the detector classes; the value is never named.
    HoldsSecret {
        /// Where: `the file` or a variable's name.
        place: String,
        /// The detected classes.
        classes: Vec<&'static str>,
    },
    /// The configuration is invalid; the text names the key and what it expects.
    Invalid(String),
    /// The scanner itself could not be built: an internal failure.
    Scanner,
}

/// The effective configuration from the file's bytes (when there is a file) and the environment,
/// in the order the configuration lists its keys, each value with its source.
///
/// # Errors
/// [`Refusal`]: a secret, an invalid value, or a scanner failure. Nothing is partly applied.
pub fn load(file: Option<&[u8]>, env: &BTreeMap<String, String>) -> Result<Vec<ConfigEntry>, Refusal> {
    let scanner = FinalScanner::new(DetectorVersion::CURRENT, []).map_err(|_| Refusal::Scanner)?;
    if let Some(bytes) = file {
        scan(&scanner, bytes, "the file")?;
    }
    for name in variables() {
        if let Some(value) = env.get(name) {
            scan(&scanner, value.as_bytes(), name)?;
        }
    }
    let table = match file {
        Some(bytes) => Some(parse(bytes)?),
        None => None,
    };
    let mut entries = Vec::with_capacity(KEYS.len());
    for key in &KEYS {
        let from_env = key.env.and_then(|name| env.get(name).map(|v| (name, v)));
        let entry = if let Some((name, raw)) = from_env {
            ConfigEntry {
                key: key.name.to_owned(),
                value: from_text(key, raw).map_err(|why| Refusal::Invalid(format!("`{name}`: {why}")))?,
                source: ConfigSource::Env,
            }
        } else if let Some(value) = table.as_ref().and_then(|t| lookup(t, key.name)) {
            ConfigEntry {
                key: key.name.to_owned(),
                value: from_toml(key, value).map_err(|why| Refusal::Invalid(format!("`{}`: {why}", key.name)))?,
                source: ConfigSource::File,
            }
        } else if table.is_some() && matches!(key.kind, Kind::Version(_)) {
            return Err(Refusal::Invalid("`config_version` is missing; expected 1".to_owned()));
        } else {
            ConfigEntry {
                key: key.name.to_owned(),
                value: match key.default {
                    Fallback::Integer(n) => ConfigValue::Integer(n),
                    Fallback::Text(t) => ConfigValue::Text(t.to_owned()),
                },
                source: ConfigSource::Default,
            }
        };
        entries.push(entry);
    }
    Ok(entries)
}

fn scan(scanner: &FinalScanner, bytes: &[u8], place: &str) -> Result<(), Refusal> {
    scanner.check_bytes(bytes).map_err(|blocked| {
        let mut classes: Vec<&'static str> = blocked.classes.iter().map(|c| c.as_str()).collect();
        if blocked.known_secret {
            classes.push("known_secret");
        }
        if blocked.scanner_failure {
            classes.push("unscannable");
        }
        Refusal::HoldsSecret {
            place: place.to_owned(),
            classes,
        }
    })
}

/// Parses the file and checks its shape: only known tables and keys, each once.
fn parse(bytes: &[u8]) -> Result<Table, Refusal> {
    let text = std::str::from_utf8(bytes).map_err(|_| Refusal::Invalid("the file is not UTF-8".to_owned()))?;
    let table: Table = toml::from_str(text).map_err(|e| {
        let line = e
            .span()
            .map(|span| text.get(..span.start).map_or(0, |before| before.matches('\n').count()) + 1);
        Refusal::Invalid(match line {
            Some(line) => format!("the file is not valid TOML (line {line})"),
            None => "the file is not valid TOML".to_owned(),
        })
    })?;
    for (top, value) in &table {
        match value {
            Value::Table(inner) => {
                for field in inner.keys() {
                    let dotted = format!("{top}.{field}");
                    if !KEYS.iter().any(|k| k.name == dotted) {
                        return Err(Refusal::Invalid(unknown(&dotted)));
                    }
                }
                if !KEYS
                    .iter()
                    .any(|k| k.name.split_once('.').is_some_and(|(t, _)| t == top))
                {
                    return Err(Refusal::Invalid(unknown(top)));
                }
            }
            _ if KEYS.iter().any(|k| k.name == top && !k.name.contains('.')) => {}
            _ if KEYS
                .iter()
                .any(|k| k.name.split_once('.').is_some_and(|(t, _)| t == top)) =>
            {
                return Err(Refusal::Invalid(format!("`{top}` must be a table")));
            }
            _ => return Err(Refusal::Invalid(unknown(top))),
        }
    }
    Ok(table)
}

/// "unknown key `x`", naming the key only when it is a plain ASCII identifier, so nothing the
/// file holds is repeated otherwise.
fn unknown(key: &str) -> String {
    let plain = !key.is_empty()
        && key.len() <= 64
        && key
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.');
    if plain {
        format!("unknown key `{key}`")
    } else {
        "an unknown key".to_owned()
    }
}

fn lookup<'t>(table: &'t Table, dotted: &str) -> Option<&'t Value> {
    match dotted.split_once('.') {
        Some((top, field)) => table.get(top)?.as_table()?.get(field),
        None => table.get(dotted),
    }
}

fn from_toml(key: &Key, value: &Value) -> Result<ConfigValue, String> {
    match (key.kind, value) {
        (Kind::Version(_) | Kind::Integer { .. }, Value::Integer(n)) => {
            integer(key, u64::try_from(*n).map_err(|_| expects(key))?)
        }
        (Kind::Locale | Kind::Choice(_), Value::String(s)) => text(key, s),
        _ => Err(expects(key)),
    }
}

fn from_text(key: &Key, raw: &str) -> Result<ConfigValue, String> {
    match key.kind {
        Kind::Version(_) | Kind::Integer { .. } => {
            let digits = !raw.is_empty() && raw.len() <= 20 && raw.bytes().all(|b| b.is_ascii_digit());
            let n = if digits { raw.parse::<u64>().ok() } else { None };
            integer(key, n.ok_or_else(|| expects(key))?)
        }
        Kind::Locale | Kind::Choice(_) => text(key, raw),
    }
}

fn integer(key: &Key, n: u64) -> Result<ConfigValue, String> {
    let ok = match key.kind {
        Kind::Version(v) => n == v,
        Kind::Integer { min, max } => (min..=max).contains(&n),
        Kind::Locale | Kind::Choice(_) => false,
    };
    if ok {
        Ok(ConfigValue::Integer(n))
    } else {
        Err(expects(key))
    }
}

fn text(key: &Key, s: &str) -> Result<ConfigValue, String> {
    let ok = match key.kind {
        Kind::Locale => LocaleTag::new(s).is_ok(),
        Kind::Choice(words) => words.contains(&s),
        Kind::Version(_) | Kind::Integer { .. } => false,
    };
    if ok {
        Ok(ConfigValue::Text(s.to_owned()))
    } else {
        Err(expects(key))
    }
}

/// What a key expects, in words, without the value it got.
fn expects(key: &Key) -> String {
    match key.kind {
        Kind::Version(v) => format!("expected {v}"),
        Kind::Locale => "expected a locale tag such as `en` or `pt-BR`".to_owned(),
        Kind::Integer { min, max } => format!("expected a whole number from {min} to {max}"),
        Kind::Choice(words) => format!("expected one of: {}", words.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect()
    }

    fn values(entries: &[ConfigEntry]) -> Vec<(String, ConfigValue, ConfigSource)> {
        entries
            .iter()
            .map(|e| (e.key.clone(), e.value.clone(), e.source))
            .collect()
    }

    #[test]
    fn the_default_file_reads_as_the_defaults() {
        let from_file = load(Some(DEFAULT_TEXT.as_bytes()), &env(&[])).unwrap_or_default();
        let defaults = load(None, &env(&[])).unwrap_or_default();
        assert_eq!(from_file.len(), KEYS.len());
        for (f, d) in from_file.iter().zip(&defaults) {
            assert_eq!((&f.key, &f.value), (&d.key, &d.value));
            assert_eq!(f.source, ConfigSource::File);
            assert_eq!(d.source, ConfigSource::Default);
        }
    }

    #[test]
    fn a_variable_wins_over_the_file_and_the_file_over_the_default() {
        let file = b"config_version = 1\n[admission]\nmax_operations = 8\n";
        let got = load(Some(file), &env(&[("UAOS_JOURNAL_DURABILITY", "strict")])).unwrap_or_default();
        let got = values(&got);
        assert!(got.contains(&(
            "admission.max_operations".to_owned(),
            ConfigValue::Integer(8),
            ConfigSource::File
        )));
        assert!(got.contains(&(
            "journal.durability".to_owned(),
            ConfigValue::Text("strict".to_owned()),
            ConfigSource::Env
        )));
        assert!(got.contains(&(
            "kernel.locale".to_owned(),
            ConfigValue::Text("en".to_owned()),
            ConfigSource::Default
        )));
    }

    #[test]
    fn every_bad_shape_is_refused_without_its_value() {
        let cases: &[(&[u8], &str)] = &[
            (b"config_version = 2\n", "`config_version`: expected 1"),
            (b"[kernel]\nlocale = \"en\"\n", "`config_version` is missing"),
            (
                b"config_version = 1\n[kernel]\nlocal = \"en\"\n",
                "unknown key `kernel.local`",
            ),
            (b"config_version = 1\nextra = 3\n", "unknown key `extra`"),
            (
                b"config_version = 1\n[kernel]\nlocale = \"en\"\nlocale = \"tr\"\n",
                "line 4",
            ),
            (
                b"config_version = 1\n[admission]\nmax_bytes = 12\n",
                "from 1048576 to 68719476736",
            ),
            (
                b"config_version = 1\n[admission]\nmax_operations = \"hidden-value\"\n",
                "whole number",
            ),
            (
                b"config_version = 1\n[journal]\ndurability = \"hidden-value\"\n",
                "balanced, strict",
            ),
            (b"config_version = 1\n\"Wei\xc3\x9fe Kiste\" = 1\n", "an unknown key"),
            (b"config_version = 1\n\xff\n", "not UTF-8"),
            (b"config_version = 1\nkernel = 3\n", "`kernel` must be a table"),
        ];
        for (file, want) in cases {
            let got = load(Some(file), &env(&[]));
            let why = match &got {
                Err(Refusal::Invalid(why)) => why.clone(),
                _ => String::new(),
            };
            assert!(
                why.contains(want),
                "{:?}: {got:?} should say {want}",
                String::from_utf8_lossy(file)
            );
            assert!(!why.contains("hidden-value"), "{why} repeats a value");
        }
    }

    #[test]
    fn a_bad_variable_is_refused_by_its_name() {
        let got = load(None, &env(&[("UAOS_ADMISSION_MAX_BYTES", "lots")]));
        assert_eq!(
            got,
            Err(Refusal::Invalid(
                "`UAOS_ADMISSION_MAX_BYTES`: expected a whole number from 1048576 to 68719476736".to_owned()
            ))
        );
    }
}
