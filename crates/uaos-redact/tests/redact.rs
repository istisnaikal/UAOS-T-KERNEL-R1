// SPDX-License-Identifier: Apache-2.0

//! Redaction behavior (P2 acceptance). Covered here: stable per-pocket placeholders, byte
//! preservation, schema-agnostic JSON at any depth (keys and unknown fields included), escape
//! evasion, fail-closed errors, the final scan, idempotence and no secrets in `Debug` output.

#![allow(
    clippy::unwrap_used,
    reason = "test harness helpers outside #[test] fns: a failed fixture must abort the test"
)]

mod common;

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fmt::Write as _;

use common::{Prng, Sample, embed, leaks, percent_encoded, prose, secret, visible_value};
use proptest::prelude::*;
use serde_json::{Map, Value, json};
use uaos_contracts::error::codes;
use uaos_platform::crypto::SecretKey;
use uaos_redact::{DataClass, DetectorVersion, FinalScanner, RedactError, Redactor};

const POCKET_KEY: [u8; 32] = [7; 32];

fn redactor() -> Redactor {
    Redactor::new(DetectorVersion::V1, SecretKey::from_bytes(POCKET_KEY)).unwrap()
}

fn scanner(known: &[&[u8]]) -> FinalScanner {
    FinalScanner::new(DetectorVersion::V1, known.iter().copied()).unwrap()
}

fn sample(class: DataClass, seed: u64) -> Sample {
    secret(&mut Prng::new(seed), class)
}

/// JSON-escapes every character as a `\u` escape: an attempt to slip a secret past a scanner
/// that only looks at raw bytes.
fn fully_escaped(s: &str) -> String {
    s.chars().fold(String::new(), |mut out, c| {
        let _infallible = write!(out, "\\u{:04x}", u32::from(c));
        out
    })
}

#[test]
fn placeholders_are_stable_per_pocket_and_differ_between_pockets() {
    let token = sample(DataClass::GithubToken, 1);
    let first = redactor().redact_text(&token.text).unwrap().output().to_owned();
    let after_restart = redactor().redact_text(&token.text).unwrap().output().to_owned();
    let other_pocket = Redactor::new(DetectorVersion::V1, SecretKey::from_bytes([8; 32]))
        .unwrap()
        .redact_text(&token.text)
        .unwrap()
        .output()
        .to_owned();
    assert_eq!(
        first, after_restart,
        "same pocket key: same placeholder after a restart"
    );
    assert_ne!(
        first, other_pocket,
        "placeholders do not correlate secrets across pockets"
    );
    let tag = first
        .strip_prefix("[REDACTED:github_token:")
        .and_then(|s| s.strip_suffix(']'))
        .unwrap();
    assert!(tag.len() == 16 && tag.bytes().all(|b| b.is_ascii_hexdigit()));
    let other = sample(DataClass::GithubToken, 2);
    assert_ne!(redactor().redact_text(&other.text).unwrap().output(), first);
}

#[test]
fn clean_json_is_returned_borrowed_byte_for_byte() {
    let body = format!(
        r#"{{"model":"m","messages":[{{"role":"user","content":"a \"quoted\" \/ path\n caf{}"}}],"n":1.50}}"#,
        fully_escaped("é")
    );
    let r = redactor().redact_json(body.as_bytes()).unwrap();
    assert!(r.is_clean());
    assert!(matches!(r.into_output(), Cow::Borrowed(b) if b == body.as_bytes()));
}

#[test]
fn json_redaction_changes_only_the_secret_bytes() {
    let key = sample(DataClass::AwsAccessKeyId, 3);
    let body = format!(
        r#"{{"a":"x\ty","b":{{"unknown":["id={}"]}},"c":"{}"}}"#,
        key.text,
        fully_escaped("é")
    );
    let r = redactor().redact_json(body.as_bytes()).unwrap();
    let placeholder = redactor().placeholder(DataClass::AwsAccessKeyId, &key.secret);
    assert_eq!(
        std::str::from_utf8(r.output()).unwrap(),
        body.replace(&key.secret, &placeholder)
    );
    assert_eq!(r.classes(), BTreeSet::from([DataClass::AwsAccessKeyId]));
}

#[test]
fn escaped_secrets_are_found_and_replaced_whole() {
    let key = sample(DataClass::AnthropicApiKey, 4);
    let body = format!(r#"{{"content":"key: {}"}}"#, fully_escaped(&key.secret));
    // The raw bytes do not show the key; the decoded string does, and so does the byte check's
    // nested view (it used to pass such bytes).
    assert!(!body.contains(key.secret.as_str()));
    assert!(
        scanner(&[])
            .check_bytes(body.as_bytes())
            .unwrap_err()
            .classes
            .contains(&DataClass::AnthropicApiKey)
    );
    let blocked = scanner(&[]).check_json(body.as_bytes()).unwrap_err();
    assert!(blocked.classes.contains(&DataClass::AnthropicApiKey));
    let r = redactor().redact_json(body.as_bytes()).unwrap();
    let out: Value = serde_json::from_slice(r.output()).unwrap();
    let expected = format!(
        "key: {}",
        redactor().placeholder(DataClass::AnthropicApiKey, &key.secret)
    );
    assert_eq!(out["content"], expected);
    assert!(scanner(&[]).check_json(r.output()).is_ok());
}

#[test]
fn private_keys_with_escaped_newlines_are_redacted_whole() {
    let key = sample(DataClass::PrivateKey, 5);
    let body = serde_json::to_vec(&json!({ "files": { "id_rsa": key.secret } })).unwrap();
    let r = redactor().redact_json(&body).unwrap();
    let out: Value = serde_json::from_slice(r.output()).unwrap();
    assert_eq!(
        out["files"]["id_rsa"],
        redactor().placeholder(DataClass::PrivateKey, &key.secret)
    );
}

fn object(key: String, value: Value) -> Value {
    let mut map = Map::new();
    map.insert(key, value);
    Value::Object(map)
}

#[test]
fn keys_unknown_fields_and_any_depth_are_scanned() {
    let token = sample(DataClass::StripeKey, 6);
    let mut deep = Value::String(format!("charge with {}", token.text));
    // 100 nesting levels: deeper than most parsers allow by default (serde_json stops at 128).
    for i in 0..50 {
        deep = object(format!("level{i}"), Value::Array(vec![deep]));
    }
    let mut doc = Map::new();
    doc.insert(token.text.clone(), Value::from(1));
    doc.insert("x_vendor_extension".to_owned(), deep);
    let body = serde_json::to_vec(&Value::Object(doc)).unwrap();
    let r = redactor().redact_json(&body).unwrap();
    let out = std::str::from_utf8(r.output()).unwrap();
    assert!(!out.contains(&token.secret));
    assert_eq!(out.matches("[REDACTED:stripe_key:").count(), 2);
    serde_json::from_slice::<Value>(r.output()).unwrap();
}

#[test]
fn malformed_input_fails_closed() {
    let lone_surrogate = format!(r#"{{"a":"{}"}}"#, "\\ud83d");
    let cases: [&[u8]; 4] = [
        br#"{"a":"open"#,
        br#"{"a":"\x"}"#,
        b"{\"a\":\"\xff\"}",
        lone_surrogate.as_bytes(),
    ];
    for bad in cases {
        assert_eq!(
            redactor().redact_json(bad).unwrap_err().code(),
            codes::REDACT_DETECTOR_FAILURE
        );
        let blocked = scanner(&[]).check_json(bad).unwrap_err();
        assert!(blocked.scanner_failure);
        assert_eq!(blocked.code(), codes::REDACT_DETECTOR_FAILURE);
    }
}

#[test]
fn final_scan_blocks_known_secrets_and_detections_but_passes_redacted_output() {
    let vault_key = b"custom-provider-secret-0123456789";
    let s = scanner(&[vault_key]);
    let body = format!(r#"{{"note":"my key is {}"}}"#, std::str::from_utf8(vault_key).unwrap());
    let blocked = s.check_json(body.as_bytes()).unwrap_err();
    assert!(blocked.known_secret && blocked.classes.is_empty());
    assert_eq!(blocked.code(), codes::REDACT_BLOCKED);
    assert!(!blocked.to_string().contains("custom-provider"), "never echoes content");
    assert!(s.check_bytes(body.as_bytes()).is_err());

    let token = sample(DataClass::GoogleApiKey, 7);
    let body = serde_json::to_vec(&json!({ "content": format!("use {}", token.text) })).unwrap();
    assert!(s.check_json(&body).is_err());
    let redacted = redactor().redact_json(&body).unwrap();
    assert!(s.check_json(redacted.output()).is_ok());

    // Content outside any string (a malformed body) is checked raw.
    let unquoted = format!(r#"{{"a": {} }}"#, sample(DataClass::AwsAccessKeyId, 10).text);
    assert!(
        s.check_json(unquoted.as_bytes())
            .unwrap_err()
            .classes
            .contains(&DataClass::AwsAccessKeyId)
    );

    assert_eq!(
        FinalScanner::new(DetectorVersion::V1, [b"short".as_slice()]).unwrap_err(),
        RedactError::KnownSecretTooShort
    );
}

#[test]
fn pinned_versions_are_enforced() {
    assert_eq!(
        Redactor::new(DetectorVersion(9), SecretKey::from_bytes(POCKET_KEY)).unwrap_err(),
        RedactError::UnknownDetectorVersion(9)
    );
    assert!(FinalScanner::new(DetectorVersion(9), std::iter::empty()).is_err());
    assert_eq!(redactor().version(), DetectorVersion::CURRENT);
}

#[test]
fn debug_output_never_contains_secrets() {
    let token = sample(DataClass::OpenaiApiKey, 8);
    let r = redactor().redact_text(&token.text).unwrap();
    let debug = format!("{r:?} {:?} {:?}", r.replacements(), redactor());
    assert!(!debug.contains(&token.secret));
    assert_eq!(r.replacements()[0].expose_secret(), token.secret);
}

#[test]
fn every_class_is_reported_for_policy() {
    let mut rng = Prng::new(9);
    let mut parts = Vec::new();
    for class in DataClass::ALL {
        let s = secret(&mut rng, class);
        parts.push(embed(&mut rng, &s.text));
    }
    let (red, text) = (redactor(), parts.join("\n"));
    let r = red.redact_text(&text).unwrap();
    assert_eq!(r.classes(), DataClass::ALL.into_iter().collect());
}

/// Prose with `count` secrets of random classes between it; returns the text and the secrets.
fn text_with_secrets(seed: u64, count: usize) -> (String, Vec<String>) {
    let mut rng = Prng::new(seed);
    let mut parts = vec![prose(&mut rng)];
    let mut secrets = Vec::new();
    for _ in 0..count {
        let class = rng.pick(&DataClass::ALL);
        let s = secret(&mut rng, class);
        parts.push(s.text);
        secrets.push(s.secret);
        parts.push(prose(&mut rng));
    }
    let separator = rng.pick(&[" ", "\n", ", ", "\t"]);
    (parts.join(separator), secrets)
}

#[test]
fn the_ci_seed_that_drew_a_stated_miss_is_redacted() {
    // In CI, the generator once drew a URL password starting with `//`
    // (`https://u://…@10.0.0.5`), a stated miss. The generator leaves such passwords out now, so
    // the input `text_redaction_removes_every_secret_and_is_a_fixpoint` reported is kept as a fixed
    // case of what is claimed.
    let (text, secrets) = text_with_secrets(4_814_893_562_051_029_426, 3);
    let r = redactor().redact_text(&text).unwrap();
    for s in &secrets {
        assert!(!r.output().contains(s.as_str()), "a secret survived redaction");
    }
    assert!(scanner(&[]).check_bytes(r.output().as_bytes()).is_ok());
}

#[test]
fn the_stress_seed_that_drew_a_stated_miss_is_redacted() {
    // A 20,000-case stress run drew `amqp://svc2:3/#5pi.m@mq.example.org` with this input: a
    // password that reads as `host:port/path`, a stated miss the generator now leaves out.
    let (text, secrets) = text_with_secrets(3_677_357_430_622_100_055, 3);
    let r = redactor().redact_text(&text).unwrap();
    for s in &secrets {
        assert!(!r.output().contains(s.as_str()), "a secret survived redaction");
    }
    assert!(scanner(&[]).check_bytes(r.output().as_bytes()).is_ok());
}

#[test]
fn the_generator_leaves_out_the_stated_misses() {
    // Stress seed 3677357430622100055 drew `amqp://svc2:3/#5pi.m@mq.example.org`, a password that
    // reads as `host:port/path`: a miss states since Amendment 1, which the generator did not leave
    // out. On each sample, the generator's verdict now matches the redactor's. The candidates are
    // synthetic, and a failure names the case without printing one.
    for (case, (user, candidate)) in [
        ("svc2", "3/#5pi.m"),
        ("app", "8080?x=1"),
        ("u", "${DB_PASS}"),
        ("root", "$ABC_1"),
        ("app", "%(db_pass)s"),
        ("app", "{{db_pass}}"),
        ("svc", "70000/x.y"),
        ("svc", "123456/a"),
        ("svc", "ab://cd"),
        ("app", "3/Xk!q"),
        ("deploy", "hunter2hunter2"),
        ("u", "//pw0rd"),
    ]
    .into_iter()
    .enumerate()
    {
        let text = format!("amqp://{user}:{candidate}@mq.example.org");
        let missed = redactor().redact_text(&text).unwrap().output().contains(candidate);
        assert_eq!(
            common::stated_miss(user, candidate),
            missed,
            "the generator and the redactor disagree on case {case} (user {user})"
        );
    }
}

fn json_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        (any::<u64>(), 0..3_usize).prop_map(|(seed, n)| Value::String(text_with_secrets(seed, n).0)),
        any::<i64>().prop_map(Value::from),
        any::<bool>().prop_map(Value::Bool),
        Just(Value::Null),
    ];
    leaf.prop_recursive(4, 48, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::vec(((any::<u64>(), 0..2_usize), inner), 0..6).prop_map(|entries| {
                Value::Object(
                    entries
                        .into_iter()
                        .map(|((seed, n), v)| (text_with_secrets(seed, n).0, v))
                        .collect(),
                )
            }),
        ]
    })
}

fn map_strings(v: &Value, f: &dyn Fn(&str) -> String) -> Value {
    match v {
        Value::String(s) => Value::String(f(s)),
        Value::Array(items) => Value::Array(items.iter().map(|i| map_strings(i, f)).collect()),
        Value::Object(map) => Value::Object(map.iter().map(|(k, v)| (f(k), map_strings(v, f))).collect()),
        other => other.clone(),
    }
}

proptest! {
    #[test]
    fn text_redaction_removes_every_secret_and_is_a_fixpoint(seed in any::<u64>(), count in 0..5_usize) {
        let (text, secrets) = text_with_secrets(seed, count);
        let r = redactor().redact_text(&text).unwrap();
        for s in &secrets {
            prop_assert!(!r.output().contains(s.as_str()), "a secret survived redaction");
        }
        prop_assert_eq!(r.is_clean(), secrets.is_empty());
        prop_assert!(redactor().redact_text(r.output()).unwrap().is_clean(), "redact(redact(x)) != redact(x)");
        prop_assert!(scanner(&[]).check_bytes(r.output().as_bytes()).is_ok());
    }

    #[test]
    fn json_redaction_is_schema_agnostic(doc in json_value(), pretty in any::<bool>()) {
        let body = if pretty { serde_json::to_vec_pretty(&doc) } else { serde_json::to_vec(&doc) }.unwrap();
        let red = redactor();
        let r = red.redact_json(&body).unwrap();
        let out: Value = serde_json::from_slice(r.output()).unwrap();
        let expected = map_strings(&doc, &|s| red.redact_text(s).unwrap().into_output().into_owned());
        prop_assert_eq!(out, expected, "JSON redaction must equal text redaction of every string");
        prop_assert!(scanner(&[]).check_json(r.output()).is_ok());
        prop_assert!(red.redact_json(r.output()).unwrap().is_clean());
        if r.is_clean() {
            prop_assert_eq!(r.output(), body.as_slice(), "clean bodies pass byte for byte");
        }
    }

    #[test]
    fn arbitrary_bytes_never_panic_and_errors_block(
        bytes in prop::collection::vec(prop::sample::select(b"u\"\\0123456789abcdefABCDEF{}[]:,dD8 \xff".to_vec()), 0..256)
    ) {
        let red = redactor();
        let redacted = red.redact_json(&bytes);
        let checked = scanner(&[]).check_json(&bytes);
        // Every refusal of the shared tokenizer blocks, never redacts.
        if uaos_json::parse(&bytes, &uaos_json::Limits::DEFAULT).is_err() {
            prop_assert!(redacted.is_err(), "a body the tokenizer refuses was redacted, not blocked");
        }
        // A fault inside a string blocks at the final scan too. A structural refusal blocks at
        // redaction; the final scan, independent of the tokenizer by design, may pass the same
        // bytes.
        if let Err(RedactError::InvalidUtf8 | RedactError::MalformedJson(_)) = &redacted {
            prop_assert!(checked.is_err(), "a string-level refusal passed the final scan");
        }
        if let Ok(r) = redacted {
            prop_assert!(scanner(&[]).check_json(r.output()).is_ok());
        }
    }
}

/// Asserts that every path handles `text` carrying `secret` of `class`: text redaction and JSON
/// redaction remove it from everything a reader can recover, and both final-scan entry points
/// block the unredacted content with the class.
fn assert_every_path_redacts(text: &str, secret: &str, class: DataClass) {
    let red = redactor();
    let s = scanner(&[]);
    let r = red.redact_text(text).unwrap();
    assert!(!leaks(r.output(), secret), "text redaction left a {class} secret");
    assert!(r.classes().contains(&class), "{class} not found");
    assert!(s.check_bytes(r.output().as_bytes()).is_ok());

    let body = serde_json::to_vec(&json!({ "messages": [{ "content": text }] })).unwrap();
    let rj = red.redact_json(&body).unwrap();
    let mut recovered = Vec::new();
    visible_value(&serde_json::from_slice(rj.output()).unwrap(), &mut recovered);
    assert!(
        !recovered.iter().any(|v| v.contains(secret)),
        "JSON redaction left a {class} secret"
    );
    assert!(s.check_json(rj.output()).is_ok());

    for blocked in [
        s.check_bytes(text.as_bytes()).unwrap_err(),
        s.check_json(&body).unwrap_err(),
    ] {
        assert!(blocked.classes.contains(&class), "the final scan missed {class}");
    }
}

/// A password with `/`, `#`, `?` or `'` passed all three paths.
#[test]
fn url_passwords_with_any_printable_byte_are_redacted() {
    for password in [
        "Zm9v/YmFy+cXV4=",
        "a#b",
        "what?now",
        "it's",
        "p@ss/w0rd",
        "x:y;z,(1)[2]{3}|~^",
    ] {
        let text = format!("DATABASE_URL=postgres://app:{password}@db.example.com:5432/app");
        assert_every_path_redacts(&text, password, DataClass::UrlCredentials);
    }
}

/// Separator glue, word glue on the right and over-long runs hid keys.
#[test]
fn glued_and_overlong_keys_are_redacted() {
    let ant = sample(DataClass::AnthropicApiKey, 20).secret;
    let gh = sample(DataClass::GithubToken, 21).secret;
    let stripe = sample(DataClass::StripeKey, 22).secret;
    let aws = sample(DataClass::AwsAccessKeyId, 23).secret;
    let cases = [
        (
            format!("${{ANTHROPIC_API_KEY:-{ant}}}"),
            ant.clone(),
            DataClass::AnthropicApiKey,
        ),
        (format!("_{gh}_"), gh.clone(), DataClass::GithubToken),
        (format!("STRIPE_KEY_{stripe}"), stripe.clone(), DataClass::StripeKey),
        (format!("{aws}SUFFIX9"), aws.clone(), DataClass::AwsAccessKeyId),
        (format!("{gh}moreword"), gh.clone(), DataClass::GithubToken),
        (
            format!("{stripe}{}", "Q".repeat(300)),
            stripe.clone(),
            DataClass::StripeKey,
        ),
    ];
    for (text, secret, class) in cases {
        assert_every_path_redacts(&text, &secret, class);
    }
}

/// JSON inside a JSON string was decoded one level only, so a secret escaped at the inner level (a
/// tool call's arguments, a `partial_json` delta) passed.
#[test]
fn secrets_nested_in_json_strings_are_redacted() {
    let key = sample(DataClass::OpenaiApiKey, 24);
    let arguments = format!(
        r#"{{"command":"export OPENAI_API_KEY={}"}}"#,
        fully_escaped(&key.secret)
    );
    assert!(!arguments.contains(key.secret.as_str()));
    assert_every_path_redacts(&arguments, &key.secret, DataClass::OpenaiApiKey);

    // One more level: the arguments streamed as a `partial_json` delta.
    let delta = serde_json::to_string(&json!({ "type": "input_json_delta", "partial_json": arguments })).unwrap();
    assert_every_path_redacts(&delta, &key.secret, DataClass::OpenaiApiKey);

    // The splice keeps the inner document valid JSON.
    let body = serde_json::to_vec(&json!({ "tool_use": { "input": arguments } })).unwrap();
    let out: Value = serde_json::from_slice(redactor().redact_json(&body).unwrap().output()).unwrap();
    let inner: Value = serde_json::from_str(out["tool_use"]["input"].as_str().unwrap()).unwrap();
    assert_eq!(
        inner["command"],
        format!(
            "export OPENAI_API_KEY={}",
            redactor().placeholder(DataClass::OpenaiApiKey, &key.secret)
        )
    );
}

/// The byte check ignored encodings, so form-encoded DSNs, percent-encoded PEM headers and
/// `\u`-escaped JSON Lines passed.
#[test]
fn encoded_secrets_in_raw_bytes_are_found() {
    let url = sample(DataClass::UrlCredentials, 25);
    let form = format!("dsn={}&pool=5", percent_encoded(&url.text));
    assert_every_path_redacts(&form, &url.secret, DataClass::UrlCredentials);

    let pem = sample(DataClass::PrivateKey, 26);
    assert_every_path_redacts(&percent_encoded(&pem.text), &pem.secret, DataClass::PrivateKey);

    let token = sample(DataClass::SlackToken, 27);
    let jsonl = format!("{{\"n\":1}}\n{{\"note\":\"{}\"}}\n", fully_escaped(&token.text));
    let blocked = scanner(&[]).check_bytes(jsonl.as_bytes()).unwrap_err();
    assert!(blocked.classes.contains(&DataClass::SlackToken));
}

/// A vault secret is matched in decoded views too.
#[test]
fn known_secrets_are_matched_through_encodings() {
    let vault_key = "custom-provider-secret/0123456789";
    let s = scanner(&[vault_key.as_bytes()]);
    for body in [
        percent_encoded(vault_key),
        format!("{{\"k\":\"{}\"}}", fully_escaped(vault_key)),
    ] {
        assert!(s.check_bytes(body.as_bytes()).unwrap_err().known_secret, "{body}");
    }
}

/// Fragments that steer random input toward the detectors' edge cases (no fuzzing with real anchors
/// existed).
const FRAGMENTS: &[&str] = &[
    "sk-ant-",
    "sk-",
    "T3BlbkFJ",
    "ghp_",
    "github_pat_",
    "glpat-",
    "xoxb-",
    "AKIA",
    "AIza",
    "eyJ",
    "-----BEGIN ",
    "PRIVATE KEY-----",
    "-----END ",
    "://",
    "@",
    ":",
    "/",
    "?",
    "#",
    "'",
    "%",
    "%40",
    "%2F",
    "\\",
    "\\\\",
    "\\n",
    "\\\"",
    "\"",
    "[REDACTED:jwt:",
    "]",
    ".",
    "_",
    "-",
    " ",
    "\n",
    "aaaaaaaaaaaaaaaaaaaa",
    "ZZZZZZZZZZZZZZZZ",
    "0123456789",
    "é",
    "ş",
];

fn anchored_text() -> impl Strategy<Value = String> {
    prop::collection::vec(prop::sample::select(FRAGMENTS), 0..64).prop_map(|parts| parts.concat())
}

proptest! {
    #[test]
    fn anchored_noise_is_redacted_to_a_clean_fixpoint(text in anchored_text()) {
        let red = redactor();
        let s = scanner(&[]);
        let r = red.redact_text(&text).unwrap();
        prop_assert!(s.check_bytes(r.output().as_bytes()).is_ok(), "the final scan rejects redacted text");
        prop_assert!(red.redact_text(r.output()).unwrap().is_clean(), "redact(redact(x)) != redact(x)");
        if r.is_clean() {
            prop_assert!(s.check_bytes(text.as_bytes()).is_ok(), "clean text must pass the final scan");
        }
        let body = serde_json::to_vec(&json!({ "a": text, "b": [text] })).unwrap();
        let rj = red.redact_json(&body).unwrap();
        prop_assert!(s.check_json(rj.output()).is_ok());
        let out: Value = serde_json::from_slice(rj.output()).unwrap();
        prop_assert_eq!(&out["a"], &Value::String(r.output().to_owned()), "JSON and text redaction agree");
    }
}

/// A JSON `\u` escape of `hex`, built at runtime.
fn u(hex: &str) -> String {
    format!("{}u{hex}", '\\')
}

/// `s` with `~` standing for a backslash.
fn bs(s: &str) -> String {
    s.replace('~', "\\")
}

/// Form encoding as browsers and `quote_plus` produce it: a space becomes `+`.
fn form_encoded(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
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

/// A synthetic secret access key, split so no key-shaped literal is committed.
const AWS_SECRET: &str = concat!("wJalrXUtnFEMI/K7", "MDENG/bPxRfiCY", "SYNTHETIC0KEY");

/// A user redacted in an earlier round (an AWS key id) hid the password, which a later view would
/// have found; the final scan passed the output.
#[test]
fn a_redacted_user_does_not_hide_the_password() {
    let id = sample(DataClass::AwsAccessKeyId, 30).secret;
    let escaped = AWS_SECRET.replace('/', &bs("~/"));
    for text in [
        format!("s3a://{id}:{escaped}@my-bucket/path"),
        format!("s3a://{id}%3Asecretpassw0rd@my-bucket"),
        format!("s3://{id}:pa{}ss-w0rd-1234@bucket", u("0026")),
    ] {
        let r = redactor().redact_text(&text).unwrap();
        assert!(r.classes().contains(&DataClass::UrlCredentials));
        for secret in ["wJalrXUtnFEMI", "secretpassw0rd", "ss-w0rd-1234", id.as_str()] {
            assert!(!leaks(r.output(), secret), "a secret survived");
        }
        assert!(scanner(&[]).check_bytes(r.output().as_bytes()).is_ok());
    }
    // The realistic shape: a tool result carrying a PHP-style escaped config.
    let inner = format!(
        "{{\"config\":\"s3a:{}{}{}:{escaped}@my-bucket{}path\"}}",
        bs("~/"),
        bs("~/"),
        id,
        bs("~/")
    );
    let body = serde_json::to_vec(&json!({ "messages": [{ "role": "tool", "content": inner }] })).unwrap();
    let rj = redactor().redact_json(&body).unwrap();
    let mut recovered = Vec::new();
    visible_value(&serde_json::from_slice(rj.output()).unwrap(), &mut recovered);
    assert!(!recovered.iter().any(|v| v.contains("wJalrXUtnFEMI")));
    assert!(scanner(&[]).check_json(rj.output()).is_ok());
}

/// Form encoding writes a space as `+`, so a form-encoded PEM key passed every path.
#[test]
fn form_encoded_keys_are_redacted() {
    let pem = sample(DataClass::PrivateKey, 31);
    let form = format!("name=deploy&private_key={}&x=1", form_encoded(&pem.text));
    assert_every_path_redacts(&form, &pem.secret, DataClass::PrivateKey);
    let url = sample(DataClass::UrlCredentials, 32);
    assert_every_path_redacts(
        &format!("dsn={}", form_encoded(&url.text)),
        &url.secret,
        DataClass::UrlCredentials,
    );
}

/// An escape tail on the left (still encoded three levels deep) made a plain key look glued, in
/// every view.
#[test]
fn escaped_left_neighbours_do_not_hide_keys() {
    let key = sample(DataClass::AwsAccessKeyId, 33).secret;
    let gh = sample(DataClass::GithubToken, 34).secret;
    for (text, secret, class) in [
        (
            format!("x{}{key}", bs("~~~~n")),
            key.as_str(),
            DataClass::AwsAccessKeyId,
        ),
        (format!("id=%252520{key}"), key.as_str(), DataClass::AwsAccessKeyId),
        (
            format!("token:{}{gh}", bs("~~~~t")),
            gh.as_str(),
            DataClass::GithubToken,
        ),
    ] {
        let r = redactor().redact_text(&text).unwrap();
        assert!(r.classes().contains(&class), "{class} not found");
        assert!(!r.output().contains(secret), "{class} survived");
        assert!(
            scanner(&[]).check_bytes(text.as_bytes()).is_err(),
            "the final scan missed {class}"
        );
    }
    let raw = format!("{{\"messages\":[{{\"content\":\"code{}{key}\"}}]}}", bs("~~~~~~~~n"));
    let rj = redactor().redact_json(raw.as_bytes()).unwrap();
    assert!(!String::from_utf8_lossy(rj.output()).contains(key.as_str()));
    assert!(scanner(&[]).check_json(raw.as_bytes()).is_err());
}

/// Replacements that open new windows, chained across views, exhausted the round budget and wedged
/// every request carrying the text. Such content is now replaced whole.
#[test]
fn a_crafted_cascade_is_replaced_whole_without_wedging() {
    let nl = "\n";
    let q = "Q".repeat(16);
    let pem = |d: &str, n: &str| {
        let begin = concat!("----BEGIN RSA PRIVATE", " KEY-----");
        let end = concat!("----END RSA PRIVATE", " KEY-----");
        format!("{d}{begin}{n}MIIabc{n}{d}{end}")
    };
    let parts = [
        format!("https://u:x{}y@host", pem("-", nl)),
        format!("https%3A//u:x{}y@host", pem("%2D", "%0A")),
        format!("https://u:abc%20{}KIA{q}@host", u("0041")),
        format!("https%253A//u:x{}y@host", pem("%252D", "%250A")),
        format!("https://u:abc%2520{}{}KIA{q}@host", bs("~"), u("0041")),
    ];
    let text = parts.join(nl);
    let r = redactor().redact_text(&text).unwrap();
    assert!(!r.is_clean());
    assert!(scanner(&[]).check_bytes(r.output().as_bytes()).is_ok());
    let body = serde_json::to_vec(&json!({ "messages": [{ "content": text }] })).unwrap();
    let rj = redactor().redact_json(&body).unwrap();
    assert!(scanner(&[]).check_json(rj.output()).is_ok());
}

/// Ordinary service URLs, scp paths and templated passwords are not credentials.
#[test]
fn service_urls_and_templates_are_not_redacted() {
    for text in [
        "docker://registry:5000/app@sha256:4d2b1f0c9e8a7b6c5d4e3f2a1b0c9d8e",
        "http://verdaccio:4873/@babel/core",
        "http://web:8000/?email=bob@example.com",
        "jdbc:mysql://db:3306/app?user=bob@corp.com",
        "pip install git+ssh://git@github.com:org/repo.git@v1.0",
        "DATABASE_URL: postgres://app:${POSTGRES_PASSWORD}@db:5432/app",
        "REDIS_URL=redis://:$REDIS_PASSWORD@redis:6379/0",
        "mysql://root:%(password)s@localhost/db",
    ] {
        assert!(redactor().redact_text(text).unwrap().is_clean(), "{text}");
        assert!(scanner(&[]).check_bytes(text.as_bytes()).is_ok(), "{text}");
    }
}

/// A backslash inside a password is covered.
#[test]
fn a_backslash_in_a_password_is_covered() {
    let text = bs("postgres://app:pa~ss9X@db.example.com/x");
    assert_every_path_redacts(&text, &bs("pa~ss9X"), DataClass::UrlCredentials);
}

/// A derived `Debug` printed the known-secret automaton, from which a probe reconstructed the vault
/// secret. Nothing secret-derived may reach `Debug` output.
#[test]
fn debug_output_carries_no_secret_material() {
    let canary = b"vault-provider-key-ZQXJ0123456789";
    let scanner = FinalScanner::new(DetectorVersion::V1, [canary.as_slice()]).unwrap();
    let shown = format!("{scanner:?} {scanner:#?}");
    assert!(
        shown.len() < 200,
        "Debug output is unexpectedly large: {} bytes",
        shown.len()
    );
    // No 4-byte window of the canary, in any form, appears in the output.
    let text = String::from_utf8_lossy(canary);
    for window in text.as_bytes().windows(4) {
        let w = String::from_utf8_lossy(window);
        assert!(!shown.contains(w.as_ref()), "Debug output contains {w:?}");
    }
    assert!(shown.contains("known_secrets: 1"));
}

/// Replacing a secret inside a key can make two keys equal; redaction parses its output again and
/// blocks instead of emitting a body the tokenizer would refuse.
#[test]
fn a_duplicate_made_by_redaction_blocks() {
    let secret = common::secret(&mut Prng::new(11), DataClass::AnthropicApiKey).secret;
    let red = redactor();
    let alone_body = format!(r#"{{"v":"{secret}"}}"#);
    let alone = red.redact_json(alone_body.as_bytes()).unwrap();
    let placeholder = alone.replacements()[0].placeholder().to_owned();
    let body = format!(r#"{{"{secret}":1,"{placeholder}":2}}"#);
    let refused = red.redact_json(body.as_bytes()).unwrap_err();
    assert_eq!(
        refused,
        RedactError::Malformed("redaction-duplicate-key"),
        "redaction emitted a body with a duplicate key"
    );
    assert_eq!(refused.code(), codes::INGRESS_MALFORMED);
    // The key edit that makes the duplicate is not the last edit: a value after it is redacted
    // too, and the duplicate must still block.
    let later = common::secret(&mut Prng::new(12), DataClass::GitlabToken).text;
    let body = format!(
        r#"{{"{secret}":1,"{placeholder}":2,"w":{}}}"#,
        serde_json::to_string(&later).unwrap()
    );
    assert_eq!(
        red.redact_json(body.as_bytes()).err(),
        Some(RedactError::Malformed("redaction-duplicate-key")),
        "a later edit hid the duplicate an earlier key edit made"
    );
    // The same secret in a key with no collision is redacted, and the output parses.
    let fine_body = format!(r#"{{"{secret}":1}}"#);
    let fine = red.redact_json(fine_body.as_bytes()).unwrap();
    assert!(uaos_json::parse(fine.output(), &uaos_json::Limits::DEFAULT).is_ok());
}

/// The first sample whose redaction makes a body longer: a placeholder longer than its secret.
/// None would leave the tests that need one comparing nothing, so the `unwrap` fails them.
fn a_growing_sample() -> String {
    let red = redactor();
    (40_u64..)
        .zip(DataClass::ALL)
        .map(|(seed, class)| sample(class, seed).text)
        .find(|text| {
            let body = serde_json::to_vec(&json!({ "v": text })).unwrap();
            red.redact_json(&body).unwrap().output().len() > body.len()
        })
        .unwrap()
}

fn limits(max_bytes: usize) -> uaos_json::Limits {
    uaos_json::Limits::new(u32::try_from(max_bytes).unwrap(), 128, 1 << 20).unwrap()
}

/// The output must fit the limits the tape was parsed under: the next reader parses it under the
/// same limits, and a placeholder can be longer than the secret it replaces.
#[test]
fn an_output_that_outgrows_the_limits_blocks() {
    let red = redactor();
    let body = serde_json::to_vec(&json!({ "v": a_growing_sample() })).unwrap();
    let grown = red.redact_json(&body).unwrap().output().len();
    let tight = limits(body.len());
    let tape = uaos_json::parse(&body, &tight).unwrap();
    let refused = red.redact_tape(&tape).unwrap_err();
    assert_eq!(refused, RedactError::TooLarge("redaction-output-too-large"));
    assert_eq!(refused.code(), codes::INGRESS_TOO_LARGE);
    // With room for the placeholder, the same body is redacted; one byte less is refused.
    let room = limits(grown);
    let tape = uaos_json::parse(&body, &room).unwrap();
    assert_eq!(red.redact_tape(&tape).unwrap().output().len(), grown);
    let short = limits(grown - 1);
    let tape = uaos_json::parse(&body, &short).unwrap();
    assert_eq!(
        red.redact_tape(&tape).err(),
        Some(RedactError::TooLarge("redaction-output-too-large")),
        "an output one byte over the limit came back"
    );
}

/// Redaction checks its output against the limits the tape was parsed under, not the defaults.
/// A body nested deeper than the default allows, accepted under a deeper limit, is redacted
/// although a secret in a key makes the redactor parse its output again.
#[test]
fn the_reparse_uses_the_tapes_limits() {
    let red = redactor();
    let secret = a_growing_sample();
    let depth = 200;
    let mut body = String::new();
    for _ in 0..depth {
        body.push_str(r#"{"a":"#);
    }
    body.push_str(&serde_json::to_string(&json!({ secret: 1 })).unwrap());
    for _ in 0..depth {
        body.push('}');
    }
    assert!(
        uaos_json::parse(body.as_bytes(), &uaos_json::Limits::DEFAULT).is_err(),
        "the body must be deeper than the default limit, or this test proves nothing"
    );
    let deep = uaos_json::Limits::new(32 << 20, 512, 1 << 20).unwrap();
    let tape = uaos_json::parse(body.as_bytes(), &deep).unwrap();
    let redacted = red.redact_tape(&tape).unwrap();
    assert!(!redacted.replacements().is_empty(), "the key's secret was not found");
    assert!(uaos_json::parse(redacted.output(), &deep).is_ok());
}

/// Only an output longer than the limit blocks. A private key's placeholder is much shorter
/// than the key, so a body exactly at the limit whose redaction shrinks it passes, although a
/// longer secret came first.
#[test]
fn an_output_that_shrinks_fits_at_the_limit() {
    let red = redactor();
    let token = sample(DataClass::GitlabToken, 70).text;
    let key = sample(DataClass::PrivateKey, 71).text;
    let body = serde_json::to_vec(&json!([token, key])).unwrap();
    let at_limit = limits(body.len());
    let tape = uaos_json::parse(&body, &at_limit).unwrap();
    let redacted = red.redact_tape(&tape).unwrap();
    assert!(redacted.output().len() < body.len(), "the fixture no longer shrinks");
    assert_eq!(redacted.replacements().len(), 2);
}

/// The overflow can come from the bytes after the last replacement: a growing secret first,
/// then a long plain tail. What is built up to the replacement fits; the whole output does not.
#[test]
fn an_overflow_in_the_tail_blocks() {
    let red = redactor();
    let tail = "x".repeat(4_096);
    let body = serde_json::to_vec(&json!([a_growing_sample(), tail])).unwrap();
    let tight = limits(body.len());
    let tape = uaos_json::parse(&body, &tight).unwrap();
    assert_eq!(
        red.redact_tape(&tape).unwrap_err(),
        RedactError::TooLarge("redaction-output-too-large"),
        "an output longer than the limit came back"
    );
}

/// Limits are too large, string-level faults keep the redactor's code, and every other structural
/// refusal is malformed and not retryable. One input per kind the tokenizer reports.
#[test]
fn every_tokenizer_refusal_maps_as_the_contract_says() {
    use uaos_json::ErrorKind as K;
    let deep = format!("{}{}", "[".repeat(129), "]".repeat(129));
    let many = format!("[{}0]", "0,".repeat(1 << 20));
    let long_key = format!(r#"{{"{}":1}}"#, "a".repeat(uaos_json::MAX_KEY_LEN + 1));
    let huge = vec![b' '; (32 << 20) + 1];
    let cases: Vec<(K, &[u8])> = vec![
        (K::TooLarge, &huge),
        (K::ByteOrderMark, b"\xEF\xBB\xBF{}"),
        (K::InvalidUtf8, b"\"\xff\""),
        (K::Empty, b"  "),
        (K::ControlCharacter, b"\"a\x01\""),
        (K::InvalidEscape, br#""\x""#),
        (K::InvalidUnicodeEscape, br#""\u12G4""#),
        (K::LoneSurrogate, br#""\ud800""#),
        (K::UnterminatedString, br#""abc"#),
        (K::InvalidNumber, b"01"),
        (K::InvalidLiteral, b"tru"),
        (K::ExpectedValue, b"[,]"),
        (K::ExpectedKey, b"{1:2}"),
        (K::ExpectedColon, br#"{"a" 1}"#),
        (K::ExpectedCommaOrClose, b"[1 2]"),
        (K::UnexpectedEnd, b"[1,"),
        (K::TrailingData, b"{} x"),
        (K::DuplicateKey, br#"{"a":1,"a":2}"#),
        (K::DepthExceeded, deep.as_bytes()),
        (K::TooManyNodes, many.as_bytes()),
        (K::KeyTooLong, long_key.as_bytes()),
    ];
    let red = redactor();
    for (kind, input) in cases {
        let found = uaos_json::parse(input, &uaos_json::Limits::DEFAULT).unwrap_err().kind();
        assert_eq!(found, kind, "the input for {kind:?} exercises {found:?}");
        let label = kind.code();
        let (expected, code) = match kind {
            K::TooLarge | K::DepthExceeded | K::TooManyNodes | K::KeyTooLong => {
                (RedactError::TooLarge(label), codes::INGRESS_TOO_LARGE)
            }
            K::InvalidUtf8 => (RedactError::InvalidUtf8, codes::REDACT_DETECTOR_FAILURE),
            K::InvalidEscape | K::InvalidUnicodeEscape | K::LoneSurrogate | K::UnterminatedString => {
                (RedactError::MalformedJson(label), codes::REDACT_DETECTOR_FAILURE)
            }
            _ => (RedactError::Malformed(label), codes::INGRESS_MALFORMED),
        };
        let refused = red.redact_json(input).unwrap_err();
        assert_eq!(refused, expected, "{kind:?} is mapped against the refusal table");
        assert_eq!(refused.code(), code, "{kind:?} carries the wrong code");
        let structural = code != codes::REDACT_DETECTOR_FAILURE;
        assert!(
            !structural || !uaos_contracts::error::spec(code).unwrap().retryable,
            "{kind:?} is a deterministic refusal with a retryable code"
        );
    }
}

/// A placeholder inside a key can push the key past the tokenizer's key limit. The re-parse after a
/// key edit refuses it with the tokenizer's own label, and the request blocks as too large, not as
/// malformed.
#[test]
fn a_key_that_outgrows_the_key_limit_blocks() {
    let red = redactor();
    let text = a_growing_sample();
    let escaped = serde_json::to_string(&text).unwrap().len() - 2;
    let key_at = |len: usize| {
        let key = format!("{} {text}", "a".repeat(len - 1 - escaped));
        let mut members = Map::new();
        members.insert(key, json!(1));
        serde_json::to_vec(&Value::Object(members)).unwrap()
    };
    // The key is exactly as long as the tokenizer allows; its redaction is longer.
    let body = key_at(uaos_json::MAX_KEY_LEN);
    assert!(uaos_json::parse(&body, &uaos_json::Limits::DEFAULT).is_ok());
    let refused = red.redact_json(&body).unwrap_err();
    assert_eq!(refused, RedactError::TooLarge("key_too_long"));
    assert_eq!(refused.code(), codes::INGRESS_TOO_LARGE);
    // A shorter key with the same secret is redacted, and the output parses.
    let short = key_at(1_000);
    let fine = red.redact_json(&short).unwrap();
    assert!(uaos_json::parse(fine.output(), &uaos_json::Limits::DEFAULT).is_ok());
}

/// Placeholders are ASCII and need no escape, so the raw splice equals what the kernel's one
/// encoder would write.
#[test]
fn placeholders_are_encoder_fixed_points() {
    let red = redactor();
    let mut rng = Prng::new(23);
    for class in DataClass::ALL {
        let sample = common::secret(&mut rng, class);
        let redacted = red.redact_text(&sample.text).unwrap();
        for replacement in redacted.replacements() {
            let mut encoded = Vec::new();
            uaos_json::encode_str(replacement.placeholder(), &mut encoded).unwrap();
            // `encode_str` writes a whole JSON string, quotes included.
            let expected = format!("\"{}\"", replacement.placeholder());
            assert_eq!(
                encoded,
                expected.as_bytes(),
                "a placeholder changes when encoded as JSON string content"
            );
        }
    }
}

// The final scan's independence from the shared tokenizer is not checked in this file: the final
// scan lives in `uaos-redact-scan`, which has no dependency path to `uaos-json`.
// `cargo xtask arch-check` enforces the graph, the clippy gate the files rustc reads, and the rest
// stays review. Seeded violations prove each check bites.

/// Redaction names the nodes it changed, so a module's view can mask them: a secret in a value
/// names that value's node; a secret in a key names the member whose key it is. The ids are the
/// tape's, and name the same nodes in the output.
#[test]
fn redaction_names_the_nodes_it_changed() {
    let token = sample(DataClass::GithubToken, 3);
    let body = format!(r#"{{"a":"clean","b":["x","key {t}"],"{t}":1}}"#, t = token.text);
    let tape = uaos_json::parse(body.as_bytes(), &uaos_json::Limits::DEFAULT).unwrap();
    let redaction = redactor().redact_tape(&tape).unwrap();
    let find = |want: &dyn Fn(&uaos_json::Node<'_, '_>) -> bool| tape.nodes().find(|n| want(n)).map(|n| n.id());
    let value = find(&|n| n.content_span().is_some_and(|s| body[s.range()].contains(&token.text))).unwrap();
    let member = find(&|n| n.key_span().is_some_and(|s| body[s.range()].contains(&token.text))).unwrap();
    let edited: Vec<(u32, bool)> = redaction
        .edited()
        .iter()
        .map(|e| (e.node().get(), e.is_key()))
        .collect();
    assert_eq!(edited, [(value.get(), false), (member.get(), true)]);
    let output = uaos_json::parse(redaction.output(), &uaos_json::Limits::DEFAULT).unwrap();
    assert_eq!(output.stats().nodes, tape.stats().nodes, "the same nodes in the output");
    assert!(
        redactor().redact_text(&token.text).unwrap().edited().is_empty(),
        "text has no tape"
    );
    let clean = uaos_json::parse(br#"{"a":"clean"}"#, &uaos_json::Limits::DEFAULT).unwrap();
    assert!(redactor().redact_tape(&clean).unwrap().edited().is_empty());
}
