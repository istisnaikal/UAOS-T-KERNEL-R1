// SPDX-License-Identifier: Apache-2.0

//! Gate `redaction-corpus` (P2): detector set v1 measured against synthetic corpus v2.
//!
//! For every claimed class, 3,000 positives are generated, each in one of five forms: plain,
//! glued to its neighbours, nested in a JSON string, double-nested, or percent-encoded. A
//! positive counts as detected only if all four paths hold:
//!
//! 1. text redaction removes the secret from every view a reader can recover;
//! 2. JSON redaction removes it everywhere: in a chat message and inside an unknown nested
//!    field, with the output still valid JSON and passing the final scan;
//! 3. the final scan of the JSON body blocks the unredacted body, naming the class;
//! 4. the final scan of the raw text blocks it too, naming the class.
//!
//! "Recover" is decided by an oracle independent of the crate: `serde_json` for JSON at any
//! depth, plus percent-decoding.
//!
//! In addition, 100,000 hard negatives in named families are checked. The thresholds:
//! recall ≥ 99.9 % per class, and false positives ≤ 0.5 % per class **and** per
//! negative family. With 3,000 positives, zero misses bounds recall above 99.9 % at 95 %
//! confidence (the rule of three).

#![allow(
    clippy::unwrap_used,
    clippy::print_stdout,
    reason = "test harness: fixtures abort on failure, and the corpus report is printed"
)]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use common::{CORPUS_SEED, Form, Prng, leaks, negative, present, secret, visible_value};
use serde_json::{Value, json};
use uaos_platform::crypto::SecretKey;
use uaos_redact::{DataClass, DetectorVersion, FinalScanner, Redactor};

const POSITIVES_PER_CLASS: usize = 3_000;
const NEGATIVES: usize = 100_000;

#[derive(Debug, Default)]
struct Tally {
    positives: usize,
    missed: usize,
    leaked_text: usize,
    leaked_json: usize,
    not_blocked: usize,
    wrong_class: usize,
    false_positives: usize,
    missed_by_form: BTreeMap<Form, usize>,
}

#[derive(Debug, Default)]
struct Family {
    samples: usize,
    false_positives: usize,
}

/// Corpus v2 on merge runs; nightly runs explore other seeds via `UAOS_CORPUS_SEED`.
#[allow(clippy::disallowed_methods, reason = "test configuration knob, read once")]
fn corpus_seed() -> u64 {
    std::env::var("UAOS_CORPUS_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(CORPUS_SEED)
}

/// `part / whole` as a percentage with three decimals, in integer arithmetic.
fn percent(part: usize, whole: usize) -> String {
    let milli = part * 100_000 / whole.max(1);
    format!("{}.{:03}%", milli / 1000, milli % 1000)
}

#[test]
#[allow(clippy::too_many_lines, reason = "one gate: positives, negatives, report")]
fn corpus_v2() {
    let seed = corpus_seed();
    let redactor = Redactor::new(DetectorVersion::V1, SecretKey::from_bytes([0x42; 32])).unwrap();
    let scanner = FinalScanner::new(DetectorVersion::V1, std::iter::empty()).unwrap();
    let mut tally: BTreeMap<DataClass, Tally> = DataClass::ALL.iter().map(|&c| (c, Tally::default())).collect();
    let mut families: BTreeMap<&str, Family> = BTreeMap::new();
    let mut rng = Prng::new(seed);

    for class in DataClass::ALL {
        for _ in 0..POSITIVES_PER_CLASS {
            let sample = secret(&mut rng, class);
            let form = Form::pick(&mut rng);
            let context = present(&mut rng, &sample.text, form);
            let t = tally.get_mut(&class).unwrap();
            t.positives += 1;

            let text = redactor.redact_text(&context).unwrap();
            let leaked_text = leaks(text.output(), &sample.secret);
            if !text.classes().contains(&class) {
                t.wrong_class += 1;
            }

            let body = serde_json::to_vec(&json!({
                "model": "m",
                "messages": [{ "role": "user", "content": context }],
                "x_unknown": { "nested": [{ "deep": context }] },
            }))
            .unwrap();
            let redacted = redactor.redact_json(&body).unwrap();
            let mut recovered = Vec::new();
            visible_value(
                &serde_json::from_slice::<Value>(redacted.output()).unwrap(),
                &mut recovered,
            );
            let leaked_json = recovered.iter().any(|s| s.contains(sample.secret.as_str()))
                || scanner.check_json(redacted.output()).is_err();

            let not_blocked = !matches!(scanner.check_json(&body), Err(b) if b.classes.contains(&class))
                || !matches!(scanner.check_bytes(context.as_bytes()), Err(b) if b.classes.contains(&class));

            t.leaked_text += usize::from(leaked_text);
            t.leaked_json += usize::from(leaked_json);
            t.not_blocked += usize::from(not_blocked);
            let missed = leaked_text || leaked_json || not_blocked;
            t.missed += usize::from(missed);
            if missed {
                *t.missed_by_form.entry(form).or_default() += 1;
            }
        }
    }

    for _ in 0..NEGATIVES {
        let (family, text) = negative(&mut rng);
        let mut classes: BTreeSet<DataClass> = redactor.redact_text(&text).unwrap().classes();
        if let Err(blocked) = scanner.check_bytes(text.as_bytes()) {
            classes.extend(blocked.classes);
        }
        let f = families.entry(family).or_default();
        f.samples += 1;
        f.false_positives += usize::from(!classes.is_empty());
        for class in classes {
            tally.get_mut(&class).unwrap().false_positives += 1;
        }
    }

    let mut report = format!(
        "redaction corpus v2 (seed {seed:#018x}), detector set v1, {NEGATIVES} negatives in {} families\n\
         {:<18} {:>9} {:>7} {:>13} {:>11} {:>9} {:>10} {:>8}\n",
        families.len(),
        "class",
        "positives",
        "missed",
        "text/json/fs",
        "wrong-class",
        "recall",
        "false-pos",
        "fp-rate"
    );
    let mut failures = Vec::new();
    for (class, t) in &tally {
        let _infallible = writeln!(
            report,
            "{:<18} {:>9} {:>7} {:>13} {:>11} {:>9} {:>10} {:>8}",
            class.as_str(),
            t.positives,
            t.missed,
            format!("{}/{}/{}", t.leaked_text, t.leaked_json, t.not_blocked),
            t.wrong_class,
            percent(t.positives - t.missed, t.positives),
            t.false_positives,
            percent(t.false_positives, NEGATIVES),
        );
        // Recall >= 99.9 % <=> missed * 1000 <= positives.
        if t.missed * 1000 > t.positives {
            failures.push(format!(
                "class {class}: recall below 99.9% ({} of {} missed; by form {:?})",
                t.missed, t.positives, t.missed_by_form
            ));
        }
        if t.wrong_class * 1000 > t.positives {
            failures.push(format!(
                "class {class}: labelled as another class too often ({} of {})",
                t.wrong_class, t.positives
            ));
        }
        // False positives <= 0.5 % <=> fp * 200 <= negatives.
        if t.false_positives * 200 > NEGATIVES {
            failures.push(format!(
                "class {class}: false-positive rate above 0.5% ({} of {NEGATIVES})",
                t.false_positives
            ));
        }
    }
    let _infallible = writeln!(
        report,
        "\n{:<22} {:>8} {:>10} {:>8}",
        "family", "samples", "false-pos", "fp-rate"
    );
    for (name, f) in &families {
        let _infallible = writeln!(
            report,
            "{name:<22} {:>8} {:>10} {:>8}",
            f.samples,
            f.false_positives,
            percent(f.false_positives, f.samples)
        );
        if f.false_positives * 200 > f.samples {
            failures.push(format!(
                "family {name}: false-positive rate above 0.5% ({} of {})",
                f.false_positives, f.samples
            ));
        }
    }
    println!("{report}");
    assert!(failures.is_empty(), "{}\n{report}", failures.join("\n"));
}
