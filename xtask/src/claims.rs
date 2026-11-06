// SPDX-License-Identifier: Apache-2.0

//! Forbidden-claims lint over every text file in the repository (red line 6).
//!
//! Claims are carried by metrics, baselines and tests. Words that promise more than any test can
//! show ("perfect", "zero loss", "tamper-proof"...) fail the merge when they appear as a claim.
//! Three uses are not claims and pass.
//!
//! * **quoted** mentions: a pair of quotes or backticks encloses exactly the term, e.g. we say
//!   "tamper-evident", not "tamper-proof". A term inside a longer quoted span is still a claim:
//!   in code that span is a string literal, and help text and error messages make claims too;
//! * **negated** statements: a negation appears shortly before the term in the same sentence,
//!   e.g. "not tamper-proof", "do not claim the key is unobtainable";
//! * lines carrying an explicit exemption with a reason that is not blank, in any comment syntax:
//!   `<!-- claims-lint: allow (reason) -->`, `// claims-lint: allow (reason)`,
//!   `# claims-lint: allow (reason)`.
//!
//! **Scope.** Every file under the root is read, whatever its extension or directory, except build output, VCS
//! data (`util::walk_files`), [`SKIPPED`] and [`SKIPPED_DIRS`]:
//!
//! * a file whose extension `.gitattributes` declares `binary` (`*.png binary`) is not read;
//! * any other file must be UTF-8 text without a NUL byte. One that is not fails the check: the
//!   lint cannot read it, so it cannot vouch for it (fail closed). That covers UTF-16 text too;
//! * every [`SKIPPED`] entry must exist, so the list cannot hold a stale or misspelled path.
//!
//! Text that has to spell a forbidden term as data (the planted violations in `negative.rs`)
//! builds it from parts at run time instead of being skipped.

use std::path::Path;

use crate::util::{rel, walk_files};

const FORBIDDEN: &[&str] = &[
    "perfect",
    "faultless",
    "flawless",
    "zero loss",
    "zero-loss",
    "zero data loss",
    "zero-data-loss",
    "tamper-proof",
    "tamperproof",
    "unobtainable",
    "quota-bending",
    "quota bending",
    "rewind time",
    "rewinds time",
    "rewound time",
    "bulletproof",
    "unhackable",
    "100% secure",
    "military-grade",
];

const NEGATIONS: &[&str] = &["not", "never", "no", "nor", "without", "cannot"];
/// How far before a term (in characters) a negation still applies.
const NEGATION_WINDOW: usize = 40;
/// A reasoned exemption: the marker followed by a parenthesised reason, in any comment syntax.
const EXEMPTION_MARKER: &str = "claims-lint: allow (";
/// Files not read, each with the reason. Paths are relative to the root, with `/` separators.
const SKIPPED: &[(&str, &str)] = &[
    (
        "xtask/src/claims.rs",
        "defines the forbidden list; its tests hold the terms as fixtures",
    ),
    ("CODE_OF_CONDUCT.md", "third-party text (Contributor Covenant)"),
    (
        "supply-chain/imports.lock",
        "third-party audit notes imported by cargo vet, not ours to edit",
    ),
];
/// Directories not read, each with the reason: tool output that is never committed (ignored in
/// `.gitignore`). They need not exist.
const SKIPPED_DIRS: &[(&str, &str)] = &[
    ("fuzz/corpus/", "cargo-fuzz inputs: arbitrary bytes, ignored by git"),
    (
        "fuzz/artifacts/",
        "cargo-fuzz crash inputs: arbitrary bytes, ignored by git",
    ),
    ("fuzz/coverage/", "cargo-fuzz coverage output, ignored by git"),
];
/// Extensions not read, each with the reason: tool output that `.gitignore` ignores anywhere.
const SKIPPED_EXTENSIONS: &[(&str, &str)] = &[("profraw", "LLVM coverage output, ignored by git")];
/// Extensions read as prose, where a pair of straight quotes around a term is a mention. Anywhere
/// else a straight-quoted term is a string literal, which a user sees.
const PROSE_EXTENSIONS: &[&str] = &["md", "txt"];

pub(crate) fn check(root: &Path) -> Result<(), String> {
    let mut violations = Vec::new();
    let mut scanned = 0usize;
    let mut binary = 0usize;
    for (skipped, _) in SKIPPED {
        if !root.join(skipped).is_file() {
            violations.push(format!("{skipped}: listed in SKIPPED but not a file (stale entry)"));
        }
    }
    let binary_extensions = declared_binary_extensions(root)?;
    for path in walk_files(root)? {
        let relative = rel(root, &path);
        let extension = path.extension().and_then(|e| e.to_str()).unwrap_or_default();
        let skipped_dir = SKIPPED_DIRS.iter().any(|(dir, _)| relative.starts_with(dir));
        let skipped_extension = SKIPPED_EXTENSIONS.iter().any(|(e, _)| *e == extension);
        if skipped_dir || skipped_extension || SKIPPED.iter().any(|(skipped, _)| *skipped == relative) {
            continue;
        }
        let bytes = std::fs::read(&path).map_err(|e| format!("{relative}: {e}"))?;
        // A declared binary type is skipped only when the file really is not text: a declaration
        // cannot take text out of the scan (`*.md binary`), and git matches extensions by case, so
        // this does too.
        let declared_binary = binary_extensions.iter().any(|b| b == extension);
        if declared_binary && (bytes.contains(&0) || std::str::from_utf8(&bytes).is_err()) {
            binary += 1;
            continue;
        }
        if bytes.contains(&0) {
            violations.push(format!(
                "{relative}: holds a NUL byte, so the lint cannot read it as text (fail closed): \
                 convert it to UTF-8, or declare its type `*.{extension} binary` in .gitattributes"
            ));
            continue;
        }
        let Ok(text) = std::str::from_utf8(&bytes) else {
            violations.push(format!(
                "{relative}: not UTF-8, so the lint cannot read it (fail closed): convert it to UTF-8"
            ));
            continue;
        };
        scanned += 1;
        let prose = PROSE_EXTENSIONS.contains(&extension);
        for (n, line) in text.lines().enumerate() {
            if let Some(term) = claim_in(line, prose) {
                violations.push(format!("{relative}:{}: \"{term}\" used as a claim", n + 1));
            }
        }
    }
    if violations.is_empty() {
        println!(
            "xtask claims: {scanned} text file(s) free of forbidden claims ({binary} binary, {} skipped)",
            SKIPPED.len()
        );
        Ok(())
    } else {
        Err(format!(
            "{} claims-lint problem(s) (red line 6). A forbidden term used as a claim: \
             quote it, negate it, or back it with a measured statement:\n  {}",
            violations.len(),
            violations.join("\n  ")
        ))
    }
}

/// Extensions `.gitattributes` declares `binary` in the form `*.<ext> binary`. Only those files may
/// be skipped as binary, and only when they are not text; any other file holding a NUL fails. A
/// pattern of another form declares nothing here, which fails closed.
fn declared_binary_extensions(root: &Path) -> Result<Vec<String>, String> {
    let text = match std::fs::read_to_string(root.join(".gitattributes")) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!(".gitattributes: {e}")),
    };
    Ok(text
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let extension = fields.next()?.strip_prefix("*.")?;
            let plain = !extension.is_empty() && extension.bytes().all(|b| b.is_ascii_alphanumeric());
            (plain && fields.any(|attribute| attribute == "binary")).then(|| extension.to_owned())
        })
        .collect())
}

/// The first forbidden term used as a claim on `line`, if any. `prose` is true for Markdown and
/// plain text, where straight quotes around a term mark a mention.
fn claim_in(line: &str, prose: bool) -> Option<&'static str> {
    if exempted(line) {
        return None;
    }
    let lower = line.to_lowercase();
    for term in FORBIDDEN {
        for (at, _) in lower.match_indices(term) {
            let before = lower.get(..at).unwrap_or_default();
            let after = lower.get(at + term.len()..).unwrap_or_default();
            let word_start = !before.chars().next_back().is_some_and(char::is_alphanumeric);
            let word_end = !after.chars().next().is_some_and(char::is_alphanumeric);
            if !(word_start && word_end) {
                continue;
            }
            if quoted(before, after, prose) || negated(before) {
                continue;
            }
            return Some(term);
        }
    }
    None
}

/// The line carries the exemption marker with a reason that is not blank:
/// `claims-lint: allow (reason)`. An empty `()` exempts nothing.
fn exempted(line: &str) -> bool {
    line.match_indices(EXEMPTION_MARKER).any(|(at, _)| {
        let rest = line.get(at + EXEMPTION_MARKER.len()..).unwrap_or_default();
        rest.split_once(')')
            .is_some_and(|(reason, _)| !reason.trim().is_empty())
    })
}

/// The term is a mention: a matching pair of quotes or backticks encloses exactly the term, as in
/// `"tamper-proof"` or `` `perfect` ``. A term that merely sits inside a longer quoted span is not
/// a mention: in code that span is a string literal, and help text and error messages are claims
/// too. Outside prose, straight quotes never mark a mention, because `"flawless"` there is a string
/// literal on its own.
fn quoted(before: &str, after: &str, prose: bool) -> bool {
    const ANYWHERE: &[(char, char)] = &[('`', '`'), ('“', '”'), ('‘', '’')];
    const PROSE_ONLY: &[(char, char)] = &[('"', '"'), ('\'', '\'')];
    let open = before.chars().next_back();
    let close = after.chars().next();
    let pairs = ANYWHERE.iter().chain(PROSE_ONLY.iter().filter(|_| prose));
    pairs.into_iter().any(|(o, c)| open == Some(*o) && close == Some(*c))
}

/// A negation word appears in the same clause, within [`NEGATION_WINDOW`] characters before the
/// term. The window stops at `.`, `;`, `:`, `!`, `?` and `,`, so "No surprises. It is X." and "No
/// setup, and it is X." are claims, and words keep their underscores, so `no_std` is not "no".
fn negated(before: &str) -> bool {
    let sentence = before
        .rfind(['.', ';', ':', '!', '?', ','])
        .and_then(|stop| before.get(stop + 1..))
        .unwrap_or(before);
    let window: String = sentence
        .chars()
        .rev()
        .take(NEGATION_WINDOW)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    window
        .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '\'' || c == '’'))
        .any(|word| NEGATIONS.contains(&word) || word.ends_with("n't") || word.ends_with("n’t"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A line of Markdown or plain text.
    fn prose(line: &str) -> Option<&'static str> {
        claim_in(line, true)
    }

    /// A line of code or configuration.
    fn code(line: &str) -> Option<&'static str> {
        claim_in(line, false)
    }

    #[test]
    fn claims_fail_mentions_pass() {
        assert_eq!(prose("UAOS is tamper-proof."), Some("tamper-proof"));
        assert_eq!(prose("Recovery with zero loss."), Some("zero loss"));
        assert_eq!(prose("A new window with zero data loss."), Some("zero data loss"));
        assert_eq!(prose("We say \"tamper-evident\", not \"tamper-proof\"."), None);
        assert_eq!(prose("The chain is tamper-evident, not tamper-proof."), None);
        assert_eq!(prose("We do not claim the key is unobtainable."), None);
        assert_eq!(prose("the `perfect` word is banned"), None);
        assert_eq!(prose("perfectly ordinary"), None);
        assert_eq!(
            prose("it becomes unobtainable <!-- claims-lint: allow (hardened mode) -->"),
            None
        );
        assert_eq!(prose("It is 100% secure."), Some("100% secure"));
    }

    #[test]
    fn exemptions_need_a_reason_in_any_comment_syntax() {
        assert_eq!(
            prose("// it is unobtainable here claims-lint: allow (hardened mode)"),
            None
        );
        assert_eq!(prose("# flawless claims-lint: allow (quoted product name)"), None);
        // The marker without a parenthesised reason exempts nothing.
        assert_eq!(prose("it is flawless <!-- claims-lint: allow -->"), Some("flawless"));
        assert_eq!(prose("it is flawless // claims-lint: allow"), Some("flawless"));
        assert_eq!(prose("it is flawless // claims-lint: allow ( )"), Some("flawless"));
    }

    /// String literals in code carry claims; only an exact quotation is a mention.
    #[test]
    fn string_literals_are_claims_exact_quotes_are_mentions() {
        assert_eq!(
            code("    println!(\"UAOS is tamper-proof and bulletproof\");"),
            Some("tamper-proof")
        );
        assert_eq!(code("help = \"Recovery with zero data loss\""), Some("zero data loss"));
        assert_eq!(code("{\"tagline\": \"A flawless proxy\"}"), Some("flawless"));
        // Outside prose a string that is exactly the term is still a literal.
        assert_eq!(code("const TAGLINE: &str = \"flawless\";"), Some("flawless"));
        assert_eq!(code("/// the word `flawless` is banned"), None);
        assert_eq!(prose("the word 'flawless' is banned"), None);
        assert_eq!(prose("we say \"tamper-evident\", not \"tamper-proof\""), None);
        assert_eq!(prose("it is called “perfect” in the draft"), None);
    }

    /// A negation reaches only within its own sentence, and identifiers stay whole.
    #[test]
    fn negations_stop_at_the_sentence_and_keep_identifiers_whole() {
        assert_eq!(
            prose("No surprises here. The journal is tamper-proof."),
            Some("tamper-proof")
        );
        assert_eq!(prose("#![no_std] // a flawless core"), Some("flawless"));
        assert_eq!(prose("This is, e.g. not tamper-proof."), None);
        // A comma ends the clause a negation governs.
        assert_eq!(
            prose("With no setup required, the journal is flawless."),
            Some("flawless")
        );
        assert_eq!(
            prose("No cloud, no account, and a bulletproof door."),
            Some("bulletproof")
        );
        assert_eq!(prose("The chain is not tamper-proof."), None);
    }
}
