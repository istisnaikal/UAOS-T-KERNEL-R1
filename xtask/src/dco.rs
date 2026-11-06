// SPDX-License-Identifier: Apache-2.0

//! Developer Certificate of Origin (CONTRIBUTING.md §DCO). Every commit in a range must carry
//! `Signed-off-by: <author name> <<author email>>` matching its author.
//!
//! One exemption: a merge commit whose combined diff is empty (`git show --cc`) adds no content
//! of its own; it only joins parents that are checked themselves. Such commits are made by
//! tools — GitHub's "Update branch" button, `git merge` without conflicts — and carry no
//! contribution to certify. A merge that resolves a conflict with new content has a non-empty
//! combined diff and needs a sign-off like any other commit.

use std::path::Path;

use crate::util::capture;

const RECORD_SEP: char = '\u{1e}';
const FIELD_SEP: char = '\u{0}';

pub(crate) fn check(repo: &Path, range: &str) -> Result<(), String> {
    let log = capture(
        repo,
        "git",
        &["log", "--format=%H%x00%an%x00%ae%x00%P%x00%B%x1e", range],
    )?;
    let mut unsigned = Vec::new();
    let mut signed = 0usize;
    let mut content_free_merges = 0usize;
    for record in log.split(RECORD_SEP).map(str::trim).filter(|r| !r.is_empty()) {
        let mut fields = record.splitn(5, FIELD_SEP);
        let (Some(sha), Some(name), Some(email), Some(parents), Some(body)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            return Err(format!("could not parse git log record: {record:?}"));
        };
        let expected = format!("Signed-off-by: {name} <{email}>");
        if body.lines().any(|l| l.trim() == expected) {
            signed += 1;
        } else if parents.split_whitespace().count() > 1 && is_content_free_merge(repo, sha)? {
            content_free_merges += 1;
        } else {
            unsigned.push(format!("{} (expected `{expected}`)", sha.get(..12).unwrap_or(sha)));
        }
    }
    if unsigned.is_empty() {
        println!("xtask dco: {signed} commit(s) signed off; {content_free_merges} content-free merge(s) exempt");
        Ok(())
    } else {
        Err(format!(
            "{} commit(s) lack a matching DCO sign-off (use `git commit -s`):\n  {}",
            unsigned.len(),
            unsigned.join("\n  ")
        ))
    }
}

/// A merge is content-free when its combined diff against all parents is empty.
fn is_content_free_merge(repo: &Path, sha: &str) -> Result<bool, String> {
    let diff = capture(repo, "git", &["show", "--format=", "--cc", "--no-color", sha])?;
    Ok(diff.trim().is_empty())
}
