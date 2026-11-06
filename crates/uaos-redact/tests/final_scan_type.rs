// SPDX-License-Identifier: Apache-2.0

//! The final scan callers reach through `uaos-redact` is the scan crate's own type. `arch.toml`
//! lets the request pipeline depend on `uaos-redact`, not on `uaos-redact-scan`, so it names
//! `uaos_redact::FinalScanner`. A type of the same name defined in `uaos-redact` instead, which
//! could find strings with the shared tokenizer before it scans, would make the independence the
//! crate split bought a fiction. The pins below stop that from compiling.

#![allow(clippy::unwrap_used, reason = "test: a failed fixture fails the test")]

/// Identity on the scan crate's types: compiles only while the re-exports are those types.
const FINAL_SCANNER: fn(uaos_redact_scan::FinalScanner) -> uaos_redact::FinalScanner = |scanner| scanner;
const BLOCKED: fn(uaos_redact_scan::Blocked) -> uaos_redact::Blocked = |blocked| blocked;
const DETECTORS: fn(uaos_redact_scan::DetectorSet) -> uaos_redact::DetectorSet = |detectors| detectors;

#[test]
fn the_final_scan_is_the_scan_crates_own() {
    let version = uaos_redact_scan::DetectorVersion::CURRENT;
    let scanner = FINAL_SCANNER(uaos_redact_scan::FinalScanner::new(version, []).unwrap());
    let blocked = BLOCKED(scanner.check_bytes(b"AKIAIOSFODNN7EXAMPLE").unwrap_err());
    assert!(!blocked.classes.is_empty(), "the pinned scanner found nothing");
    let detectors = DETECTORS(uaos_redact_scan::DetectorSet::new(version).unwrap());
    assert_eq!(detectors.version(), version);
}
