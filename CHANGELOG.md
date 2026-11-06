# Changelog

All notable changes are recorded here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org). A change to a contract schema in
`schemas/` is recorded here in the same change (`cargo xtask docs-sync`).

## [Unreleased]

### The seeded-violation suite: three cases that proved nothing

- The merge lane's `negative` job failed on the previous two updates: three seeded violations
  did not prove their gate. Fixed:
  - `redact-tape-refusal-passes`: its seed no longer compiled once `Redaction` gained `edited`.
  - `grant-wire-drops-provider`: the round trip unwrapped a record the seeded defect made
    unreadable, so the test failed before the assertion that names the defect. A record that no
    longer reads back now fails that same assertion.
  - `drain-race-admits-past-the-count`: its test raced two threads for a window the CI runners
    never hit, so the seed did not bite there. Admission's checks before the lock and its count
    under the lock are now two steps, and a unit test puts the drain between them without a
    race. The threaded test stays.

### Boot reads the ledger's entries without copying them

- Boot reads every `budget.entry` record's entry. The reader now deserializes it from the
  record's parsed payload in place, instead of from a copy of it. Measured with
  `cargo bench -p uaos-runtime --bench boot` at 49,751 records, 125 Operations left open, on a
  cloud host, three runs each, alternated: boot's own phase took 44.7, 46.6 and 45.5 ms, against
  68.8, 69.3 and 63.2 ms before. The whole boot (the journal's open, the read of its records,
  boot) took 591, 628 and 547 ms, against 624, 641 and 632 ms, within the runs' spread.
- `uaos-ledger` depends on `serde` directly; it already reached it through `serde_json`.

### Windows: the last failing test

- The `xtask` sources test compared sorted paths to a list in string order. `Path` orders by
  component, and on Windows `C:\` sorts before `..`; the expected list is now sorted the same
  way. Every other test that ran on Windows in the previous CI run passed.

### Dependency updates

- Dependency versions arrive with the project's updates, after they pass the same gates as any
  change (`cargo deny`, `cargo vet`, the tests). This repository no longer carries a Dependabot
  version-update configuration.

### Windows, the API documentation and the merge lane

- **Windows:** the first CI run failed on Windows. Fixed:
  - `xtask`: a Unix-only seeded violation bound its path to an underscore name on other systems,
    which clippy refuses there.
  - `uaos`: `XDG_DATA_HOME` counts as absolute when it starts with `/`, the Unix rule, so a
    simulated Unix answers the same on any host.
  - The command-line tests compared paths printed with the host's separator to Unix spellings.
  - The kill test's `WRITER_FAILED` was read only on Unix: dead code on Windows.
- **API documentation:** rustdoc's warn-by-default lints are denied in the workspace lint table,
  and `cargo doc --workspace --no-deps --locked` runs in the merge lane (`cargo xtask ci` and CI's
  clippy job). It found two public items whose documentation linked a private one; both fixed.
  Seeded violation `doc-links-private-item`.
- **Every library builds on its own:** CI's test job runs `cargo check --workspace --lib
  --locked`, which the local lane already ran.
- **Supply chain:** `deny.toml` allows only licenses the dependency graph uses.

### The open-core snapshot

- The kernel core, its command line and its verification suite, published as one snapshot under
  the Apache License 2.0. See the README for what it holds.
