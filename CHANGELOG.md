# Changelog

All notable changes are recorded here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org). A change to a contract schema in
`schemas/` is recorded here in the same change (`cargo xtask docs-sync`).

## [Unreleased]

### The one-record intent: an Operation's money in its own records

- **One record per transition that moves money.** An Operation's reservation travels inline in
  its `op.reserved_intent` record, as a compact `ledger` delta (new schema `uaos.op_ledger/1`,
  `schemas/op-ledger.v1.json`). The record that closes it (`op.committed`, `op.failed` or
  `op.denied`) carries the closing entries. A crash between two records can no longer leave the
  money without its Operation, or the Operation without its money. Journals written in the
  earlier two-record form still read.
- **The reader** checks every record against these rules before boot uses it. It refuses a
  journal that breaks one with `BUDGET_ENTRIES_UNREADABLE`, naming the first record.
- **Boot** closes an Operation left open in that Operation's own `op.indeterminate` record,
  settled in full as estimated, and says whether `op.executing` was recorded. What recovery
  cannot close is a stuck item: counted in `kernel.booted`, listed, and holding the ledger until
  a person repairs it. A repair needs that person's approval, which has no command yet, so
  repairs run only in tests.
- **The ledger task** (`uaos-runtime`) is the ledger's one ordered writer:
  - `reserve` returns a `Held` token only after the intent is acknowledged;
  - `execute` journals `op.executing` and checks the stop before and after it, and only then
    returns the `InFlight` token a door call needs;
  - closes are typed (`Released`, `Settled`). Once offered, a close is the task's and lands even
    if its caller is cancelled, and a token dropped without a close is closed by the task;
  - every channel is bounded: with no free slot, `reserve` is refused as `RUNTIME_OVERLOAD`
    before anything is written;
  - a close refused while an engaged stop's record cannot land is tried again, and a write of
    unknown fate poisons the ledger and stops the kernel;
  - shutdown drains the task first and counts in `kernel.shutdown` what it left open;
  - a refusal's wire error names the Operation and its reservation, never an amount, with an
    agent message true for every call that can meet it;
  - an upstream name is a token of letters, digits, `.`, `_` and `-`, so a URL is refused.
- **APIs:**
  - `uaos-egress`: `EgressError::may_have_sent()` and `EgressError::kind()`, and a variant
    `AlreadySent`, split from `Refused`;
  - the state actor: `StateError::NotQueued` and `StateError::StopPending`, and
    `StateHandle::flush_policy()`. A queue capacity past a bounded channel's limit is clamped.
- **Measured** with `cargo bench -p uaos-runtime --bench state_actor` (5,000 Operations, on a
  cloud host): `reserve` p50 86.3 µs and p99 172.5 µs; `execute` p50 72.0 µs and p99 144.5 µs.
- **Proof:** tests pin each of these behaviours, most with a seeded violation that shows the
  test fails without it.

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
