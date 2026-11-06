# Changelog

All notable changes are recorded here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org). A change to a contract schema in
`schemas/` is recorded here in the same change (`cargo xtask docs-sync`).

## [Unreleased]

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
