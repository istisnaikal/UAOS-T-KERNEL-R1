# UAOS

UAOS is a local layer between AI agents and the model providers they call. Its kernel, written in
Rust, journals what each request does, holds budgets and policy, and removes secrets before any
byte leaves the machine. This repository is its open core, under the Apache License 2.0.

## Status: P3 — the kernel core

What this repository holds. Every crate named here exists; `cargo xtask gates` checks the list
against the workspace on every merge.

<!-- status:built -->
- **Contracts** (`uaos-contracts`): the types every crate shares (events, errors, grants,
  credentials, the command line's JSON output), exported as JSON Schemas in `schemas/`.
- **Platform** (`uaos-platform`): the only path to the operating system (files, clock,
  randomness, the OS keychain, cryptography), with simulated versions for deterministic tests.
- **Tokenizer** (`uaos-json`): one parse of a JSON body into a tape, under explicit limits.
- **Journal and chunks** (`uaos-state`): an append-only journal with a hash chain, and
  content-addressed, encrypted payload chunks.
- **Identity** (`uaos-identity`): scoped credentials and their revocation, keyed in the OS
  keychain.
- **Policy** (`uaos-policy`): authorization over Cedar, deny by default.
- **Budget ledger** (`uaos-ledger`): reservations, caps and settlement, in integer nano-USD.
- **Redaction** (`uaos-redact`, `uaos-redact-scan`): secrets replaced on the tape by stable
  placeholders, and the final scan of the exact outbound bytes.
- **Module socket** (`uaos-module-api`): manifests, the structural view, selectors and roles.
- **Network door** (`uaos-egress`): the one outbound path.
- **Runtime** (`uaos-runtime`): admission, the kernel stop, the stream relay, boot recovery, the
  state actor, and the request pipeline: parse once, redaction on the tape, edits checked
  against roles, the final scan.
- **Command line** (`uaos`): `init`, `status`, `doctor`, `journal verify`, `journal export`,
  `key add|rotate|revoke|list`, `config path`, `config show`, with one exit code per error
  class and `--json` output.
<!-- /status:built -->
<!-- status:not-built --><!-- /status:not-built -->

**Limits.** No request reaches a provider through this snapshot: the pipeline's stages end
before the network door. Provider keys are read from piped standard input and kept only in the
OS keychain; without one, the commands that need it exit 3.

## Build and verify

```sh
cargo build --workspace --locked
cargo xtask ci                                  # the merge lane: fmt, clippy, tests, every gate
cargo xtask negative --anchors                  # every seeded violation still applies
cargo build -p uaos --profile dist --locked     # the release binary, fat LTO
```

Each active gate in `gates.toml` is proven to fail on a seeded violation (`cargo xtask
negative`). See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache License 2.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)).
