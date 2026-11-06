# Releasing

No release is cut while any gate is pending or any open decision remains:

```sh
cargo xtask gates --release       # zero pending gates
cargo xtask decisions --release   # zero open-decision markers
cargo build -p uaos --profile dist --locked   # the distributed artifact: fat LTO
cargo xtask evidence --streak 7   # nightly proofs green, <= 48 h old, from this exact code
```

## Versioning

- The binary follows [Semantic Versioning](https://semver.org). Before 1.0, a 0.y minor may
  change APIs, but **on-disk formats (journal, profiles) stay readable from the first public
  release onward**. A binary that is too old for a journal refuses to run
  (`UAOS-JOURNAL-0006`) instead of risking corruption.
- Wire contracts are versioned separately (`uaos.<name>/<major>`); see CONTRIBUTING.md.
- Deprecations warn for at least one minor release. Every release has migration notes.

## Cadence and channels

- Minor release every 4 weeks; patch releases as needed; security fixes out of band.
- Channels: `nightly` → `beta` (the canary) → `stable`.

## Artifacts

| Property | Release artifacts |
|---|---|
| Targets | Linux x86_64, macOS arm64, Windows x86_64 |
| Provenance | GitHub artifact attestations (Sigstore-backed SLSA provenance) |
| Reproducibility | pinned toolchain, `--locked`, `SOURCE_DATE_EPOCH`, path remapping |
| SBOM | CycloneDX, `cargo auditable` |
| OS signing | Authenticode, Apple notarization (if certificates are ready; otherwise documented) |

## Pre-release checks

1. **Upgrade matrix:** data directories produced by every previous release are migrated with a
   dry run, then for real, then verified.
2. **Rollback rehearsal:** install N → run → upgrade to N+1 → downgrade to N. Data must be intact,
   or the downgrade must refuse honestly.
3. Soak on the release branch (24 hours; 72 hours before GA).
4. Canary on `beta`, then promote.

## Notices

`NOTICE` is regenerated at release time from the dependency graph (licenses permitted by
`deny.toml`, including the OpenSSL license of aws-lc-sys and CDLA-Permissive-2.0 data) and
included in every artifact.

## Rollback

The previous signed binary stays available; `uaos self rollback` verifies its signature
before switching (P3+). There is no remote kill switch: an opt-in signed advisory feed may
recommend disabling a module, and the user decides.
