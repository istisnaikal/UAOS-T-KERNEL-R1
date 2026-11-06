// SPDX-License-Identifier: Apache-2.0

//! # UAOS identity: scoped credentials
//!
//! Agents never hold provider keys. They authenticate with credentials that UAOS issues:
//!
//! * **recognisable:** `uaos_sk_` + base32 + a CRC-32 checksum, a format secret scanners can match.
//!   UAOS's own redaction class for it arrives with detector set v2;
//! * **stored as digests only:** HMAC-SHA-256 under an identity key held in the OS keychain.
//!   The secret is shown once and never journaled;
//! * **hierarchical:** master → sub → child, at most
//!   [`uaos_contracts::limits::MAX_CREDENTIAL_DEPTH`] long. A child's scope must be within its
//!   parent's, checked at issuance (records are immutable; narrowing means re-issuing). Live
//!   credentials are bounded overall and per parent;
//! * **revocable:** directly, or for a whole subtree by bumping an epoch. Every revocation is a
//!   critical journal record before it returns;
//! * **restore-safe:** a counter in the OS keychain detects a data directory restored from
//!   before a revocation. Verification and writes then fail closed until restore recovery
//!   revokes every live master. A counter that is deleted or implausible also fails closed.
//!
//! Like the ledger, the identity is a pure replay of its journal entries (`identity.entry`).

#![deny(missing_docs)]
#![deny(clippy::indexing_slicing)]

mod identity;
mod journal_sink;
pub mod scope;
mod secret;
mod state;

pub use identity::{GuardOutcome, Identity, IdentityKeys, IdentitySink, IssueRequest, Issued, MemorySink};
pub use journal_sink::{JournalSink, entries_from_journal};
pub use secret::{MalformedCredential, PREFIX, Secret, TEXT_LEN};
pub use state::{GUARD_CEILING, GuardStatus, IdentityError, IdentityState, Node, Verified, guard_status};
