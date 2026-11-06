// SPDX-License-Identifier: Apache-2.0

//! # UAOS canonical contracts
//!
//! The vocabulary every other crate speaks. This crate is deliberately boring:
//!
//! * **No I/O, no async, no clocks, no randomness.** Anything nondeterministic is passed in by the
//!   caller (normally from `uaos-platform`), so every type here is reproducible in deterministic
//!   simulation.
//! * **Invariants live in types.** An identifier cannot be confused with another kind of
//!   identifier, money cannot be a float, an Operation that is not compensable cannot be
//!   reported as compensated (red line 3).
//! * **Wire forms are stable.** Every exported contract carries a `schema` tag of the form
//!   `uaos.<name>/<major>`. JSON Schemas are generated from these types into `schemas/` and
//!   diffed in CI; a breaking diff without a major bump fails the merge.
//! * **64-bit integers travel as decimal strings**, so no JSON consumer silently loses
//!   precision above 2^53.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod budget;
pub mod cli;
pub mod credential;
pub mod digest;
pub mod error;
pub mod event;
pub mod grant;
pub mod id;
pub mod limits;
pub mod money;
pub mod operation;
pub mod schema;
pub mod time;
mod token;
pub mod wire;
