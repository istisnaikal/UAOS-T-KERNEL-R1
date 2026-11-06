// SPDX-License-Identifier: Apache-2.0

//! # UAOS state
//!
//! The journal is the source of truth: an append-only, hash-chained sequence of `uaos.event/1`
//! records. Everything else in this crate (projections) is derived from it and can be rebuilt.
//!
//! All disk access goes through [`uaos_platform::fs::Fs`], so every durability claim below is
//! proven twice: against the real filesystem and under deterministic crash simulation.

#![deny(missing_docs)]

pub mod chunks;
pub mod journal;
pub mod projection;
