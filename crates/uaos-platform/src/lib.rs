// SPDX-License-Identifier: Apache-2.0

//! # UAOS platform boundary
//!
//! Every source of nondeterminism and every OS facility enters the kernel through a trait defined
//! here. The composition root injects real implementations ([`real`]); tests and deterministic
//! simulation inject [`sim`] implementations, so any failure can be replayed from a seed.
//!
//! `clippy.toml` bans direct use of clocks, randomness, `std::fs` and process spawning
//! everywhere else; this crate is the single, audited place where those calls are made.
//!
//! Phase scope: time, randomness and identifiers (P0); filesystem and exclusive locks (P1). Peer
//! credentials, keychain and process spawning arrive with the work packages that first need them,
//! each with a real and a simulated implementation.

#![deny(missing_docs)]

pub mod crypto;
pub mod fs;
pub mod keychain;
pub mod real;
pub mod sim;

use std::fmt;

use uaos_contracts::id::TypedId;
use uaos_contracts::time::WallTime;
use uaos_contracts::wire::MonoNanos;

/// Error returned when the operating system cannot provide a reading.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlatformError {
    /// The wall clock reports a time outside the representable range (for example before
    /// 1970). UAOS refuses to fabricate a timestamp.
    #[error("the system wall clock is outside the supported range")]
    ClockOutOfRange,
    /// The OS random source failed. UAOS never falls back to a weaker source.
    #[error("the operating system random source failed")]
    RandomUnavailable,
}

/// Source of time.
pub trait Clock: Send + Sync + fmt::Debug {
    /// Current wall-clock instant in UTC.
    ///
    /// # Errors
    /// Returns [`PlatformError::ClockOutOfRange`] if the system clock is unusable.
    fn wall(&self) -> Result<WallTime, PlatformError>;

    /// Current monotonic reading. Never decreases within one process.
    fn mono(&self) -> MonoNanos;
}

/// Source of randomness.
pub trait Rng: Send + Sync + fmt::Debug {
    /// Fills `buf` with random bytes.
    ///
    /// # Errors
    /// Returns [`PlatformError::RandomUnavailable`] if the source failed.
    fn fill(&self, buf: &mut [u8]) -> Result<(), PlatformError>;
}

/// Generates typed identifiers from a [`Clock`] and an [`Rng`].
#[derive(Debug)]
pub struct IdSource<C, R> {
    clock: C,
    rng: R,
}

impl<C: Clock, R: Rng> IdSource<C, R> {
    /// Creates an identifier source.
    pub const fn new(clock: C, rng: R) -> Self {
        Self { clock, rng }
    }

    /// Generates a new identifier of type `T`.
    ///
    /// # Errors
    /// Propagates clock or randomness failures; never substitutes a weaker identifier.
    pub fn next<T: TypedId>(&self) -> Result<T, PlatformError> {
        let unix_ms = self.clock.wall()?.unix_millis_saturating();
        let mut random = [0u8; 10];
        self.rng.fill(&mut random)?;
        Ok(T::from_parts(unix_ms, random))
    }
}
