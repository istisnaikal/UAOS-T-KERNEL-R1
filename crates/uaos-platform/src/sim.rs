// SPDX-License-Identifier: Apache-2.0

//! Deterministic simulation implementations.
//!
//! Same seed, same run: time only moves when the test moves it, and randomness comes from a
//! seeded generator. These are test doubles for reproducibility, **not** security
//! primitives; the composition root never injects them.

pub mod fs;
pub mod keychain;

use std::sync::atomic::{AtomicU64, Ordering};

use uaos_contracts::time::WallTime;
use uaos_contracts::wire::MonoNanos;

use crate::{Clock, PlatformError, Rng};

/// A clock that advances only when told to.
#[derive(Debug)]
pub struct SimClock {
    wall_origin_unix_nanos: i128,
    elapsed_nanos: AtomicU64,
}

impl SimClock {
    /// Creates a clock whose wall time starts at `wall_origin` and monotonic time at zero.
    #[must_use]
    pub fn new(wall_origin: WallTime) -> Self {
        Self {
            wall_origin_unix_nanos: wall_origin.as_unix_nanos(),
            elapsed_nanos: AtomicU64::new(0),
        }
    }

    /// Advances both clocks by `nanos`, saturating at `u64::MAX` elapsed nanoseconds.
    pub fn advance(&self, nanos: u64) {
        // fetch_update with a saturating add never fails for an always-Some closure.
        let _previous = self
            .elapsed_nanos
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |e| Some(e.saturating_add(nanos)));
    }
}

impl Clock for SimClock {
    fn wall(&self) -> Result<WallTime, PlatformError> {
        let elapsed = i128::from(self.elapsed_nanos.load(Ordering::SeqCst));
        WallTime::from_unix_nanos(self.wall_origin_unix_nanos.saturating_add(elapsed))
            .map_err(|_| PlatformError::ClockOutOfRange)
    }

    fn mono(&self) -> MonoNanos {
        MonoNanos(self.elapsed_nanos.load(Ordering::SeqCst))
    }
}

/// A seeded `SplitMix64` generator. Lock-free: each call claims the next state atomically, so
/// the sequence of outputs is fully determined by the seed and the order of calls.
#[derive(Debug)]
pub struct SimRng {
    state: AtomicU64,
}

/// `SplitMix64` increment (the 64-bit golden ratio), from Steele, Lea & Flood (2014).
const GOLDEN_GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;

impl SimRng {
    /// Creates a generator from a seed.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            state: AtomicU64::new(seed),
        }
    }

    fn next_u64(&self) -> u64 {
        let mut z = self
            .state
            .fetch_add(GOLDEN_GAMMA, Ordering::SeqCst)
            .wrapping_add(GOLDEN_GAMMA);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

impl Rng for SimRng {
    fn fill(&self, buf: &mut [u8]) -> Result<(), PlatformError> {
        for chunk in buf.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            for (dst, src) in chunk.iter_mut().zip(bytes) {
                *dst = src;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IdSource;
    use proptest::prelude::*;
    use uaos_contracts::id::{SessionId, TypedId};

    #[test]
    fn splitmix_reference_vector() {
        // First output of SplitMix64 with seed 0 (widely published reference value).
        assert_eq!(SimRng::new(0).next_u64(), 0xE220_A839_7B1D_CDAF);
    }

    proptest! {
        #[test]
        fn same_seed_same_ids(seed in any::<u64>(), steps in 1usize..32) {
            let make = || IdSource::new(SimClock::new(WallTime::UNIX_EPOCH), SimRng::new(seed));
            let (a, b) = (make(), make());
            for _ in 0..steps {
                let x: SessionId = a.next().unwrap();
                let y: SessionId = b.next().unwrap();
                prop_assert_eq!(x, y);
            }
        }

        #[test]
        fn clock_moves_only_when_advanced(advances in prop::collection::vec(0u64..1_000_000, 0..16)) {
            let clock = SimClock::new(WallTime::UNIX_EPOCH);
            let mut total = 0u64;
            for step in advances {
                prop_assert_eq!(clock.mono(), MonoNanos(total));
                clock.advance(step);
                total += step;
            }
            prop_assert_eq!(clock.wall().unwrap().as_unix_nanos(), i128::from(total));
        }
    }

    #[test]
    fn ids_carry_simulated_time() {
        let clock = SimClock::new(WallTime::from_unix_nanos(1_760_000_000_000_000_000).unwrap());
        let ids = IdSource::new(clock, SimRng::new(7));
        let id: SessionId = ids.next().unwrap();
        let (secs, _) = id.as_uuid().get_timestamp().unwrap().to_unix();
        assert_eq!(secs, 1_760_000_000);
    }
}
