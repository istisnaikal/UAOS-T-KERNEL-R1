// SPDX-License-Identifier: Apache-2.0

//! Time as data. Reading a clock is a platform concern (`uaos_platform::Clock`); this module
//! only defines how instants are represented and exchanged.

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::wire::MonoNanos;

/// Error returned when a wall-clock instant is invalid or not in UTC `Z` form.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WallTimeError {
    /// The text is not an RFC 3339 timestamp ending in `Z`.
    #[error("expected an RFC 3339 timestamp in UTC ending with `Z`")]
    Format,
    /// The instant is outside the supported range.
    #[error("instant is outside the supported range")]
    Range,
}

/// A wall-clock instant in UTC. Wire form: RFC 3339 with a `Z` suffix, for example
/// `2026-10-12T09:30:00.123456789Z`. Human-readable on purpose: journal lines are meant to be
/// inspectable with ordinary tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WallTime(jiff::Timestamp);

impl WallTime {
    /// The Unix epoch.
    pub const UNIX_EPOCH: Self = Self(jiff::Timestamp::UNIX_EPOCH);

    /// Builds an instant from nanoseconds since the Unix epoch.
    ///
    /// # Errors
    /// Returns [`WallTimeError::Range`] if the value is outside the supported range.
    pub fn from_unix_nanos(nanos: i128) -> Result<Self, WallTimeError> {
        // Checked before jiff sees it: for values far outside its range, jiff 0.2.38 reaches an
        // internal assertion instead of returning its error (found by wire property).
        let range = jiff::Timestamp::MIN.as_nanosecond()..=jiff::Timestamp::MAX.as_nanosecond();
        if !range.contains(&nanos) {
            return Err(WallTimeError::Range);
        }
        jiff::Timestamp::from_nanosecond(nanos)
            .map(Self)
            .map_err(|_| WallTimeError::Range)
    }

    /// Nanoseconds since the Unix epoch.
    #[must_use]
    pub fn as_unix_nanos(self) -> i128 {
        self.0.as_nanosecond()
    }

    /// Milliseconds since the Unix epoch, clamped to zero for pre-epoch instants.
    /// Used to timestamp `UUIDv7` identifiers, which cannot represent earlier times.
    #[must_use]
    pub fn unix_millis_saturating(self) -> u64 {
        u64::try_from(self.0.as_millisecond()).unwrap_or(0)
    }
}

impl fmt::Display for WallTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // jiff renders a `Timestamp` in RFC 3339 with a `Z` offset.
        fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for WallTime {
    type Err = WallTimeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.ends_with('Z') {
            return Err(WallTimeError::Format);
        }
        s.parse::<jiff::Timestamp>()
            .map(Self)
            .map_err(|_| WallTimeError::Format)
    }
}

impl Serialize for WallTime {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for WallTime {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = Cow::<'de, str>::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for WallTime {
    fn schema_name() -> Cow<'static, str> {
        "WallTime".into()
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "format": "date-time",
            "pattern": "Z$",
            "description": "RFC 3339 instant in UTC with a Z suffix."
        })
    }
}

/// When an event happened: wall time for humans and cross-process ordering, monotonic time
/// for durations and ordering within one process run (wall clocks can jump).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EventTime {
    /// Wall-clock instant in UTC.
    pub wall: WallTime,
    /// Monotonic reading in nanoseconds since the process's clock origin.
    pub mono_ns: MonoNanos,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Out-of-range values return an error; none of them reaches jiff's internal assertion.
    #[test]
    fn out_of_range_nanos_are_refused_without_a_panic() {
        let max = jiff::Timestamp::MAX.as_nanosecond();
        let min = jiff::Timestamp::MIN.as_nanosecond();
        for nanos in [i128::MAX, i128::MIN, i128::from(u64::MAX) * 1_000_000, max + 1, min - 1] {
            assert_eq!(WallTime::from_unix_nanos(nanos), Err(WallTimeError::Range), "{nanos}");
        }
        assert!(WallTime::from_unix_nanos(max).is_ok() && WallTime::from_unix_nanos(min).is_ok());
    }

    #[test]
    fn rejects_non_utc_offsets() {
        assert_eq!(
            "2026-10-12T09:30:00+03:00".parse::<WallTime>(),
            Err(WallTimeError::Format)
        );
        assert!("2026-10-12T09:30:00Z".parse::<WallTime>().is_ok());
    }

    proptest! {
        #[test]
        fn wire_round_trip(nanos in 0i128..4_102_444_800_000_000_000i128) {
            let t = WallTime::from_unix_nanos(nanos).unwrap();
            let json = serde_json::to_string(&t).unwrap();
            prop_assert!(json.ends_with("Z\""));
            prop_assert_eq!(serde_json::from_str::<WallTime>(&json).unwrap(), t);
        }
    }
}
