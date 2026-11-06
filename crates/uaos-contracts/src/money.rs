// SPDX-License-Identifier: Apache-2.0

//! Money.
//!
//! Amounts are integer nano-US-dollars (1 USD = 10^9 nUSD) in an `i64`, which covers about
//! ±9.2 billion USD. Floats never touch money: they are not associative and drift under
//! repeated settlement. Arithmetic is checked; overflow is an error, never a wrap.
//! On the wire an amount is a canonical decimal string, like every 64-bit value.

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::wire::{WireIntError, parse_canonical_i64};

/// An amount of money in nano-US-dollars.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct NanoUsd(i64);

/// Number of nano-dollars in one US dollar.
pub const NANOS_PER_USD: i64 = 1_000_000_000;

impl NanoUsd {
    /// Zero.
    pub const ZERO: Self = Self(0);

    /// Wraps a raw nano-dollar amount.
    #[must_use]
    pub const fn new(nanos: i64) -> Self {
        Self(nanos)
    }

    /// Returns the raw nano-dollar amount.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }

    /// Checked addition. Returns `None` on overflow.
    #[must_use]
    pub const fn checked_add(self, rhs: Self) -> Option<Self> {
        match self.0.checked_add(rhs.0) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }

    /// Checked subtraction. Returns `None` on overflow.
    #[must_use]
    pub const fn checked_sub(self, rhs: Self) -> Option<Self> {
        match self.0.checked_sub(rhs.0) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }

    /// Checked negation. Returns `None` for `i64::MIN`.
    #[must_use]
    pub const fn checked_neg(self) -> Option<Self> {
        match self.0.checked_neg() {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }

    /// Returns `true` if the amount is below zero.
    #[must_use]
    pub const fn is_negative(self) -> bool {
        self.0 < 0
    }
}

impl fmt::Display for NanoUsd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for NanoUsd {
    type Err = WireIntError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_canonical_i64(s).map(Self)
    }
}

impl Serialize for NanoUsd {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for NanoUsd {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = Cow::<'de, str>::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for NanoUsd {
    fn schema_name() -> Cow<'static, str> {
        "NanoUsd".into()
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "pattern": "^(0|-?[1-9][0-9]{0,18})$",
            "description": "Signed amount in nano-US-dollars (1e-9 USD) as a canonical decimal string."
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn overflow_is_an_error_not_a_wrap() {
        assert_eq!(NanoUsd::new(i64::MAX).checked_add(NanoUsd::new(1)), None);
        assert_eq!(NanoUsd::new(i64::MIN).checked_sub(NanoUsd::new(1)), None);
        assert_eq!(NanoUsd::new(i64::MIN).checked_neg(), None);
    }

    proptest! {
        #[test]
        fn wire_round_trip(n in any::<i64>()) {
            let json = serde_json::to_string(&NanoUsd::new(n)).unwrap();
            prop_assert_eq!(serde_json::from_str::<NanoUsd>(&json).unwrap(), NanoUsd::new(n));
        }

        #[test]
        fn add_then_sub_is_identity(a in any::<i64>(), b in any::<i64>()) {
            let (a, b) = (NanoUsd::new(a), NanoUsd::new(b));
            if let Some(sum) = a.checked_add(b) {
                prop_assert_eq!(sum.checked_sub(b), Some(a));
            }
        }
    }
}
