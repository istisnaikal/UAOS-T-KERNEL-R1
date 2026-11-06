// SPDX-License-Identifier: Apache-2.0

//! Pricing usage in nano-USD. The published table, `uaos.pricing/1`, is; [`DeclaredPrice`] is the
//! user-declared flat form that ADR permits.

use std::fmt;

use uaos_contracts::money::NanoUsd;
use uaos_module_api::Code;

/// Why usage could not be priced. Either way the relay cuts: metering fails closed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PriceError {
    /// A dimension has no price (`BUDGET_UNKNOWN_PRICING`).
    #[error("a billing dimension has no price")]
    Unpriced,
    /// The cost does not fit in nano-USD.
    #[error("the cost overflows")]
    Overflow,
    /// A declared price is negative, or names a dimension twice.
    #[error("invalid declared price")]
    Invalid,
}

/// Prices usage: for each billing dimension, a count of units.
pub trait Price: Send + Sync + fmt::Debug {
    /// The cost of `usage`, each dimension named once.
    ///
    /// # Errors
    /// [`PriceError`]: an unpriced dimension or an overflow.
    fn cost(&self, usage: &[(Code, u64)]) -> Result<NanoUsd, PriceError>;
}

/// A price the user declared: nano-USD per unit of each dimension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredPrice {
    per_unit: Vec<(Code, NanoUsd)>,
}

impl DeclaredPrice {
    /// A declared price.
    ///
    /// # Errors
    /// [`PriceError::Invalid`] if a price is negative or a dimension appears twice.
    pub fn new(per_unit: impl IntoIterator<Item = (Code, NanoUsd)>) -> Result<Self, PriceError> {
        let per_unit: Vec<(Code, NanoUsd)> = per_unit.into_iter().collect();
        let duplicate = per_unit
            .iter()
            .enumerate()
            .any(|(i, (name, _))| per_unit[..i].iter().any(|(earlier, _)| earlier == name));
        if duplicate || per_unit.iter().any(|(_, price)| price.is_negative()) {
            return Err(PriceError::Invalid);
        }
        Ok(Self { per_unit })
    }
}

impl Price for DeclaredPrice {
    fn cost(&self, usage: &[(Code, u64)]) -> Result<NanoUsd, PriceError> {
        let mut total = NanoUsd::ZERO;
        for (name, count) in usage {
            let unit = self
                .per_unit
                .iter()
                .find(|(priced, _)| priced == name)
                .map(|(_, price)| *price)
                .ok_or(PriceError::Unpriced)?;
            if unit == NanoUsd::ZERO {
                // Free, whatever the count.
                continue;
            }
            let count = i64::try_from(*count).map_err(|_| PriceError::Overflow)?;
            let cost = unit.get().checked_mul(count).ok_or(PriceError::Overflow)?;
            total = total.checked_add(NanoUsd::new(cost)).ok_or(PriceError::Overflow)?;
        }
        Ok(total)
    }
}
