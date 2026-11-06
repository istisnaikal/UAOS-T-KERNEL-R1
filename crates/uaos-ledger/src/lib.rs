// SPDX-License-Identifier: Apache-2.0

//! # UAOS budget ledger
//!
//! Pools of money, reservations taken before an Operation executes, settlement against actual
//! usage, and transfers. What the cap guarantees, precisely:
//!
//! * **reservations and outgoing transfers are capped:** one that exceeds the pool's available
//!   balance, minus any overrun not yet closed, is refused before anything is recorded. The
//!   same rule is checked again on every entry when the journal is replayed;
//! * **actual spend is not capped by this crate.** When a provider reports more than was
//!   reserved, the overrun is recorded truthfully (the pool can go negative) and returned in
//!   [`Settlement::overrun`] for the runtime to raise as S1. Keeping overruns rare is the job of
//!   the affordability clamp and the pricing reconciliation in P3;
//! * money is integer nano-USD; floats are banned in this crate;
//! * every entry is recorded before it takes effect. It survives a process kill; within the
//!   power-loss window W of balanced durability it can be lost. The ledger is a pure replay of its
//!   entries (the journal's `budget.entry` records);
//! * money that may already be spent is never released: in-flight reservations can only settle,
//!   and recovery settles open reservations at full cost, marked estimated. A rebuilt ledger
//!   refuses new work until that recovery has run.
//!
//! Limitations stated plainly: the idempotency index and the set of closed reservations grow
//! with the number of entries until journal compaction introduces snapshots; the journal
//! does not yet record when execution began (see [`Ledger`]).

#![deny(missing_docs)]
#![deny(clippy::float_arithmetic)]

mod journal_sink;
mod ledger;
mod state;

pub use journal_sink::{JournalSink, entries_from_journal};
pub use ledger::{
    CloseError, Held, InFlight, Ledger, LedgerSink, MemorySink, Recovery, Reservation, Settlement, Usage,
};
pub use state::{LedgerError, LedgerState, PoolState};
