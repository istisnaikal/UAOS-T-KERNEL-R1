// SPDX-License-Identifier: Apache-2.0

//! # The UAOS runtime: the relay, the stop, admission and boot recovery
//!
//! The state actor is, the bus, and the pipeline that joins them to the egress door.
//!
//! - [`Stop`] is the kernel's kill switch. It is one atomic flag that admission reads first and
//!   every admitted Operation watches. It acts before its record ([`Engaged::draft`]), and a
//!   journaled stop is honoured at boot ([`boot_state`]).
//! - [`Admission`] counts bytes in flight as well as Operations.
//! - [`ConfigCell`] publishes configuration snapshots. Each Operation pins one, with its locale
//!   as an opaque [`LocaleTag`]. No Ring 0 type names a locale (language neutrality).
//! - [`DeclaredPrice`] prices usage in nano-USD per unit, the user-declared form permits.
//! - [`Relay`] streams a provider's response to the client. The client's connection pulls it,
//!   it holds at most one incomplete event, and it forwards exact bytes. Every usage report the
//!   codec finds is priced against the Operation's reservation, and the first one past it cuts
//!   the stream, drops the upstream and engages the stop.
//! - [`Supervisor`] is the runtime's only spawner.
//! - [`pipeline`] is the request's typestate, stages in order, the only way to the
//!   [`pipeline::Ready`] value the door will accept.
//! - [`boot`] recovers the kernel from its journal: it refuses records that are not the whole
//!   journal and a configuration older than the journal's, restores the stop, recovers the ledger,
//!   makes every open intent `Indeterminate` once with the effect it declared, and explains the
//!   boot, saying when a stop may have been lost.
//!
//! **Honest limits.** The hard cap is the reservation taken before the request. The relay sees
//! token counts only when the provider reports them, so content between reports is forwarded
//! unmetered. Bytes already forwarded cannot be recalled, and a cut never claims a rollback (red
//! line 3).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod admission;
mod boot;
mod config;
mod ledger_task;
pub mod pipeline;
mod price;
mod relay;
pub mod splice;
mod sse;
mod startup;
mod state;
mod stop;
mod supervisor;

pub use admission::{Admission, AdmissionLimits, DRAINING_RETRY_AFTER, Permit, Refusal, RefusalReason};
pub use boot::{BootError, BootReport, Booted, CRASH_RECOVERY, LastEnd, boot};
pub use config::{ConfigCell, ConfigError, ConfigSnapshot, LocaleError, LocaleTag, MAX_LOCALE_TAG};
pub use ledger_task::{
    DEFAULT_LEDGER_QUEUE, Held, InFlight, LedgerCallError, LedgerHandle, LedgerSnapshot, LedgerStats,
    MAX_UPSTREAM_NAME, Movement, OpenReservations, OperationRecord, Released, RepairBy, Settled, is_upstream_name,
    start_ledger_task,
};
pub use price::{DeclaredPrice, Price, PriceError};
pub use relay::{CutReason, Relay, RelayBody, RelayEnd, RelayError, RelayLimits, RelayReport};
pub use startup::{JournalSource, Started, StartupError, start_kernel};
pub use state::{
    DEFAULT_QUEUE_CAPACITY, LEDGER_DRAIN_GRACE, ShutdownReason, ShutdownReport, StartRefused, StateActor, StateCore,
    StateError, StateExit, StateHandle, StateQueue, StateStats, shut_down, start_state_actor, state_queue,
    stop_reason_for,
};
pub use stop::{BootState, Engaged, EngagedBy, Stop, StopReason, StopWatch, boot_state};
pub use supervisor::{SpawnError, Supervisor, SupervisorLimits};
