// SPDX-License-Identifier: Apache-2.0

//! # UAOS reference monitor
//!
//! Authorization for every Operation: default deny, fail closed on any evaluation error,
//! `Deny > Ask > Allow`, time-bounded grants that act as approvals, bounded policy text, and an
//! explanation for every decision. Built on Cedar; pure and synchronous, so a decision never waits
//! on I/O.
//!
//! ```text
//! @id("anthropic-for-agents")
//! permit(principal is Uaos::Agent, action == Uaos::Action::"model.call",
//!        resource in Uaos::Provider::"anthropic");
//!
//! @id("no-secrets-upstream")
//! forbid(principal, action == Uaos::Action::"model.call", resource)
//! when { context.data_classes.contains("secret.aws") };
//!
//! @id("exec-needs-approval") @effect("ask")
//! permit(principal is Uaos::Agent, action == Uaos::Action::"exec", resource);
//! ```

#![deny(missing_docs)]

mod engine;
mod model;
mod wire;

pub use engine::{CLOCK_TOLERANCE_MS, PolicyEngine, PolicyError};
pub use model::{Action, Basis, Decision, Effect, Grant, Name, NameError, Principal, Request, Resource};
pub use wire::{WireError, check_grant, grant_crosses_pockets, grant_record};
