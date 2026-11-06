// SPDX-License-Identifier: Apache-2.0

//! The Operation lifecycle.
//!
//! Every side effect UAOS mediates (model call, token count, tool call, exec, budget
//! transfer, config change) is an [`Operation`] and moves through exactly one state machine.
//! The machine is a pure function, so it can be exhaustively property-tested and replayed
//! from the journal.
//!
//! ```text
//! Proposed ─Authorize→ Authorized ─Reserve→ Reserved ─Execute→ Executing ─Commit→ Committed
//!    │ ├─Deny→ Denied      │ └─Deny/Fail→ Denied/Failed     │       └─Fail→ Failed
//!    │ └─RequireApproval→ ApprovalRequired (terminal; retry = new Operation)
//!    │                           Reserved/Executing ─CrashRecovered→ Indeterminate
//!    │                           Indeterminate ─ResolveCommitted/ResolveFailed→ Committed/Failed
//!    └ Committed/Failed ─Compensate→ Compensated   (only if compensable — red line 3)
//! ```
//!
//! Two honesty rules are enforced here rather than in review:
//! 1. An Operation whose effect is not compensable can never reach `Compensated`.
//! 2. `Indeterminate` is reachable only through crash recovery, and leaves it only through
//!    evidence (`ResolveCommitted` / `ResolveFailed`), never by assumption.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::id::OperationId;

/// What kind of side effect an Operation performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    /// A billable call to a model provider.
    ModelCall,
    /// A non-billable token-count call; still carries the full prompt, so it is governed.
    CountTokens,
    /// A tool invocation mediated by UAOS.
    ToolCall,
    /// A process execution through the sandbox broker.
    Exec,
    /// A transfer between budget pools.
    BudgetTransfer,
    /// A transactional configuration change.
    ConfigChange,
}

/// How far an Operation's effect reaches. Drives approval, journaling and honesty rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SideEffectClass {
    /// No effect outside UAOS's own state.
    None,
    /// A local effect that can be reverted exactly (for example a config change with a
    /// recorded previous snapshot).
    LocalReversible,
    /// A local effect that cannot be reverted exactly (for example a deleted file).
    LocalIrreversible,
    /// An effect outside this machine: a provider call, a network request, a message sent.
    External,
}

/// Risk tier, 0 (lowest) to 3 (highest). Higher tiers fail closed and require approval more
/// readily.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct RiskTier(u8);

impl JsonSchema for RiskTier {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "RiskTier".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "description": "Risk tier, 0 (lowest) to 3 (highest).",
            "type": "integer",
            "minimum": 0,
            "maximum": 3
        })
    }
}

/// Error returned for a risk tier above 3.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("risk tier must be between 0 and 3")]
pub struct RiskTierError;

impl RiskTier {
    /// The highest risk tier.
    pub const MAX: Self = Self(3);
    /// The lowest tier: routine bookkeeping.
    pub const MIN: Self = Self(0);

    /// Creates a risk tier.
    ///
    /// # Errors
    /// Returns [`RiskTierError`] if `tier > 3`.
    pub const fn new(tier: u8) -> Result<Self, RiskTierError> {
        if tier <= 3 { Ok(Self(tier)) } else { Err(RiskTierError) }
    }

    /// Returns the numeric tier.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for RiskTier {
    type Error = RiskTierError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        Self::new(v)
    }
}

impl From<RiskTier> for u8 {
    fn from(t: RiskTier) -> Self {
        t.0
    }
}

/// Lifecycle state of an Operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    /// Created; nothing decided yet.
    Proposed,
    /// Policy allowed it.
    Authorized,
    /// Refused before any side effect (policy, budget, or the final egress scan).
    Denied,
    /// Needs a human decision. Terminal for this Operation: the client receives an error
    /// carrying the approval ID, and a retry after approval is a new Operation.
    ApprovalRequired,
    /// A budget reservation and the write-ahead intent are durably recorded.
    Reserved,
    /// The side effect is in progress (bytes may have left the machine).
    Executing,
    /// Completed successfully.
    Committed,
    /// Failed. If it failed after execution started, side effects may still have happened.
    Failed,
    /// Its effect was undone by a compensating action.
    Compensated,
    /// A crash happened after the write-ahead intent and before an outcome was recorded.
    /// Neither success nor failure may be assumed.
    Indeterminate,
}

impl OperationState {
    /// Returns `true` if no further transition is possible except compensation or
    /// evidence-based resolution.
    #[must_use]
    pub const fn is_settled(self) -> bool {
        matches!(
            self,
            Self::Denied | Self::ApprovalRequired | Self::Committed | Self::Failed | Self::Compensated
        )
    }
}

/// An input to the lifecycle state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Transition {
    /// Policy allowed the Operation.
    Authorize,
    /// Refused before any side effect.
    Deny,
    /// Policy requires a human decision.
    RequireApproval,
    /// Budget reserved and write-ahead intent recorded.
    Reserve,
    /// Execution started.
    Execute,
    /// Execution completed successfully.
    Commit,
    /// The Operation failed.
    Fail,
    /// A compensating action undid the effect.
    Compensate,
    /// Startup recovery found an intent without an outcome.
    CrashRecovered,
    /// Evidence (for example provider usage records) shows the effect completed.
    ResolveCommitted,
    /// Evidence shows the effect did not complete.
    ResolveFailed,
}

/// Why a transition was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TransitionError {
    /// The transition is not defined from the current state.
    #[error("transition {transition:?} is not allowed from state {from:?}")]
    NotAllowed {
        /// State the Operation was in.
        from: OperationState,
        /// Transition that was attempted.
        transition: Transition,
    },
    /// Compensation was requested for an Operation whose effect is not compensable.
    /// UAOS must warn honestly instead of claiming a rollback (red line 3).
    #[error("operation is not compensable; its effect cannot be undone and must not be reported as undone")]
    NotCompensable,
}

/// A unit of side effect and its lifecycle position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Operation {
    /// Identifier.
    pub id: OperationId,
    /// What the Operation does.
    pub kind: OperationKind,
    /// How far its effect reaches.
    pub side_effect_class: SideEffectClass,
    /// Whether a compensating action can undo the effect.
    pub compensable: bool,
    /// Risk tier.
    pub risk_tier: RiskTier,
    /// Current lifecycle state.
    pub state: OperationState,
}

impl Operation {
    /// Creates an Operation in the [`OperationState::Proposed`] state.
    #[must_use]
    pub const fn propose(
        id: OperationId,
        kind: OperationKind,
        side_effect_class: SideEffectClass,
        compensable: bool,
        risk_tier: RiskTier,
    ) -> Self {
        Self {
            id,
            kind,
            side_effect_class,
            compensable,
            risk_tier,
            state: OperationState::Proposed,
        }
    }

    /// Applies a transition, returning the Operation in its new state. The receiver is not
    /// modified: lifecycle history is a sequence of values, mirrored by journal events.
    ///
    /// # Errors
    /// Returns [`TransitionError`] if the transition is not allowed from the current state,
    /// or if compensation is requested for a non-compensable Operation.
    pub fn apply(self, transition: Transition) -> Result<Self, TransitionError> {
        use OperationState as S;
        use Transition as T;

        let next = match (self.state, transition) {
            (S::Proposed, T::Authorize) => S::Authorized,
            (S::Proposed | S::Authorized | S::Reserved, T::Deny) => S::Denied,
            (S::Proposed, T::RequireApproval) => S::ApprovalRequired,
            (S::Authorized, T::Reserve) => S::Reserved,
            (S::Authorized | S::Reserved | S::Executing, T::Fail) | (S::Indeterminate, T::ResolveFailed) => S::Failed,
            (S::Reserved, T::Execute) => S::Executing,
            (S::Executing, T::Commit) | (S::Indeterminate, T::ResolveCommitted) => S::Committed,
            (S::Reserved | S::Executing, T::CrashRecovered) => S::Indeterminate,
            (S::Committed | S::Failed, T::Compensate) => {
                if !self.compensable {
                    return Err(TransitionError::NotCompensable);
                }
                S::Compensated
            }
            (from, transition) => return Err(TransitionError::NotAllowed { from, transition }),
        };
        Ok(Self { state: next, ..self })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::TypedId;
    use proptest::prelude::*;

    const ALL: [Transition; 11] = [
        Transition::Authorize,
        Transition::Deny,
        Transition::RequireApproval,
        Transition::Reserve,
        Transition::Execute,
        Transition::Commit,
        Transition::Fail,
        Transition::Compensate,
        Transition::CrashRecovered,
        Transition::ResolveCommitted,
        Transition::ResolveFailed,
    ];

    fn op(compensable: bool) -> Operation {
        Operation::propose(
            OperationId::from_parts(1, [0; 10]),
            OperationKind::ModelCall,
            SideEffectClass::External,
            compensable,
            RiskTier::MAX,
        )
    }

    fn run(mut o: Operation, steps: &[usize]) -> Vec<OperationState> {
        let mut seen = vec![o.state];
        for &i in steps {
            if let Ok(next) = o.apply(ALL[i % ALL.len()]) {
                o = next;
                seen.push(o.state);
            }
        }
        seen
    }

    #[test]
    fn happy_path() {
        let o = op(false);
        let o = o.apply(Transition::Authorize).unwrap();
        let o = o.apply(Transition::Reserve).unwrap();
        let o = o.apply(Transition::Execute).unwrap();
        let o = o.apply(Transition::Commit).unwrap();
        assert_eq!(o.state, OperationState::Committed);
        assert_eq!(o.apply(Transition::Compensate), Err(TransitionError::NotCompensable));
    }

    #[test]
    fn approval_required_is_terminal() {
        let o = op(true).apply(Transition::RequireApproval).unwrap();
        for t in ALL {
            assert!(o.apply(t).is_err(), "{t:?} escaped ApprovalRequired");
        }
    }

    proptest! {
        /// Red line 3: a non-compensable Operation never reaches `Compensated`.
        #[test]
        fn non_compensable_never_compensated(steps in prop::collection::vec(any::<usize>(), 0..64)) {
            let seen = run(op(false), &steps);
            prop_assert!(!seen.contains(&OperationState::Compensated));
        }

        /// `Indeterminate` is entered only from Reserved/Executing via crash recovery.
        #[test]
        fn indeterminate_only_via_crash_recovery(steps in prop::collection::vec(any::<usize>(), 0..64)) {
            let mut o = op(true);
            for i in steps {
                let t = ALL[i % ALL.len()];
                if let Ok(next) = o.apply(t) {
                    if next.state == OperationState::Indeterminate {
                        prop_assert_eq!(t, Transition::CrashRecovered);
                        prop_assert!(matches!(o.state, OperationState::Reserved | OperationState::Executing));
                    }
                    o = next;
                }
            }
        }

        /// Nothing but compensation leaves a settled state, and only Compensated is final.
        #[test]
        fn settled_states_only_leave_via_compensation(steps in prop::collection::vec(any::<usize>(), 0..64)) {
            let mut o = op(true);
            for i in steps {
                let t = ALL[i % ALL.len()];
                if let Ok(next) = o.apply(t) {
                    if o.state.is_settled() {
                        prop_assert_eq!(t, Transition::Compensate);
                    }
                    o = next;
                }
            }
        }

        /// Applying a transition never mutates identity or facts, only the state.
        #[test]
        fn only_state_changes(steps in prop::collection::vec(any::<usize>(), 0..32)) {
            let start = op(true);
            let mut o = start;
            for i in steps {
                if let Ok(next) = o.apply(ALL[i % ALL.len()]) {
                    prop_assert_eq!(Operation { state: start.state, ..next }, start);
                    o = next;
                }
            }
        }
    }
}
