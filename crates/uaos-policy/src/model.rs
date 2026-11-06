// SPDX-License-Identifier: Apache-2.0

//! Typed requests, decisions and grants. Everything that becomes Cedar text or a Cedar entity
//! identifier is validated here first, so caller-supplied strings can never alter a policy.

use std::collections::BTreeSet;
use std::fmt;

use uaos_contracts::event::ModuleName;
use uaos_contracts::id::{CredentialId, GrantId, PocketId, PoolId};
use uaos_contracts::operation::{OperationKind, RiskTier};

/// Error for a name that cannot be used as a resource or data-class identifier.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("names are 1..=128 characters of [A-Za-z0-9._:/-]")]
pub struct NameError;

/// A resource or data-class name, restricted to characters that need no escaping anywhere.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name(String);

/// Maximum length of a [`Name`].
const MAX_NAME: usize = 128;

impl Name {
    /// Validates and wraps a name.
    ///
    /// # Errors
    /// [`NameError`] if empty, too long, or containing other characters.
    pub fn new(value: impl Into<String>) -> Result<Self, NameError> {
        let value = value.into();
        let ok = !value.is_empty()
            && value.len() <= MAX_NAME
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'/' | b'-'));
        if ok { Ok(Self(value)) } else { Err(NameError) }
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Actions known to the authorization schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Action {
    /// A billable model call.
    ModelCall,
    /// A token-count call (non-billable, but carries the full prompt).
    CountTokens,
    /// A tool invocation.
    ToolCall,
    /// A process execution.
    Exec,
    /// A budget transfer between pools.
    BudgetTransfer,
    /// A configuration change.
    ConfigChange,
    /// Reading a pocket's memory: default deny. Reading another pocket is allowed only by a live
    /// grant; a policy at most asks for one. Reading the requesting pocket itself follows policy as
    /// any action does.
    MemoryRead,
}

impl Action {
    /// Every action, in schema order.
    pub const ALL: [Self; 7] = [
        Self::ModelCall,
        Self::CountTokens,
        Self::ToolCall,
        Self::Exec,
        Self::BudgetTransfer,
        Self::ConfigChange,
        Self::MemoryRead,
    ];

    /// Cedar action identifier.
    #[must_use]
    pub const fn cedar_id(self) -> &'static str {
        match self {
            Self::ModelCall => "model.call",
            Self::CountTokens => "model.count_tokens",
            Self::ToolCall => "tool.call",
            Self::Exec => "exec",
            Self::BudgetTransfer => "budget.transfer",
            Self::ConfigChange => "config.change",
            Self::MemoryRead => "memory.read",
        }
    }

    /// The action that authorizes an Operation of `kind`.
    #[must_use]
    pub const fn for_operation(kind: OperationKind) -> Self {
        match kind {
            OperationKind::ModelCall => Self::ModelCall,
            OperationKind::CountTokens => Self::CountTokens,
            OperationKind::ToolCall => Self::ToolCall,
            OperationKind::Exec => Self::Exec,
            OperationKind::BudgetTransfer => Self::BudgetTransfer,
            OperationKind::ConfigChange => Self::ConfigChange,
        }
    }
}

/// Who is asking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    /// An agent authenticated with a UAOS credential.
    Agent(CredentialId),
    /// A human through a user-present channel.
    Human,
    /// A module.
    Module(ModuleName),
    /// The kernel itself.
    System,
}

/// What is being acted on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resource {
    /// A model of a provider.
    Model {
        /// Provider name, e.g. `anthropic`.
        provider: Name,
        /// Model name, e.g. `claude-sonnet-5-5`.
        model: Name,
    },
    /// A tool.
    Tool(Name),
    /// A budget pool.
    Pool(PoolId),
    /// A configuration key.
    ConfigKey(Name),
    /// A pocket whose memory is read; the reading pocket is the request's `pocket`.
    Pocket(PocketId),
}

/// One authorization question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Who asks.
    pub principal: Principal,
    /// What they want to do.
    pub action: Action,
    /// On what.
    pub resource: Resource,
    /// In which pocket.
    pub pocket: PocketId,
    /// The grant the request carries, if any: a module's `GrantRef`. When set, only that grant can
    /// satisfy the request. A cross-pocket `memory.read` that names none is never allowed.
    pub grant: Option<GrantId>,
    /// Risk tier of the Operation.
    pub risk_tier: RiskTier,
    /// Data classes detected in the content (e.g. `secret.aws`, `pii.email`).
    pub data_classes: BTreeSet<Name>,
    /// Evaluation time, Unix milliseconds, from the trusted platform clock (`uaos_platform::Clock`).
    /// The engine refuses a request whose clock is more than
    /// [`CLOCK_TOLERANCE_MS`](crate::CLOCK_TOLERANCE_MS) behind the latest one it has seen.
    pub now_ms: u64,
}

/// Outcome, by precedence: `Deny` > `Ask` > `Allow`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Effect {
    /// Proceed.
    Allow,
    /// A human must approve first.
    Ask,
    /// Refused.
    Deny,
}

/// Why the decision came out as it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Basis {
    /// At least one permit matched and nothing forbade or asked.
    Permitted,
    /// A matching permit requires approval.
    ApprovalRequired,
    /// A live grant matched: it allows on its own, and it is the approval any matching ask policy
    /// requires. Never overrides a forbid.
    Granted,
    /// A forbid matched.
    Forbidden,
    /// No permit matched: default deny.
    NoMatchingPermit,
    /// A policy failed to evaluate, or the request was malformed: fail closed.
    EvaluationError,
}

/// An explained decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// The effect.
    pub effect: Effect,
    /// Why.
    pub basis: Basis,
    /// `@id`s of the policies that determined the decision, sorted; a grant is `grant:<id>`
    /// and comes first, followed by the ask policies it satisfied.
    pub policies: Vec<String>,
    /// `<@id>: <@reason>` for each of those policies that gives a reason.
    pub reasons: Vec<String>,
    /// Evaluation errors, if any (they always force `Deny`).
    pub errors: Vec<String>,
}

impl Decision {
    pub(crate) fn deny_error(error: impl Into<String>) -> Self {
        Self {
            effect: Effect::Deny,
            basis: Basis::EvaluationError,
            policies: Vec::new(),
            reasons: Vec::new(),
            errors: vec![error.into()],
        }
    }

    /// One-line explanation for `uaos policy explain`.
    #[must_use]
    pub fn explain(&self) -> String {
        let by = if self.policies.is_empty() {
            String::new()
        } else {
            format!(" by {}", self.policies.join(", "))
        };
        let why = if self.reasons.is_empty() {
            String::new()
        } else {
            format!(" ({})", self.reasons.join("; "))
        };
        match self.basis {
            Basis::Permitted => format!("allowed{by}{why}"),
            Basis::ApprovalRequired => format!("approval required{by}{why}"),
            Basis::Granted => format!("allowed{by}: the grant is the approval{why}"),
            Basis::Forbidden => format!("denied{by}{why}"),
            Basis::NoMatchingPermit => "denied: no policy permits this (default deny)".to_owned(),
            Basis::EvaluationError => format!(
                "denied: evaluation failed, so UAOS fails closed ({})",
                self.errors.join("; ")
            ),
        }
    }
}

/// A time-bounded capability, usually the recorded result of an approval. It covers only this
/// principal, action, resource and pocket, only while `now_ms < expires_at_ms`, and only requests
/// no riskier than approved (risk tier, data classes). It is equivalent to a Cedar permit with
/// those constraints, and it also satisfies the ask policies it lists in `approves`. A forbid still
/// wins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// Identifier, shown in explanations as `grant:<id>`.
    pub id: GrantId,
    /// Who receives it.
    pub principal: Principal,
    /// What it allows.
    pub action: Action,
    /// On what.
    pub resource: Resource,
    /// Where.
    pub pocket: PocketId,
    /// Unix milliseconds from which on it no longer applies (exclusive end).
    pub expires_at_ms: u64,
    /// The highest risk tier the approval covered; a riskier request is not covered.
    pub max_risk_tier: RiskTier,
    /// The data classes the approved content carried; a request with any other class is not
    /// covered.
    pub data_classes: BTreeSet<Name>,
    /// `@id`s of the ask policies this grant was issued to satisfy. A grant satisfies the asks
    /// that fire on a request only if it lists every one of them; with none listed, it still
    /// allows on its own where no permit matches.
    pub approves: BTreeSet<String>,
}

impl Request {
    /// Whether it reads another pocket than its own: `memory.read` on a pocket other than `pocket`.
    /// Only consent, a grant, allows that.
    #[must_use]
    pub fn crosses_pockets(&self) -> bool {
        self.action == Action::MemoryRead && self.resource != Resource::Pocket(self.pocket)
    }
}
