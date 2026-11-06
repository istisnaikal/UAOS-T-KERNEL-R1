// SPDX-License-Identifier: Apache-2.0

//! `uaos.grant/1` and the engine's [`Grant`]. A grant journaled when it is issued reloads into the
//! engine at boot exactly, and the engine loads no grant the wire cannot hold: [`check_grant`] is
//! the one place the wire's rules live, and both [`PolicyEngine::load`](crate::PolicyEngine::load)
//! and [`grant_record`] call it. The engine holds no approval, issue time or injection policy, so
//! building a record takes them from the caller.

use uaos_contracts::credential::ActionName;
use uaos_contracts::grant::{
    DataClass, GrantError, GrantName, GrantPrincipal, GrantRecord, GrantResource, InjectionPolicy, PolicyId,
};
use uaos_contracts::id::ApprovalId;
use uaos_contracts::limits::MAX_SCOPE_ITEMS;
use uaos_contracts::time::WallTime;

use crate::model::{Action, Grant, Name, Principal, Resource};

/// A grant that does not convert between the wire and the engine.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WireError {
    /// An action the engine does not know.
    #[error("the action `{0}` is not one the engine knows")]
    UnknownAction(String),
    /// A name or policy identifier outside the wire's grammar, or a model provider with `/`
    /// (which the engine's provider entity cannot hold).
    #[error("a name or policy identifier does not fit both grammars")]
    Name,
    /// An expiry outside the wire's time range (after 9999-12-30T22:00Z, the wire's maximum).
    #[error("the expiry is outside the wire's time range")]
    Expiry,
    /// A grant that fails `uaos.grant/1`'s own rules.
    #[error(transparent)]
    Invalid(#[from] GrantError),
}

/// The expiry as wire time, if the wire can hold it.
fn wire_expiry(expires_at_ms: u64) -> Result<WallTime, WireError> {
    i128::from(expires_at_ms)
        .checked_mul(1_000_000)
        .and_then(|nanos| WallTime::from_unix_nanos(nanos).ok())
        .ok_or(WireError::Expiry)
}

/// Whether `grant` is a read of another pocket: the one kind that carries an injection policy.
#[must_use]
pub fn grant_crosses_pockets(grant: &Grant) -> bool {
    grant.action == Action::MemoryRead && grant.resource != Resource::Pocket(grant.pocket)
}

/// Checks that the wire can hold `grant`: names in the wire's grammar and no provider with `/`, at
/// most [`MAX_SCOPE_ITEMS`] data classes and approved asks, approved asks in the policy-identifier
/// grammar, an expiry the wire can hold, and `memory.read` paired with a pocket and only with one.
///
/// # Errors
/// The first rule the grant breaks.
pub fn check_grant(grant: &Grant) -> Result<(), WireError> {
    let wire_name = |name: &Name| GrantName::new(name.as_str()).map(drop).map_err(|_| WireError::Name);
    match &grant.resource {
        Resource::Model { provider, model } => {
            if provider.as_str().contains('/') {
                return Err(WireError::Name);
            }
            wire_name(provider)?;
            wire_name(model)?;
        }
        Resource::Tool(name) | Resource::ConfigKey(name) => wire_name(name)?,
        Resource::Pool(_) | Resource::Pocket(_) => {}
    }
    if (grant.action == Action::MemoryRead) != matches!(grant.resource, Resource::Pocket(_)) {
        return Err(GrantError::ResourceMismatch.into());
    }
    if grant.data_classes.len() > MAX_SCOPE_ITEMS || grant.approves.len() > MAX_SCOPE_ITEMS {
        return Err(GrantError::TooBroad { max: MAX_SCOPE_ITEMS }.into());
    }
    for class in &grant.data_classes {
        DataClass::new(class.as_str()).map_err(|_| WireError::Name)?;
    }
    for ask in &grant.approves {
        PolicyId::new(ask.as_str()).map_err(|_| WireError::Name)?;
    }
    wire_expiry(grant.expires_at_ms).map(drop)
}

fn engine_name(name: &str) -> Result<Name, WireError> {
    Name::new(name).map_err(|_| WireError::Name)
}

fn wire_name(name: &Name) -> Result<GrantName, WireError> {
    GrantName::new(name.as_str()).map_err(|_| WireError::Name)
}

impl TryFrom<&GrantRecord> for Grant {
    type Error = WireError;

    /// Reloads a journaled grant. An expiry finer than a millisecond floors, so the reloaded
    /// grant ends early, never late.
    fn try_from(record: &GrantRecord) -> Result<Self, WireError> {
        record.validate()?;
        let action = Action::ALL
            .into_iter()
            .find(|a| a.cedar_id() == record.action.as_str())
            .ok_or_else(|| WireError::UnknownAction(record.action.as_str().to_owned()))?;
        let principal = match &record.principal {
            GrantPrincipal::Agent { credential } => Principal::Agent(*credential),
            GrantPrincipal::Module { name } => Principal::Module(name.clone()),
            GrantPrincipal::Human {} => Principal::Human,
            GrantPrincipal::System {} => Principal::System,
        };
        let resource = match &record.resource {
            GrantResource::Model { provider, name } => Resource::Model {
                provider: engine_name(provider.as_str())?,
                model: engine_name(name.as_str())?,
            },
            GrantResource::Tool { name } => Resource::Tool(engine_name(name.as_str())?),
            GrantResource::Pool { id } => Resource::Pool(*id),
            GrantResource::ConfigKey { name } => Resource::ConfigKey(engine_name(name.as_str())?),
            GrantResource::Pocket { id } => Resource::Pocket(*id),
        };
        let grant = Self {
            id: record.id,
            principal,
            action,
            resource,
            pocket: record.pocket,
            expires_at_ms: record.expires_at.unix_millis_saturating(),
            max_risk_tier: record.max_risk_tier,
            data_classes: record
                .data_classes
                .iter()
                .map(|c| engine_name(c.as_str()))
                .collect::<Result<_, _>>()?,
            approves: record.approves.iter().map(|id| id.as_str().to_owned()).collect(),
        };
        // A record the engine could not load (a provider with `/`) is refused here, not at load,
        // where it would refuse the whole set.
        check_grant(&grant)?;
        Ok(grant)
    }
}

/// The record that journals `grant`, issued through `approval` at `issued_at`, with `injection`
/// for a read of another pocket.
///
/// # Errors
/// [`WireError`] if [`check_grant`] refuses the grant, or the record fails its own validation
/// (an expiry at or before `issued_at`, or an injection policy on any grant but a cross-pocket
/// read, or none on one).
pub fn grant_record(
    grant: &Grant,
    approval: ApprovalId,
    issued_at: WallTime,
    injection: Option<InjectionPolicy>,
) -> Result<GrantRecord, WireError> {
    check_grant(grant)?;
    let principal = match &grant.principal {
        Principal::Agent(credential) => GrantPrincipal::Agent {
            credential: *credential,
        },
        Principal::Module(name) => GrantPrincipal::Module { name: name.clone() },
        Principal::Human => GrantPrincipal::Human {},
        Principal::System => GrantPrincipal::System {},
    };
    let resource = match &grant.resource {
        Resource::Model { provider, model } => GrantResource::Model {
            provider: wire_name(provider)?,
            name: wire_name(model)?,
        },
        Resource::Tool(name) => GrantResource::Tool { name: wire_name(name)? },
        Resource::Pool(id) => GrantResource::Pool { id: *id },
        Resource::ConfigKey(name) => GrantResource::ConfigKey { name: wire_name(name)? },
        Resource::Pocket(id) => GrantResource::Pocket { id: *id },
    };
    let record = GrantRecord {
        id: grant.id,
        principal,
        action: ActionName::new(grant.action.cedar_id())
            .map_err(|_| WireError::UnknownAction(grant.action.cedar_id().to_owned()))?,
        resource,
        pocket: grant.pocket,
        approval,
        issued_at,
        expires_at: wire_expiry(grant.expires_at_ms)?,
        max_risk_tier: grant.max_risk_tier,
        data_classes: grant
            .data_classes
            .iter()
            .map(|c| DataClass::new(c.as_str()).map_err(|_| WireError::Name))
            .collect::<Result<_, _>>()?,
        approves: grant
            .approves
            .iter()
            .map(|id| PolicyId::new(id.as_str()).map_err(|_| WireError::Name))
            .collect::<Result<_, _>>()?,
        injection,
    };
    record.validate()?;
    Ok(record)
}
