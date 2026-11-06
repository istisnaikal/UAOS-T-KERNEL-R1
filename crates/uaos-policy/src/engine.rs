// SPDX-License-Identifier: Apache-2.0

//! The policy engine: Cedar evaluation with UAOS semantics layered on top.
//!
//! * **Default deny.** Nothing is allowed unless a permit or a grant matches. A read of another
//!   pocket is the exception that narrows it: only the grant the request names allows it, and a
//!   permit at most asks.
//! * **Fail closed.** Cedar skips a policy whose evaluation errors (for example an integer
//!   overflow), so an erroring `forbid` would silently stop forbidding. UAOS turns any
//!   evaluation error into `Deny`, as it does a request or entity set that fails validation, and a
//!   request whose clock runs backwards.
//! * **Deny > Ask > Allow.** A permit annotated `@effect("ask")` that matches turns an Allow into
//!   an approval request; a forbid wins over both. A matching **grant** is the recorded approval
//!   for exactly that principal, action, resource and pocket: it satisfies an Ask, and allows on
//!   its own when no permit matches, but never overrides a forbid.
//! * **Strict loading.** Policy text is bounded before Cedar parses it (nesting, operators,
//!   length), so crafted text cannot overflow the stack. Every policy carries a unique, plain
//!   `@id`; only known annotations are accepted (a typo such as `@efect("ask")` would otherwise
//!   silently mean Allow); templates are refused; and the set is validated against the UAOS
//!   schema in strict mode. A policy set that fails any check never loads.
//! * **Grants** are exact-match capabilities, indexed by principal, action, resource and pocket,
//!   and only live while `now_ms` is before their expiry. Evaluating them costs a map lookup, not
//!   a Cedar policy each; a property test proves the result equals compiling the grant to a Cedar
//!   permit, except for a cross-pocket read, where a compiled permit would only ask. The engine
//!   loads no grant `uaos.grant/1` cannot journal (`check_grant`) and no grant id twice.
//! * **Slicing.** Policies are partitioned at load by their action constraint (following the
//!   schema's action groups) and, within an action, by an exact `resource ==` constraint. A
//!   decision evaluates the action's common policies plus those for its resource, merging the
//!   two Cedar answers. A property test against the complete set proves slicing never changes a
//!   decision.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};

use cedar_policy::{
    ActionConstraint, AuthorizationError, Authorizer, Context, Decision as CedarDecision, Effect as CedarEffect,
    Entities, Entity, EntityId, EntityTypeName, EntityUid, Policy, PolicySet, Request as CedarRequest,
    ResourceConstraint, RestrictedExpression, Schema, ValidationMode, Validator,
};

use uaos_contracts::id::GrantId;

use crate::model::{Action, Basis, Decision, Effect, Grant, Principal, Request, Resource};
use crate::wire::check_grant;

const SCHEMA_SRC: &str = include_str!("uaos.cedarschema");
const NAMESPACE: &str = "Uaos";

/// Annotations a policy may carry.
const ANNOTATION_ID: &str = "id";
const ANNOTATION_EFFECT: &str = "effect";
const ANNOTATION_REASON: &str = "reason";
const EFFECT_ASK: &str = "ask";
/// Prefix reserved for grants in explanations.
const GRANT_PREFIX: &str = "grant:";
/// Longest `@id`.
const MAX_ID: usize = 128;

/// Bounds on policy text, checked before Cedar sees it. Cedar's parser and evaluator recurse;
/// measured on a 1 MiB stack in a debug build, they overflow at 32 nested brackets, 256 nested
/// `if`s and 4,096 chained operators. The bounds sit far inside those limits so that all of them at
/// once still fit (`a_policy_at_every_bound_still_loads`).
const MAX_NESTING: usize = 8;
const MAX_IFS: usize = 16;
const MAX_OPERATORS: usize = 256;
const MAX_STATEMENT_BYTES: usize = 16 * 1024;
const MAX_TEXT_BYTES: usize = 4 * 1024 * 1024;

/// How far a request's clock may run behind the latest one seen before it is refused: a clock
/// moving backwards could otherwise revive an expired grant.
pub const CLOCK_TOLERANCE_MS: u64 = 5_000;

/// Why a policy set could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// The built-in schema failed to parse (a build defect, never user input).
    #[error("authorization schema is invalid: {0}")]
    Schema(String),
    /// The policy text does not parse.
    #[error("policy text does not parse: {0}")]
    Parse(String),
    /// A policy violates a UAOS loading rule (ids, annotations, templates, bounds).
    #[error("policy {policy}: {problem}")]
    Rule {
        /// The policy's `@id`, or its statement number if it has none yet.
        policy: String,
        /// What is wrong.
        problem: String,
    },
    /// The set does not validate against the schema in strict mode.
    #[error("policies do not validate against the UAOS schema: {0}")]
    Invalid(String),
}

/// The engine loads no grant the wire cannot journal, and no grant id twice: every grant it holds
/// can be journaled and reloaded exactly.
fn check_grants(grants: &[Grant]) -> Result<(), PolicyError> {
    let mut ids = BTreeSet::new();
    for grant in grants {
        let label = format!("{GRANT_PREFIX}{}", grant.id);
        check_grant(grant).map_err(|e| PolicyError::Rule {
            policy: label.clone(),
            problem: e.to_string(),
        })?;
        if !ids.insert(grant.id) {
            return Err(PolicyError::Rule {
                policy: label,
                problem: "the grant id is used twice".to_owned(),
            });
        }
    }
    Ok(())
}

/// What a grant matches exactly: action, principal, resource and pocket.
type GrantKey = (Action, String, String, String);

/// A live grant in the index, with what its approval covered.
#[derive(Debug)]
struct GrantEntry {
    id: GrantId,
    label: String,
    expires_at_ms: u64,
    max_risk_tier: u8,
    data_classes: BTreeSet<String>,
    approves: BTreeSet<String>,
}

/// The policies one action evaluates: those for any resource, and those pinned to one resource by
/// `resource == …` (1,000 policies on one action took p99 1.7 ms).
#[derive(Debug, Default)]
struct Slice {
    common: PolicySet,
    by_resource: BTreeMap<String, PolicySet>,
}

/// A loaded, immutable policy set. Build a new engine to change policies or grants.
#[derive(Debug)]
pub struct PolicyEngine {
    schema: Schema,
    authorizer: Authorizer,
    /// The complete validated set, kept as the oracle that slicing is checked against.
    all: PolicySet,
    by_action: BTreeMap<Action, Slice>,
    /// Cedar policy id → UAOS `@id`.
    labels: BTreeMap<String, String>,
    /// `@id` → `@reason`, for policies that give one.
    reasons: BTreeMap<String, String>,
    /// Cedar policy ids of permits annotated `@effect("ask")`.
    asks: BTreeSet<String>,
    /// Live grants by what they match, sorted by label.
    grants: BTreeMap<GrantKey, Vec<GrantEntry>>,
    /// The latest `now_ms` any request carried.
    clock_high_water: AtomicU64,
}

fn schema() -> Result<Schema, PolicyError> {
    Schema::from_cedarschema_str(SCHEMA_SRC)
        .map(|(schema, _warnings)| schema)
        .map_err(|e| PolicyError::Schema(e.to_string()))
}

fn uid(entity_type: &str, id: &str) -> Result<EntityUid, String> {
    let ty = EntityTypeName::from_str(&format!("{NAMESPACE}::{entity_type}")).map_err(|e| e.to_string())?;
    Ok(EntityUid::from_type_name_and_id(ty, EntityId::new(id)))
}

fn principal_uid(p: &Principal) -> Result<EntityUid, String> {
    match p {
        Principal::Agent(cred) => uid("Agent", &cred.to_string()),
        Principal::Human => uid("Human", "human"),
        Principal::Module(name) => uid("Module", name.as_str()),
        Principal::System => uid("System", "system"),
    }
}

fn resource_uid(r: &Resource) -> Result<EntityUid, String> {
    match r {
        Resource::Model { provider, model } => {
            // `provider/model` is injective only if the provider has no `/`.
            if provider.as_str().contains('/') {
                return Err("a provider name must not contain `/`".to_owned());
            }
            uid("Model", &format!("{provider}/{model}"))
        }
        Resource::Tool(name) => uid("Tool", name.as_str()),
        Resource::Pool(pool) => uid("Pool", &pool.to_string()),
        Resource::ConfigKey(name) => uid("ConfigKey", name.as_str()),
        Resource::Pocket(pocket) => uid("Pocket", &pocket.to_string()),
    }
}

fn action_uid(action: Action) -> Result<EntityUid, String> {
    uid("Action", action.cedar_id())
}

/// Cedar source text of an entity reference, e.g. `Uaos::Tool::"git"`. Safe to embed: every
/// component is a validated name or a typed identifier.
fn cedar_ref(entity: &EntityUid) -> String {
    format!("{}::\"{}\"", entity.type_name(), entity.id().unescaped())
}

fn grant_key(action: Action, principal: &Principal, resource: &Resource, pocket: &str) -> Result<GrantKey, String> {
    Ok((
        action,
        principal_uid(principal)?.to_string(),
        resource_uid(resource)?.to_string(),
        pocket.to_owned(),
    ))
}

impl Grant {
    /// The grant as Cedar policy text: the permit it is equivalent to. UAOS does not evaluate
    /// this text (grants are matched directly); it is the oracle the equivalence property checks
    /// against.
    ///
    /// # Errors
    /// The grant's principal or resource cannot be named, or its expiry exceeds Cedar's range.
    #[doc(hidden)]
    pub fn equivalent_permit(&self, id: &str) -> Result<String, String> {
        let principal = principal_uid(&self.principal)?;
        let resource = resource_uid(&self.resource)?;
        let action = action_uid(self.action)?;
        let expires = i64::try_from(self.expires_at_ms).map_err(|_| "expiry out of range".to_owned())?;
        let classes = if self.data_classes.is_empty() {
            "context.data_classes.isEmpty()".to_owned()
        } else {
            let list: Vec<String> = self.data_classes.iter().map(|c| format!("\"{c}\"")).collect();
            format!("[{}].containsAll(context.data_classes)", list.join(", "))
        };
        Ok(format!(
            "@id(\"{id}\")\npermit(principal == {}, action == {}, resource == {})\nwhen {{ context.pocket == \"{}\" && context.now_ms < {expires} && context.risk_tier <= {} && {classes} }};",
            cedar_ref(&principal),
            cedar_ref(&action),
            cedar_ref(&resource),
            self.pocket,
            self.max_risk_tier.get(),
        ))
    }
}

impl PolicyEngine {
    /// Loads `policies` (Cedar text) plus `grants`. Grants already expired at `now_ms` are
    /// left out; the rest stop applying at their expiry anyway.
    ///
    /// # Errors
    /// [`PolicyError`] if anything exceeds the text bounds, fails to parse, breaks a loading
    /// rule, or fails strict schema validation; if a grant names something that cannot be named,
    /// is one `uaos.grant/1` cannot journal (`check_grant`), or shares its id with another.
    /// Nothing is partially loaded.
    pub fn load(policies: &str, grants: &[Grant], now_ms: u64) -> Result<Self, PolicyError> {
        Self::load_with(schema()?, policies, grants, now_ms)
    }

    /// Like [`PolicyEngine::load`] with another Cedar schema in place of the UAOS one. For tests
    /// of schema-dependent behaviour (action groups), never for production.
    ///
    /// # Errors
    /// As [`PolicyEngine::load`], or [`PolicyError::Schema`] if `schema_src` does not parse.
    #[doc(hidden)]
    pub fn load_with_schema(
        schema_src: &str,
        policies: &str,
        grants: &[Grant],
        now_ms: u64,
    ) -> Result<Self, PolicyError> {
        let schema = Schema::from_cedarschema_str(schema_src)
            .map(|(schema, _warnings)| schema)
            .map_err(|e| PolicyError::Schema(e.to_string()))?;
        Self::load_with(schema, policies, grants, now_ms)
    }

    fn load_with(schema: Schema, policies: &str, grants: &[Grant], now_ms: u64) -> Result<Self, PolicyError> {
        check_bounds(policies)?;
        let parsed = PolicySet::from_str(policies).map_err(|e| PolicyError::Parse(e.to_string()))?;
        if let Some(template) = parsed.templates().next() {
            return Err(PolicyError::Rule {
                policy: template.annotation(ANNOTATION_ID).unwrap_or("a template").to_owned(),
                problem: "templates are not supported; write static policies or use grants".to_owned(),
            });
        }

        let mut all = PolicySet::new();
        let mut labels = BTreeMap::new();
        let mut reasons = BTreeMap::new();
        let mut asks = BTreeSet::new();
        let mut seen_ids = BTreeSet::new();
        for policy in parsed.policies() {
            let label = check_rules(policy, &mut seen_ids)?;
            if policy.annotation(ANNOTATION_EFFECT) == Some(EFFECT_ASK) {
                asks.insert(policy.id().to_string());
            }
            if let Some(reason) = policy.annotation(ANNOTATION_REASON) {
                reasons.insert(label.clone(), reason.to_owned());
            }
            labels.insert(policy.id().to_string(), label);
            all.add(policy.clone()).map_err(|e| PolicyError::Parse(e.to_string()))?;
        }

        let validation = Validator::new(schema.clone()).validate(&all, ValidationMode::Strict);
        if !validation.validation_passed() {
            let errors: Vec<String> = validation.validation_errors().map(ToString::to_string).collect();
            return Err(PolicyError::Invalid(errors.join("; ")));
        }

        check_grants(grants)?;

        let mut index: BTreeMap<GrantKey, Vec<GrantEntry>> = BTreeMap::new();
        for grant in grants.iter().filter(|g| g.expires_at_ms > now_ms) {
            let label = format!("{GRANT_PREFIX}{}", grant.id);
            let key = grant_key(
                grant.action,
                &grant.principal,
                &grant.resource,
                &grant.pocket.to_string(),
            )
            .map_err(|problem| PolicyError::Rule {
                policy: label.clone(),
                problem,
            })?;
            index.entry(key).or_default().push(GrantEntry {
                id: grant.id,
                label,
                expires_at_ms: grant.expires_at_ms,
                max_risk_tier: grant.max_risk_tier.get(),
                data_classes: grant.data_classes.iter().map(ToString::to_string).collect(),
                approves: grant.approves.clone(),
            });
        }
        for entries in index.values_mut() {
            entries.sort_by(|a, b| a.label.cmp(&b.label));
        }

        let actions = schema
            .action_entities()
            .map_err(|e| PolicyError::Schema(e.to_string()))?;
        let mut by_action = BTreeMap::new();
        for action in Action::ALL {
            let action_id = action_uid(action).map_err(PolicyError::Schema)?;
            // An action is covered by `action in [G]` for any group `G` above it.
            let mut covering: BTreeSet<EntityUid> = actions
                .ancestors(&action_id)
                .map(|ancestors| ancestors.cloned().collect())
                .unwrap_or_default();
            covering.insert(action_id.clone());
            let mut slice = Slice::default();
            for policy in all.policies() {
                if !applies(&policy.action_constraint(), &action_id, &covering) {
                    continue;
                }
                let set = match policy.resource_constraint() {
                    ResourceConstraint::Eq(resource) => slice.by_resource.entry(resource.to_string()).or_default(),
                    _ => &mut slice.common,
                };
                set.add(policy.clone()).map_err(|e| PolicyError::Parse(e.to_string()))?;
            }
            by_action.insert(action, slice);
        }

        Ok(Self {
            schema,
            authorizer: Authorizer::new(),
            all,
            by_action,
            labels,
            reasons,
            asks,
            grants: index,
            clock_high_water: AtomicU64::new(now_ms),
        })
    }

    /// Answers one authorization question. Never panics; every failure is a `Deny`.
    #[must_use]
    pub fn authorize(&self, request: &Request) -> Decision {
        let Some(slice) = self.by_action.get(&request.action) else {
            return Decision::deny_error("unknown action");
        };
        let pinned = resource_uid(&request.resource)
            .ok()
            .and_then(|resource| slice.by_resource.get(&resource.to_string()));
        match pinned {
            Some(pinned) => self.authorize_with(request, &[&slice.common, pinned]),
            None => self.authorize_with(request, &[&slice.common]),
        }
    }

    /// Like [`PolicyEngine::authorize`] but against the complete policy set as loaded, never
    /// against the slices. Used to prove that slicing never changes a decision.
    #[doc(hidden)]
    #[must_use]
    pub fn authorize_unsliced(&self, request: &Request) -> Decision {
        self.authorize_with(request, &[&self.all])
    }

    fn label(&self, id: &str) -> String {
        self.labels.get(id).cloned().unwrap_or_else(|| id.to_owned())
    }

    /// The live grants, sorted by label, that cover the request: same principal, action,
    /// resource and pocket, not expired at `now_ms`, a risk tier no higher than approved, and
    /// only data classes the approval saw.
    fn matching_grants(&self, request: &Request, now_ms: u64) -> Result<Vec<&GrantEntry>, String> {
        let key = grant_key(
            request.action,
            &request.principal,
            &request.resource,
            &request.pocket.to_string(),
        )?;
        let tier = request.risk_tier.get();
        // A cross-pocket read is allowed only by the grant it names: naming none, it has none.
        if request.crosses_pockets() && request.grant.is_none() {
            return Ok(Vec::new());
        }
        Ok(self
            .grants
            .get(&key)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|g| {
                        now_ms < g.expires_at_ms
                            && tier <= g.max_risk_tier
                            && request.data_classes.iter().all(|c| g.data_classes.contains(c.as_str()))
                            && request.grant.is_none_or(|carried| g.id == carried)
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    fn decision(&self, effect: Effect, basis: Basis, policies: Vec<String>) -> Decision {
        let reasons = policies
            .iter()
            .filter_map(|label| self.reasons.get(label).map(|reason| format!("{label}: {reason}")))
            .collect();
        Decision {
            effect,
            basis,
            policies,
            reasons,
            errors: Vec::new(),
        }
    }

    /// Evaluates `sets` and merges the answers as one set would give them: any error denies,
    /// any matching forbid denies, otherwise any matching permit allows.
    fn authorize_with(&self, request: &Request, sets: &[&PolicySet]) -> Decision {
        // Validate the whole request first: a malformed one must not move the clock mark.
        let (cedar_request, entities) = match self.build(request) {
            Ok(built) => built,
            Err(e) => return Decision::deny_error(e),
        };
        let latest = self.clock_high_water.fetch_max(request.now_ms, Ordering::Relaxed);
        if request.now_ms.saturating_add(CLOCK_TOLERANCE_MS) < latest {
            return Decision::deny_error(
                "the request clock is behind a clock already seen; refusing a decision that could revive an expired grant",
            );
        }
        // Grants are judged at the latest clock seen, so the tolerance never extends one.
        let grants = match self.matching_grants(request, latest.max(request.now_ms)) {
            Ok(grants) => grants,
            Err(e) => return Decision::deny_error(e),
        };
        let responses: Vec<_> = sets
            .iter()
            .map(|set| self.authorizer.is_authorized(&cedar_request, set, &entities))
            .collect();
        // Cedar reports errors in hash order and by internal id; name them by `@id` and sort,
        // so the same question always gets the same explanation.
        let mut errors: Vec<String> = responses
            .iter()
            .flat_map(|r| r.diagnostics().errors())
            .map(|e| match e {
                AuthorizationError::PolicyEvaluationError(e) => {
                    format!("policy {}: {}", self.label(e.policy_id().as_ref()), e.inner())
                }
                #[allow(unreachable_patterns, reason = "future Cedar error kinds still fail closed")]
                other => other.to_string(),
            })
            .collect();
        errors.sort();
        if !errors.is_empty() {
            return Decision {
                effect: Effect::Deny,
                basis: Basis::EvaluationError,
                policies: Vec::new(),
                reasons: Vec::new(),
                errors,
            };
        }
        let reasons_of = |decision: CedarDecision| -> Vec<String> {
            responses
                .iter()
                .filter(|r| r.decision() == decision)
                .flat_map(|r| r.diagnostics().reason().map(ToString::to_string))
                .collect()
        };
        let forbids = reasons_of(CedarDecision::Deny);
        let (decision, matched) = if forbids.is_empty() {
            let permits = reasons_of(CedarDecision::Allow);
            let decision = if permits.is_empty() {
                CedarDecision::Deny
            } else {
                CedarDecision::Allow
            };
            (decision, permits)
        } else {
            (CedarDecision::Deny, forbids)
        };
        let mut labels: Vec<String> = matched.iter().map(|id| self.label(id)).collect();
        labels.sort();
        match decision {
            CedarDecision::Deny if !matched.is_empty() => self.decision(Effect::Deny, Basis::Forbidden, labels),
            CedarDecision::Deny => match grants.first() {
                Some(grant) => self.decision(Effect::Allow, Basis::Granted, vec![grant.label.clone()]),
                None => self.decision(Effect::Deny, Basis::NoMatchingPermit, Vec::new()),
            },
            CedarDecision::Allow => {
                let mut asking: Vec<String> = matched
                    .iter()
                    .filter(|id| self.asks.contains(*id))
                    .map(|id| self.label(id))
                    .collect();
                asking.sort();
                // A cross-pocket read needs consent: a grant, which carries the injection policy. A
                // permit alone, however broad, at most asks for that consent; the Ask names the
                // permits, and its approval issues the grant. A read of the requesting pocket
                // itself crosses nothing and follows the policies as any action does.
                let cross_pocket = request.crosses_pockets();
                if asking.is_empty() && cross_pocket {
                    return match grants.first() {
                        Some(grant) => self.decision(Effect::Allow, Basis::Granted, vec![grant.label.clone()]),
                        None => self.decision(Effect::Ask, Basis::ApprovalRequired, labels),
                    };
                }
                if asking.is_empty() {
                    return self.decision(Effect::Allow, Basis::Permitted, labels);
                }
                // A grant satisfies the asks only if its approval named every one of them.
                match grants.iter().find(|g| asking.iter().all(|a| g.approves.contains(a))) {
                    Some(grant) => {
                        let mut by = vec![grant.label.clone()];
                        by.extend(asking);
                        self.decision(Effect::Allow, Basis::Granted, by)
                    }
                    None => self.decision(Effect::Ask, Basis::ApprovalRequired, asking),
                }
            }
        }
    }

    #[allow(
        clippy::disallowed_types,
        reason = "Cedar's entity API takes a HashSet of parents; membership, not iteration order, matters"
    )]
    fn build(&self, request: &Request) -> Result<(CedarRequest, Entities), String> {
        use std::collections::HashSet;

        let principal = principal_uid(&request.principal)?;
        let resource = resource_uid(&request.resource)?;
        let action = action_uid(request.action)?;

        let mut entities = vec![Entity::new_no_attrs(principal.clone(), HashSet::new())];
        if let Resource::Model { provider, .. } = &request.resource {
            let provider = uid("Provider", provider.as_str())?;
            entities.push(Entity::new_no_attrs(provider.clone(), HashSet::new()));
            entities.push(Entity::new_no_attrs(resource.clone(), HashSet::from([provider])));
        } else {
            entities.push(Entity::new_no_attrs(resource.clone(), HashSet::new()));
        }
        let entities = Entities::from_entities(entities, Some(&self.schema)).map_err(|e| e.to_string())?;

        let now = i64::try_from(request.now_ms).map_err(|_| "time out of range".to_owned())?;
        let classes = request
            .data_classes
            .iter()
            .map(|c| RestrictedExpression::new_string(c.to_string()));
        let context = Context::from_pairs([
            (
                "pocket".to_owned(),
                RestrictedExpression::new_string(request.pocket.to_string()),
            ),
            (
                "risk_tier".to_owned(),
                RestrictedExpression::new_long(i64::from(request.risk_tier.get())),
            ),
            ("data_classes".to_owned(), RestrictedExpression::new_set(classes)),
            ("now_ms".to_owned(), RestrictedExpression::new_long(now)),
        ])
        .map_err(|e| e.to_string())?;

        let cedar_request =
            CedarRequest::new(principal, action, resource, context, Some(&self.schema)).map_err(|e| e.to_string())?;
        Ok((cedar_request, entities))
    }
}

/// Whether a policy with action constraint `constraint` can apply to `action`. `covering` is the
/// action itself and every action group above it in the schema (without the groups, `action in [G]`
/// would be sliced away from G's members and a forbid would stop applying).
pub(crate) fn applies(constraint: &ActionConstraint, action: &EntityUid, covering: &BTreeSet<EntityUid>) -> bool {
    match constraint {
        ActionConstraint::Any => true,
        ActionConstraint::Eq(a) => a == action,
        ActionConstraint::In(list) => list.iter().any(|a| covering.contains(a)),
    }
}

/// Enforces the UAOS loading rules on one policy; returns its `@id`.
fn check_rules(policy: &Policy, seen: &mut BTreeSet<String>) -> Result<String, PolicyError> {
    let position = policy.id().to_string();
    let Some(id) = policy.annotation(ANNOTATION_ID) else {
        return Err(PolicyError::Rule {
            policy: position,
            problem: "missing @id(\"…\") annotation".to_owned(),
        });
    };
    // A plain id cannot pose as an explanation (`allowed by x, grant:…`).
    let plain = !id.is_empty()
        && id.len() <= MAX_ID
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'));
    if !plain {
        return Err(PolicyError::Rule {
            policy: position,
            problem: format!("@id must be 1..={MAX_ID} characters of [A-Za-z0-9._:-]"),
        });
    }
    let rule = |problem: &str| PolicyError::Rule {
        policy: id.to_owned(),
        problem: problem.to_owned(),
    };
    if id.starts_with(GRANT_PREFIX) {
        return Err(rule("@id must not use the reserved `grant:` prefix"));
    }
    if !seen.insert(id.to_owned()) {
        return Err(rule("duplicate @id"));
    }
    for (key, value) in policy.annotations() {
        match key {
            ANNOTATION_ID | ANNOTATION_REASON => {}
            ANNOTATION_EFFECT if value == EFFECT_ASK && policy.effect() == CedarEffect::Permit => {}
            ANNOTATION_EFFECT if value == EFFECT_ASK => {
                return Err(rule("@effect(\"ask\") is only meaningful on permit"));
            }
            ANNOTATION_EFFECT => return Err(rule("@effect only accepts \"ask\"")),
            _ => {
                return Err(rule(&format!(
                    "unknown annotation @{key} (allowed: @id, @effect, @reason)"
                )));
            }
        }
    }
    Ok(id.to_owned())
}

/// Per-statement counters for [`check_bounds`].
#[derive(Default)]
struct Statement {
    start: usize,
    depth: usize,
    ifs: usize,
    operators: usize,
}

/// Bounds policy text before Cedar parses it, so that no input can overflow the parser's or the
/// evaluator's stack (about 80 nested parentheses aborted the process). Strings and comments are
/// skipped; brackets, `if`s and operators are counted per statement.
fn check_bounds(text: &str) -> Result<(), PolicyError> {
    let too = |statement: usize, problem: String| PolicyError::Rule {
        policy: format!("statement {}", statement + 1),
        problem,
    };
    if text.len() > MAX_TEXT_BYTES {
        return Err(too(0, format!("policy text exceeds {MAX_TEXT_BYTES} bytes")));
    }
    let bytes = text.as_bytes();
    let mut index = 0;
    let mut current = Statement::default();
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'"' => {
                // Skip the string, honouring backslash escapes.
                i += 1;
                while let Some(&c) = bytes.get(i) {
                    i += if c == b'\\' { 2 } else { 1 };
                    if c == b'"' {
                        break;
                    }
                }
                continue;
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                i = comment_end(bytes, i);
                continue;
            }
            b'(' | b'[' | b'{' => {
                current.depth += 1;
                if current.depth > MAX_NESTING {
                    return Err(too(index, format!("brackets nest deeper than {MAX_NESTING}")));
                }
                // An opening bracket is also an operator: `x["a"]["b"]…`, calls and literals deepen
                // the expression even when their depth goes back down.
                current.operators += 1;
                if current.operators > MAX_OPERATORS {
                    return Err(too(index, format!("a policy has more than {MAX_OPERATORS} operators")));
                }
            }
            b')' | b']' | b'}' => current.depth = current.depth.saturating_sub(1),
            b';' if current.depth == 0 => {
                if i - current.start > MAX_STATEMENT_BYTES {
                    return Err(too(index, format!("a policy exceeds {MAX_STATEMENT_BYTES} bytes")));
                }
                index += 1;
                current = Statement {
                    start: i + 1,
                    ..Statement::default()
                };
            }
            b'&' | b'|' | b'=' | b'!' | b'<' | b'>' | b'+' | b'-' | b'*' | b'.' => {
                // `&&`, `==`, `<=` … count once: only the first byte of a run counts.
                let previous = i.checked_sub(1).and_then(|p| bytes.get(p)).copied();
                if !previous.is_some_and(|p| matches!(p, b'&' | b'|' | b'=' | b'!' | b'<' | b'>')) || b == b'!' {
                    current.operators += 1;
                }
                if current.operators > MAX_OPERATORS {
                    return Err(too(index, format!("a policy has more than {MAX_OPERATORS} operators")));
                }
            }
            b'i' if is_keyword(bytes, i, b"if") => {
                current.ifs += 1;
                if current.ifs > MAX_IFS {
                    return Err(too(index, format!("a policy has more than {MAX_IFS} `if`s")));
                }
            }
            b'i' | b'h' | b'l'
                if [b"in".as_slice(), b"is", b"has", b"like"]
                    .iter()
                    .any(|w| is_keyword(bytes, i, w)) =>
            {
                current.operators += 1;
                if current.operators > MAX_OPERATORS {
                    return Err(too(index, format!("a policy has more than {MAX_OPERATORS} operators")));
                }
            }
            _ => {}
        }
        i += 1;
    }
    if bytes.len() - current.start.min(bytes.len()) > MAX_STATEMENT_BYTES {
        return Err(too(index, format!("a policy exceeds {MAX_STATEMENT_BYTES} bytes")));
    }
    Ok(())
}

/// End of a `//` comment starting at `from`: the next `\n` or `\r`, as in Cedar's lexer
/// (`//[^\n\r]*`), or the end of the text.
fn comment_end(bytes: &[u8], from: usize) -> usize {
    bytes
        .get(from..)
        .and_then(|rest| rest.iter().position(|&b| b == b'\n' || b == b'\r'))
        .map_or(bytes.len(), |at| from + at)
}

/// Whether `word` stands alone at `at` (not part of a longer identifier).
fn is_keyword(bytes: &[u8], at: usize, word: &[u8]) -> bool {
    let ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    bytes.get(at..at + word.len()) == Some(word)
        && !at.checked_sub(1).and_then(|p| bytes.get(p)).is_some_and(|&b| ident(b))
        && !bytes.get(at + word.len()).is_some_and(|&b| ident(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group_uid(id: &str) -> EntityUid {
        uid("Action", id).unwrap()
    }

    /// A policy constrained to an action group applies to the group's members.
    #[test]
    fn slicing_follows_action_groups() {
        let exec = group_uid("exec");
        let dangerous = group_uid("dangerous");
        let covering = BTreeSet::from([exec.clone(), dangerous.clone()]);
        assert!(applies(&ActionConstraint::In(vec![dangerous]), &exec, &covering));
        assert!(applies(&ActionConstraint::In(vec![exec.clone()]), &exec, &covering));
        assert!(!applies(
            &ActionConstraint::In(vec![group_uid("other")]),
            &exec,
            &covering
        ));
        assert!(applies(&ActionConstraint::Any, &exec, &covering));
        assert!(!applies(
            &ActionConstraint::Eq(group_uid("tool.call")),
            &exec,
            &covering
        ));
    }

    #[test]
    fn bounds_skip_strings_and_comments() {
        let deep_string = format!("@id(\"{}\") permit(principal, action, resource);", "(".repeat(100));
        assert!(check_bounds(&deep_string).is_ok());
        let deep_comment = format!(
            "// {}\n@id(\"a\") permit(principal, action, resource);",
            "(".repeat(100)
        );
        assert!(check_bounds(&deep_comment).is_ok());
        let escaped_quote = "@id(\"a\\\"((((((((((\") permit(principal, action, resource);";
        assert!(check_bounds(escaped_quote).is_ok());
    }
}
