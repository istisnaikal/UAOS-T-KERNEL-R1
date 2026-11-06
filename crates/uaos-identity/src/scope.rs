// SPDX-License-Identifier: Apache-2.0

//! Scope containment and coverage.
//!
//! Both questions are decidable because patterns are only exact or prefix:
//!
//! * **containment** (`child ⊆ parent`): every dimension of the child is within the parent's,
//!   and the child expires no later than the parent;
//! * **coverage**: a scope admits a concrete request (action, resource, pocket, pool).

use uaos_contracts::credential::{PatternMatch, ResourceKind, ResourcePattern, Scope, ScopeSet};
use uaos_contracts::id::{PocketId, PoolId};
use uaos_contracts::time::WallTime;

/// A concrete request to check against a scope. Leaving out a dimension the scope restricts
/// denies the request (see [`scope_covers`]).
#[derive(Debug, Clone, Copy)]
pub struct ScopeRequest<'a> {
    /// The action, e.g. `model.call`.
    pub action: &'a str,
    /// The resource acted on, if any.
    pub resource: Option<(ResourceKind, &'a str)>,
    /// The pocket the Operation runs in, if any.
    pub pocket: Option<PocketId>,
    /// The pool it reserves from, if it spends money.
    pub pool: Option<PoolId>,
}

/// `true` if `child` is within `parent` in every dimension.
#[must_use]
pub fn scope_within(child: &Scope, parent: &Scope) -> bool {
    set_within(&child.actions, &parent.actions)
        && resources_within(&child.resources, &parent.resources)
        && set_within(&child.pockets, &parent.pockets)
        && set_within(&child.pools, &parent.pools)
        && expiry_within(child.expires_at, parent.expires_at)
}

/// `true` if `scope` admits `request`.
#[must_use]
pub fn scope_covers(scope: &Scope, request: &ScopeRequest<'_>) -> bool {
    let action = match &scope.actions {
        ScopeSet::Any => true,
        ScopeSet::Only(actions) => actions.iter().any(|a| a.as_str() == request.action),
    };
    // A restricted dimension that the request leaves out fails closed: "no resource" must not
    // slip past a resource restriction. The pool is the exception by meaning: a request without
    // a pool spends no money, so a pool restriction does not apply to it.
    let resource = match (&scope.resources, request.resource) {
        (ScopeSet::Any, _) => true,
        (ScopeSet::Only(_), None) => false,
        (ScopeSet::Only(patterns), Some((kind, name))) => patterns.iter().any(|p| pattern_matches(p, kind, name)),
    };
    let pocket = match (&scope.pockets, request.pocket) {
        (ScopeSet::Any, _) => true,
        (ScopeSet::Only(_), None) => false,
        (ScopeSet::Only(pockets), Some(p)) => pockets.contains(&p),
    };
    let pool = request.pool.is_none_or(|p| member(&scope.pools, &p));
    action && resource && pocket && pool
}

/// `true` if `parent` matches every name that `child` matches.
#[must_use]
pub fn pattern_covers(parent: &ResourcePattern, child: &ResourcePattern) -> bool {
    if parent.kind != child.kind {
        return false;
    }
    let (p, c) = (parent.value.as_str(), child.value.as_str());
    match (parent.matching, child.matching) {
        (PatternMatch::Exact, PatternMatch::Exact) => p == c,
        // An exact parent matches one name; a prefix child matches infinitely many.
        (PatternMatch::Exact, PatternMatch::Prefix) => false,
        (PatternMatch::Prefix, _) => c.starts_with(p),
    }
}

/// `true` if `pattern` matches the resource `name` of `kind`.
#[must_use]
pub fn pattern_matches(pattern: &ResourcePattern, kind: ResourceKind, name: &str) -> bool {
    pattern.kind == kind
        && match pattern.matching {
            PatternMatch::Exact => name == pattern.value.as_str(),
            PatternMatch::Prefix => name.starts_with(pattern.value.as_str()),
        }
}

fn member<T: Ord>(set: &ScopeSet<T>, item: &T) -> bool {
    match set {
        ScopeSet::Any => true,
        ScopeSet::Only(members) => members.contains(item),
    }
}

fn set_within<T: Ord>(child: &ScopeSet<T>, parent: &ScopeSet<T>) -> bool {
    match (child, parent) {
        (_, ScopeSet::Any) => true,
        (ScopeSet::Any, ScopeSet::Only(_)) => false,
        (ScopeSet::Only(c), ScopeSet::Only(p)) => c.is_subset(p),
    }
}

fn resources_within(child: &ScopeSet<ResourcePattern>, parent: &ScopeSet<ResourcePattern>) -> bool {
    match (child, parent) {
        (_, ScopeSet::Any) => true,
        (ScopeSet::Any, ScopeSet::Only(_)) => false,
        (ScopeSet::Only(c), ScopeSet::Only(p)) => c.iter().all(|cp| p.iter().any(|pp| pattern_covers(pp, cp))),
    }
}

fn expiry_within(child: Option<WallTime>, parent: Option<WallTime>) -> bool {
    match (child, parent) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(c), Some(p)) => c <= p,
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use uaos_contracts::credential::PatternValue;

    use super::*;

    const UNIVERSE_LEN: usize = 4;

    fn pattern(matching: PatternMatch, value: &str) -> ResourcePattern {
        ResourcePattern {
            kind: ResourceKind::Model,
            matching,
            value: PatternValue::new(value).unwrap(),
        }
    }

    /// Every name over {a, b} of length `1..=UNIVERSE_LEN`.
    fn universe() -> Vec<String> {
        let mut out = Vec::new();
        let mut frontier = vec![String::new()];
        for _ in 0..UNIVERSE_LEN {
            let mut next = Vec::new();
            for s in &frontier {
                for c in ['a', 'b'] {
                    let mut t = s.clone();
                    t.push(c);
                    out.push(t.clone());
                    next.push(t);
                }
            }
            frontier = next;
        }
        out
    }

    fn arb_pattern() -> impl Strategy<Value = ResourcePattern> {
        (
            prop_oneof![Just(PatternMatch::Exact), Just(PatternMatch::Prefix)],
            "[ab]{1,3}",
        )
            .prop_map(|(m, v)| pattern(m, &v))
    }

    proptest! {
        /// Containment agrees with brute force over a universe longer than any pattern, so
        /// "every name the child matches, the parent matches" is decided exactly.
        #[test]
        fn pattern_containment_matches_brute_force(parent in arb_pattern(), child in arb_pattern()) {
            let brute = universe().iter().all(|name| {
                !pattern_matches(&child, ResourceKind::Model, name)
                    || pattern_matches(&parent, ResourceKind::Model, name)
            });
            prop_assert_eq!(pattern_covers(&parent, &child), brute);
        }
    }

    #[test]
    fn kinds_never_cover_each_other() {
        let mut tool = pattern(PatternMatch::Prefix, "a");
        tool.kind = ResourceKind::Tool;
        assert!(!pattern_covers(&tool, &pattern(PatternMatch::Exact, "a")));
    }

    #[test]
    fn any_contains_only_but_not_the_reverse() {
        let only: ScopeSet<u8> = ScopeSet::Only([1].into());
        assert!(set_within(&only, &ScopeSet::Any));
        assert!(!set_within(&ScopeSet::Any, &only));
        assert!(set_within(&ScopeSet::Only([1].into()), &ScopeSet::Only([1, 2].into())));
        assert!(!set_within(&ScopeSet::Only([3].into()), &ScopeSet::Only([1, 2].into())));
    }

    #[test]
    fn expiry_rules() {
        let t = |s| Some(WallTime::from_unix_nanos(s).unwrap());
        assert!(expiry_within(t(1), None));
        assert!(!expiry_within(None, t(1)));
        assert!(expiry_within(t(1), t(2)));
        assert!(!expiry_within(t(3), t(2)));
    }
}
