// SPDX-License-Identifier: Apache-2.0

//! A reference to a grant, carried into a child Operation.

use uaos_contracts::id::GrantId;

/// Names a grant (`uaos.grant/1`) a module carries into a child Operation.
///
/// **Authority is never in the reference.** The host hands a module the references of the live
/// grants its manifest declared for the Operation's pocket, and re-checks the named grant at
/// every use: issued to this module, for this pocket, for the requested action and resource, not
/// expired, not revoked. A module that names a grant it was not given gains nothing it was not
/// already granted; the request fails closed and is explained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GrantRef(GrantId);

impl GrantRef {
    /// A reference to `grant`. The host builds these; see the type's documentation for why a
    /// module building one gains nothing.
    #[must_use]
    pub const fn new(grant: GrantId) -> Self {
        Self(grant)
    }

    /// The grant it names.
    #[must_use]
    pub const fn grant(self) -> GrantId {
        self.0
    }
}
