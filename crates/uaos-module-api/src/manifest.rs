// SPDX-License-Identifier: Apache-2.0

//! The manifest (`uaos.module/1`), the hook points and the kernel's admission of a module: whole or
//! not at all.

use std::collections::BTreeSet;
use std::fmt;

use uaos_contracts::event::ModuleName;
use uaos_json::{Kind, Limits};

use crate::code::Code;
use crate::decl::MAX_EVENT_VALUES;

/// The largest per-pocket state a module may keep.
pub const MAX_STATE_BYTES: u32 = 64 * 1024;
/// The most declarations one hook call may return.
pub const MAX_DECLS: u16 = 64;
/// The most entries of one kind a manifest may declare: reasons, labels, events, targets or
/// grants.
pub const MAX_CODES: usize = 64;
/// The largest configuration schema, in bytes.
pub const MAX_CONFIG_SCHEMA_BYTES: usize = 16 * 1024;

/// The module API a module was built against, or a kernel offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ModuleApiVersion {
    major: u16,
    minor: u16,
}

impl ModuleApiVersion {
    /// The version this crate defines.
    pub const CURRENT: Self = Self { major: 1, minor: 0 };

    /// A version.
    #[must_use]
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// Its major number: a different one is incompatible.
    #[must_use]
    pub const fn major(self) -> u16 {
        self.major
    }

    /// Its minor number: additive growth.
    #[must_use]
    pub const fn minor(self) -> u16 {
        self.minor
    }
}

/// A module's own version. `#[non_exhaustive]`: built with [`ModuleVersion::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub struct ModuleVersion {
    /// Major.
    pub major: u32,
    /// Minor.
    pub minor: u32,
    /// Patch.
    pub patch: u32,
}

impl ModuleVersion {
    /// A version.
    #[must_use]
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch }
    }
}

impl fmt::Display for ModuleVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// What a running kernel offers a module beyond the base hook points. A module lists every feature
/// it uses; the kernel admits it only if it offers all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum KernelFeature {
    /// The `stream.observe` point.
    StreamObserve,
    /// The `stream.assert` point.
    StreamAssert,
    /// Child Operations ([`crate::Decl::Request`]).
    ChildOperations,
    /// Child Operations that read another pocket under a grant.
    CrossPocketRead,
    /// [`crate::Decl::Checkpoint`].
    StateCheckpoints,
    /// Child Operations that request a configuration change.
    ConfigChangeRequests,
}

impl KernelFeature {
    /// Every feature at `uaos.module/1`.
    pub const ALL: [Self; 6] = [
        Self::StreamObserve,
        Self::StreamAssert,
        Self::ChildOperations,
        Self::CrossPocketRead,
        Self::StateCheckpoints,
        Self::ConfigChangeRequests,
    ];

    /// Its stable name, for explanations.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::StreamObserve => "stream_observe",
            Self::StreamAssert => "stream_assert",
            Self::ChildOperations => "child_operations",
            Self::CrossPocketRead => "cross_pocket_read",
            Self::StateCheckpoints => "state_checkpoints",
            Self::ConfigChangeRequests => "config_change_requests",
        }
    }
}

/// Where a module may be called.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum HookPoint {
    /// After the request is parsed.
    IngressParsed,
    /// Classification: labels that only raise risk.
    Classify,
    /// Context assembly: append-only.
    ContextAssemble,
    /// The newest turn's tool result.
    ToolResult,
    /// Route choice among permitted, account-pinned candidates.
    RouteDecide,
    /// Each forwarded stream frame, after forwarding.
    StreamObserve,
    /// Each stream frame, with the power to cancel from the next one.
    StreamAssert,
    /// After settlement.
    ResponsePost,
    /// An upstream error, for an additive annotation.
    ErrorTranslate,
}

/// What a point shows a module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ViewKind {
    /// The redacted structural view of the request.
    Redacted,
    /// Identifiers and metadata only.
    Metadata,
    /// One stream frame.
    Frame,
    /// An error and its metadata.
    Error,
}

impl HookPoint {
    /// Every point at `uaos.module/1`.
    pub const ALL: [Self; 9] = [
        Self::IngressParsed,
        Self::Classify,
        Self::ContextAssemble,
        Self::ToolResult,
        Self::RouteDecide,
        Self::StreamObserve,
        Self::StreamAssert,
        Self::ResponsePost,
        Self::ErrorTranslate,
    ];

    /// Its stable name.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::IngressParsed => "ingress.parsed",
            Self::Classify => "classify",
            Self::ContextAssemble => "context.assemble",
            Self::ToolResult => "tool.result",
            Self::RouteDecide => "route.decide",
            Self::StreamObserve => "stream.observe",
            Self::StreamAssert => "stream.assert",
            Self::ResponsePost => "response.post",
            Self::ErrorTranslate => "error.translate",
        }
    }

    /// The deadline ceiling in microseconds; a manifest may ask for less, never more.
    #[must_use]
    pub const fn ceiling_us(self) -> u32 {
        match self {
            Self::IngressParsed | Self::ToolResult => 300,
            Self::Classify | Self::ErrorTranslate => 200,
            Self::ContextAssemble => 400,
            Self::RouteDecide | Self::StreamAssert => 100,
            Self::StreamObserve => 50,
            Self::ResponsePost => 5_000,
        }
    }

    /// What the point shows.
    #[must_use]
    pub const fn view(self) -> ViewKind {
        match self {
            Self::IngressParsed | Self::Classify | Self::ContextAssemble | Self::ToolResult => ViewKind::Redacted,
            Self::RouteDecide | Self::ResponsePost => ViewKind::Metadata,
            Self::StreamObserve | Self::StreamAssert => ViewKind::Frame,
            Self::ErrorTranslate => ViewKind::Error,
        }
    }

    /// Whether a hook here may act ([`HookMode::Act`]). `stream.observe` and `response.post` only
    /// observe; `error.translate`'s additive annotation has no declaration yet, so it observes
    /// too until one is added.
    #[must_use]
    pub const fn acts(self) -> bool {
        !matches!(self, Self::StreamObserve | Self::ResponsePost | Self::ErrorTranslate)
    }

    /// Whether a failure here can still deny the Operation: every point before forwarding, and
    /// `stream.assert`, which cancels. A manifest's `OnFailure::Deny` only makes such a point
    /// stricter; the point's own policy is the floor.
    #[must_use]
    pub const fn denies(self) -> bool {
        !matches!(self, Self::StreamObserve | Self::ResponsePost | Self::ErrorTranslate)
    }

    /// The feature a module must require to hook this point, if any.
    #[must_use]
    pub const fn required_feature(self) -> Option<KernelFeature> {
        match self {
            Self::StreamObserve => Some(KernelFeature::StreamObserve),
            Self::StreamAssert => Some(KernelFeature::StreamAssert),
            _ => None,
        }
    }
}

/// Whether a hook only observes or acts in its point's way (strip, append, veto, label, rank,
/// cancel or annotate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HookMode {
    /// Observes; any declaration but `Emit`, `Request`, `CancelOp` and `Checkpoint` is a strike.
    Observe,
    /// Acts as the point allows.
    Act,
}

/// What a hook's failure (a strike, a timeout, a panic) does to the Operation. At risk tier 2 or
/// more, a failed veto denies whatever the manifest says (the kernel rule).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum OnFailure {
    /// The kernel goes on as if the module had declared nothing, and explains it.
    Skip,
    /// The Operation is denied, and explained.
    Deny,
}

/// One hooked point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookDecl {
    point: HookPoint,
    mode: HookMode,
    priority: u16,
    deadline_us: u32,
    on_failure: OnFailure,
}

impl HookDecl {
    /// A hook at `point`, at the point's deadline ceiling, priority 0, skipped on failure.
    #[must_use]
    pub const fn new(point: HookPoint, mode: HookMode) -> Self {
        Self {
            point,
            mode,
            priority: 0,
            deadline_us: point.ceiling_us(),
            on_failure: OnFailure::Skip,
        }
    }

    /// Runs before lower priorities at the same point; ties go by module name.
    #[must_use]
    pub const fn priority(mut self, priority: u16) -> Self {
        self.priority = priority;
        self
    }

    /// Asks for a deadline below the point's ceiling.
    #[must_use]
    pub const fn deadline_us(mut self, deadline_us: u32) -> Self {
        self.deadline_us = deadline_us;
        self
    }

    /// What a failure does.
    #[must_use]
    pub const fn on_failure(mut self, on_failure: OnFailure) -> Self {
        self.on_failure = on_failure;
        self
    }

    /// The point.
    #[must_use]
    pub const fn point(&self) -> HookPoint {
        self.point
    }

    /// The mode.
    #[must_use]
    pub const fn mode(&self) -> HookMode {
        self.mode
    }

    /// The priority.
    #[must_use]
    pub const fn priority_value(&self) -> u16 {
        self.priority
    }

    /// The deadline, in microseconds.
    #[must_use]
    pub const fn deadline(&self) -> u32 {
        self.deadline_us
    }

    /// The failure policy.
    #[must_use]
    pub const fn failure(&self) -> OnFailure {
        self.on_failure
    }
}

/// A kind of child Operation a module may request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ChildKind {
    /// A model call (for example a local model that rewrites a prompt).
    ModelCall,
    /// A token count.
    CountTokens,
    /// A tool call (denied: tools run only through a sandbox).
    ToolCall,
    /// A configuration change, which policy answers with an approval.
    ConfigChange,
    /// A read of another pocket's memory under a grant.
    MemoryRead,
}

impl ChildKind {
    /// The Cedar action that authorizes it.
    #[must_use]
    pub const fn cedar_action(self) -> &'static str {
        match self {
            Self::ModelCall => "model.call",
            Self::CountTokens => "model.count_tokens",
            Self::ToolCall => "tool.call",
            Self::ConfigChange => "config.change",
            Self::MemoryRead => "memory.read",
        }
    }

    /// The features a module must require to request it.
    #[must_use]
    pub fn required_features(self) -> BTreeSet<KernelFeature> {
        let mut features = BTreeSet::from([KernelFeature::ChildOperations]);
        match self {
            Self::MemoryRead => {
                features.insert(KernelFeature::CrossPocketRead);
            }
            Self::ConfigChange => {
                features.insert(KernelFeature::ConfigChangeRequests);
            }
            Self::ModelCall | Self::CountTokens | Self::ToolCall => {}
        }
        features
    }
}

/// A grant a module may hold, and why. `#[non_exhaustive]`: built with [`GrantDecl::new`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub struct GrantDecl {
    /// The kind of child Operation it covers.
    pub kind: ChildKind,
    /// A declared reason, shown to the human who approves it.
    pub why: Code,
}

impl GrantDecl {
    /// A grant for child Operations of `kind`, held for the reason `why`.
    #[must_use]
    pub const fn new(kind: ChildKind, why: Code) -> Self {
        Self { kind, why }
    }
}

/// Whether a module event is journaled (truth, resumable) or ephemeral (lossy, counted).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EventClass {
    /// Lossy, never resumed.
    Ephemeral,
    /// Journaled, rate-limited per module per Operation, resumable.
    Journaled,
}

/// An event code a module may emit, and the names of the values it may carry (at most
/// [`MAX_EVENT_VALUES`]): a value under any other name is a strike, so an event can never carry
/// words taken from content. `#[non_exhaustive]`: built with [`EventDecl::new`] and
/// [`EventDecl::field`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EventDecl {
    /// The code.
    pub code: Code,
    /// Its class.
    pub class: EventClass,
    /// The value names it may carry.
    pub fields: BTreeSet<Code>,
}

impl EventDecl {
    /// An event code of `class`, carrying no values yet.
    #[must_use]
    pub const fn new(code: Code, class: EventClass) -> Self {
        Self {
            code,
            class,
            fields: BTreeSet::new(),
        }
    }

    /// Declares a value name it may carry.
    #[must_use]
    pub fn field(mut self, name: Code) -> Self {
        self.fields.insert(name);
        self
    }
}

/// A module's configuration schema: a JSON object of at most [`MAX_CONFIG_SCHEMA_BYTES`].
#[derive(Clone, PartialEq, Eq)]
pub struct ConfigSchema(String);

impl ConfigSchema {
    /// Checks that `text` is one JSON object within the bound, under the kernel's own grammar.
    ///
    /// # Errors
    /// [`ManifestError::ConfigSchema`] if it is too large, not JSON, or not an object.
    pub fn new(text: impl Into<String>) -> Result<Self, ManifestError> {
        let text = text.into();
        if text.len() > MAX_CONFIG_SCHEMA_BYTES {
            return Err(ManifestError::ConfigSchema);
        }
        let tape = uaos_json::parse(text.as_bytes(), &Limits::DEFAULT).map_err(|_| ManifestError::ConfigSchema)?;
        if tape.root().kind() != Kind::Object {
            return Err(ManifestError::ConfigSchema);
        }
        drop(tape);
        Ok(Self(text))
    }

    /// The schema's text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ConfigSchema {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigSchema").field("len", &self.0.len()).finish()
    }
}

/// A manifest that cannot be honoured whole. The module is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ManifestError {
    /// The same point hooked twice.
    #[error("the point `{}` is hooked twice", .0.code())]
    DuplicateHook(HookPoint),
    /// A deadline of zero, or above the point's ceiling.
    #[error("a deadline at `{}` must be between 1 and {ceiling_us} µs", .point.code())]
    Deadline {
        /// The point.
        point: HookPoint,
        /// Its ceiling.
        ceiling_us: u32,
    },
    /// A hook, an action or a declaration needs a feature the manifest does not require.
    #[error("the manifest uses `{}` without requiring it", .0.code())]
    FeatureNotRequired(KernelFeature),
    /// More state than [`MAX_STATE_BYTES`].
    #[error("state is bounded at {max} bytes per pocket")]
    StateTooLarge {
        /// The bound.
        max: u32,
    },
    /// A declaration bound of zero, or above [`MAX_DECLS`].
    #[error("declarations per call must be between 1 and {max}")]
    Decls {
        /// The bound.
        max: u16,
    },
    /// More codes of one kind than [`MAX_CODES`].
    #[error("at most {max} codes of one kind")]
    TooManyCodes {
        /// The bound.
        max: usize,
    },
    /// The same event code declared twice.
    #[error("the event code `{0}` is declared twice")]
    DuplicateEvent(Code),
    /// A grant for a kind of child Operation the manifest does not request.
    #[error("a grant for a child Operation the manifest does not declare")]
    GrantWithoutAction,
    /// A grant whose reason is not one of the manifest's reason codes.
    #[error("the grant reason `{0}` is not a declared reason")]
    UndeclaredCode(Code),
    /// An acting hook at a point that only observes.
    #[error("the point `{}` only observes", .0.code())]
    ModeUnavailable(HookPoint),
    /// `OnFailure::Deny` at a point that runs after the request was forwarded or settled, where
    /// nothing is left to deny.
    #[error("the point `{}` runs after forwarding: a failure there cannot deny", .0.code())]
    FailureUnavailable(HookPoint),
    /// Enabled by default although it reaches outside the request.
    #[error("a module that requests child Operations is off by default")]
    DefaultOnReachesOutside,
    /// A configuration schema that is too large, not JSON or not an object.
    #[error("the configuration schema must be one JSON object of at most 16 KiB")]
    ConfigSchema,
}

impl ManifestError {
    /// A stable label for the kernel's `module.refused` explanation.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::DuplicateHook(_) => "duplicate_hook",
            Self::FeatureNotRequired(_) => "feature_not_required",
            Self::Deadline { .. } | Self::StateTooLarge { .. } | Self::Decls { .. } | Self::TooManyCodes { .. } => {
                "bound_exceeded"
            }
            Self::DuplicateEvent(_) => "duplicate_event",
            Self::GrantWithoutAction => "grant_without_action",
            Self::UndeclaredCode(_) => "undeclared_code",
            Self::ModeUnavailable(_) | Self::FailureUnavailable(_) => "point_unavailable",
            Self::DefaultOnReachesOutside => "default_on_reaches_outside",
            Self::ConfigSchema => "config_schema",
        }
    }
}

/// A module's manifest: built through [`Manifest::builder`] and validated whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    name: ModuleName,
    version: ModuleVersion,
    api: ModuleApiVersion,
    requires: BTreeSet<KernelFeature>,
    hooks: Vec<HookDecl>,
    actions: BTreeSet<ChildKind>,
    grants: Vec<GrantDecl>,
    reasons: BTreeSet<Code>,
    labels: BTreeSet<Code>,
    events: Vec<EventDecl>,
    targets: BTreeSet<Code>,
    config_schema: Option<ConfigSchema>,
    state_bytes: u32,
    max_decls: u16,
    default_enabled: bool,
}

impl Manifest {
    /// Starts a manifest for `name` at `version`, built against [`ModuleApiVersion::CURRENT`]:
    /// no hooks, no features, no state, off by default.
    #[must_use]
    pub fn builder(name: ModuleName, version: ModuleVersion) -> ManifestBuilder {
        ManifestBuilder(Self {
            name,
            version,
            api: ModuleApiVersion::CURRENT,
            requires: BTreeSet::new(),
            hooks: Vec::new(),
            actions: BTreeSet::new(),
            grants: Vec::new(),
            reasons: BTreeSet::new(),
            labels: BTreeSet::new(),
            events: Vec::new(),
            targets: BTreeSet::new(),
            config_schema: None,
            state_bytes: 0,
            max_decls: 8,
            default_enabled: false,
        })
    }

    /// The module's name.
    #[must_use]
    pub const fn name(&self) -> &ModuleName {
        &self.name
    }

    /// Its version.
    #[must_use]
    pub const fn version(&self) -> ModuleVersion {
        self.version
    }

    /// The module API it was built against.
    #[must_use]
    pub const fn api(&self) -> ModuleApiVersion {
        self.api
    }

    /// The features it requires.
    #[must_use]
    pub const fn requires(&self) -> &BTreeSet<KernelFeature> {
        &self.requires
    }

    /// Its hooks.
    #[must_use]
    pub fn hooks(&self) -> &[HookDecl] {
        &self.hooks
    }

    /// Its hook at `point`, if any.
    #[must_use]
    pub fn hook(&self, point: HookPoint) -> Option<&HookDecl> {
        self.hooks.iter().find(|h| h.point == point)
    }

    /// The child Operations it may request.
    #[must_use]
    pub const fn actions(&self) -> &BTreeSet<ChildKind> {
        &self.actions
    }

    /// The grants it may hold.
    #[must_use]
    pub fn grants(&self) -> &[GrantDecl] {
        &self.grants
    }

    /// Whether `code` is one of its declared reasons.
    #[must_use]
    pub fn declares_reason(&self, code: &Code) -> bool {
        self.reasons.contains(code)
    }

    /// Whether `code` is one of its declared labels.
    #[must_use]
    pub fn declares_label(&self, code: &Code) -> bool {
        self.labels.contains(code)
    }

    /// The class of the event `code`, if declared.
    #[must_use]
    pub fn event_class(&self, code: &Code) -> Option<EventClass> {
        self.event(code).map(|e| e.class)
    }

    /// The declaration of the event `code`, if any.
    #[must_use]
    pub fn event(&self, code: &Code) -> Option<&EventDecl> {
        self.events.iter().find(|e| &e.code == code)
    }

    /// Whether `code` names a tool or a configuration key its child Operations may name.
    #[must_use]
    pub fn declares_target(&self, code: &Code) -> bool {
        self.targets.contains(code)
    }

    /// Its configuration schema, if any.
    #[must_use]
    pub const fn config_schema(&self) -> Option<&ConfigSchema> {
        self.config_schema.as_ref()
    }

    /// Its per-pocket state bound, in bytes.
    #[must_use]
    pub const fn state_bytes(&self) -> u32 {
        self.state_bytes
    }

    /// The most declarations one call may return.
    #[must_use]
    pub const fn max_decls(&self) -> u16 {
        self.max_decls
    }

    /// Whether it is enabled without configuration saying so.
    #[must_use]
    pub const fn default_enabled(&self) -> bool {
        self.default_enabled
    }
}

/// Builds a [`Manifest`]; [`ManifestBuilder::build`] validates it whole.
#[derive(Debug, Clone)]
pub struct ManifestBuilder(Manifest);

impl ManifestBuilder {
    /// Requires a kernel feature.
    #[must_use]
    pub fn requires(mut self, feature: KernelFeature) -> Self {
        self.0.requires.insert(feature);
        self
    }

    /// Hooks a point.
    #[must_use]
    pub fn hook(mut self, hook: HookDecl) -> Self {
        self.0.hooks.push(hook);
        self
    }

    /// Declares a kind of child Operation it may request.
    #[must_use]
    pub fn action(mut self, kind: ChildKind) -> Self {
        self.0.actions.insert(kind);
        self
    }

    /// Declares a grant it may hold.
    #[must_use]
    pub fn grant(mut self, grant: GrantDecl) -> Self {
        self.0.grants.push(grant);
        self
    }

    /// Declares a reason code.
    #[must_use]
    pub fn reason(mut self, code: Code) -> Self {
        self.0.reasons.insert(code);
        self
    }

    /// Declares a label code.
    #[must_use]
    pub fn label(mut self, code: Code) -> Self {
        self.0.labels.insert(code);
        self
    }

    /// Declares an event code.
    #[must_use]
    pub fn event(mut self, event: EventDecl) -> Self {
        self.0.events.push(event);
        self
    }

    /// Declares a tool or a configuration key its child Operations may name.
    #[must_use]
    pub fn target(mut self, code: Code) -> Self {
        self.0.targets.insert(code);
        self
    }

    /// Sets the configuration schema.
    #[must_use]
    pub fn config_schema(mut self, schema: ConfigSchema) -> Self {
        self.0.config_schema = Some(schema);
        self
    }

    /// Asks for per-pocket state of at most `bytes`.
    #[must_use]
    pub const fn state_bytes(mut self, bytes: u32) -> Self {
        self.0.state_bytes = bytes;
        self
    }

    /// Bounds the declarations one call may return.
    #[must_use]
    pub const fn max_decls(mut self, max: u16) -> Self {
        self.0.max_decls = max;
        self
    }

    /// Enables the module without configuration saying so.
    #[must_use]
    pub const fn default_enabled(mut self, enabled: bool) -> Self {
        self.0.default_enabled = enabled;
        self
    }

    /// Validates the manifest whole.
    ///
    /// # Errors
    /// The first [`ManifestError`] that would keep the kernel from honouring all of it.
    pub fn build(self) -> Result<Manifest, ManifestError> {
        let m = self.0;
        let mut points = BTreeSet::new();
        for hook in &m.hooks {
            if !points.insert(hook.point) {
                return Err(ManifestError::DuplicateHook(hook.point));
            }
            if hook.deadline_us == 0 || hook.deadline_us > hook.point.ceiling_us() {
                return Err(ManifestError::Deadline {
                    point: hook.point,
                    ceiling_us: hook.point.ceiling_us(),
                });
            }
            if let Some(feature) = hook.point.required_feature()
                && !m.requires.contains(&feature)
            {
                return Err(ManifestError::FeatureNotRequired(feature));
            }
            if hook.mode == HookMode::Act && !hook.point.acts() {
                return Err(ManifestError::ModeUnavailable(hook.point));
            }
            if hook.on_failure == OnFailure::Deny && !hook.point.denies() {
                return Err(ManifestError::FailureUnavailable(hook.point));
            }
        }
        for kind in &m.actions {
            if let Some(feature) = kind.required_features().into_iter().find(|f| !m.requires.contains(f)) {
                return Err(ManifestError::FeatureNotRequired(feature));
            }
        }
        if m.grants.iter().any(|g| !m.actions.contains(&g.kind)) {
            return Err(ManifestError::GrantWithoutAction);
        }
        if let Some(grant) = m.grants.iter().find(|g| !m.reasons.contains(&g.why)) {
            return Err(ManifestError::UndeclaredCode(grant.why.clone()));
        }
        if m.state_bytes > MAX_STATE_BYTES {
            return Err(ManifestError::StateTooLarge { max: MAX_STATE_BYTES });
        }
        if m.max_decls == 0 || m.max_decls > MAX_DECLS {
            return Err(ManifestError::Decls { max: MAX_DECLS });
        }
        if [
            m.reasons.len(),
            m.labels.len(),
            m.events.len(),
            m.targets.len(),
            m.grants.len(),
        ]
        .into_iter()
        .any(|n| n > MAX_CODES)
        {
            return Err(ManifestError::TooManyCodes { max: MAX_CODES });
        }
        if m.events.iter().any(|e| e.fields.len() > MAX_EVENT_VALUES) {
            return Err(ManifestError::TooManyCodes { max: MAX_EVENT_VALUES });
        }
        let mut seen = BTreeSet::new();
        for event in &m.events {
            if !seen.insert(&event.code) {
                return Err(ManifestError::DuplicateEvent(event.code.clone()));
            }
        }
        if m.default_enabled && !m.actions.is_empty() {
            return Err(ManifestError::DefaultOnReachesOutside);
        }
        Ok(m)
    }
}

/// Why a kernel refuses a valid manifest.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Refusal {
    /// Built against another major version of the module API.
    #[error("the module needs module API {module_major}.x; the kernel offers {kernel_major}.x")]
    ApiMajor {
        /// The kernel's major.
        kernel_major: u16,
        /// The module's major.
        module_major: u16,
    },
    /// Built against a newer minor version than the kernel offers.
    #[error("the module needs module API minor {module_minor}; the kernel offers {kernel_minor}")]
    ApiMinorAhead {
        /// The kernel's minor.
        kernel_minor: u16,
        /// The module's minor.
        module_minor: u16,
    },
    /// The module requires a feature the kernel does not offer.
    #[error("the kernel does not offer `{}`", .0.code())]
    FeatureMissing(KernelFeature),
}

impl Refusal {
    /// A stable label for the kernel's `module.refused` explanation.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ApiMajor { .. } => "api_major",
            Self::ApiMinorAhead { .. } => "api_minor_ahead",
            Self::FeatureMissing(_) => "feature_missing",
        }
    }
}

/// What a running kernel offers: its module API and its features. A degraded kernel offers fewer
/// features, so the same check refuses what it cannot honour. A modules-off kernel (`empty-kernel`)
/// admits no module at all: the host never calls [`KernelOffer::admit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelOffer {
    api: ModuleApiVersion,
    features: BTreeSet<KernelFeature>,
}

impl KernelOffer {
    /// An offer.
    #[must_use]
    pub const fn new(api: ModuleApiVersion, features: BTreeSet<KernelFeature>) -> Self {
        Self { api, features }
    }

    /// The features offered.
    #[must_use]
    pub const fn features(&self) -> &BTreeSet<KernelFeature> {
        &self.features
    }

    /// Admits a module whole, or refuses it with the first reason: by version, then by every
    /// required feature compared as a set.
    ///
    /// # Errors
    /// The [`Refusal`].
    pub fn admit(&self, manifest: &Manifest) -> Result<(), Refusal> {
        let (kernel, module) = (self.api, manifest.api());
        if kernel.major() != module.major() {
            return Err(Refusal::ApiMajor {
                kernel_major: kernel.major(),
                module_major: module.major(),
            });
        }
        if module.minor() > kernel.minor() {
            return Err(Refusal::ApiMinorAhead {
                kernel_minor: kernel.minor(),
                module_minor: module.minor(),
            });
        }
        match manifest.requires().iter().find(|f| !self.features.contains(f)) {
            Some(missing) => Err(Refusal::FeatureMissing(*missing)),
            None => Ok(()),
        }
    }
}
