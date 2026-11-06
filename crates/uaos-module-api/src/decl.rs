// SPDX-License-Identifier: Apache-2.0

//! Declarations: what a module may ask the kernel to do. A module never performs an effect; the
//! kernel checks every declaration against the manifest and the point, then acts.

use std::fmt;

use uaos_contracts::id::{OperationId, PocketId};

use crate::code::Code;
use crate::grant_ref::GrantRef;
use crate::manifest::{ChildKind, HookMode, HookPoint, KernelFeature, Manifest};
use crate::selector::Selector;

/// The longest text a module may add, in bytes.
pub const MAX_MODULE_TEXT: usize = 8 * 1024;
/// The most values one module event may carry.
pub const MAX_EVENT_VALUES: usize = 8;
/// The most candidates one [`Decl::Rank`] may name.
pub const MAX_RANK: usize = 64;

/// Text that does not fit [`ModuleText`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TextError {
    /// Longer than [`MAX_MODULE_TEXT`].
    #[error("module text is at most {MAX_MODULE_TEXT} bytes")]
    TooLong,
    /// A control character other than a newline, a carriage return or a tab.
    #[error("module text holds a control character other than a newline, a carriage return or a tab")]
    Control,
    /// A variation selector that follows no visible base character (whitespace, a control and a
    /// default-ignorable code point are none), or another variation selector, or, for an
    /// ideographic one, anything but a CJK ideograph: runs
    /// of them can carry bytes a model decodes and a person cannot see.
    #[error("module text holds a variation selector that follows no visible base")]
    VariationRun,
    /// A Unicode tag character (U+E0000 to U+E007F): text a model reads and a person cannot see.
    #[error("module text holds a Unicode tag character (U+E0000-U+E007F)")]
    Tag,
    /// An explicit bidirectional embedding, override or isolate.
    #[error("module text holds an explicit bidirectional control (U+202A-U+202E, U+2066-U+2069)")]
    Bidi,
}

/// Whether `c` is an explicit bidirectional embedding, override or isolate: U+202A to U+202E and
/// U+2066 to U+2069. A model gains nothing from one, and a person reading the text can be misled
/// by one (Trojan Source). The implicit marks U+200E, U+200F and U+061C are not among them.
#[must_use]
pub const fn is_explicit_bidi(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// Whether `c` is a Unicode tag character, U+E0000 to U+E007F. A model reads tag text that no
/// display shows, so a module could append instructions an approver never sees.
#[must_use]
pub const fn is_tag(c: char) -> bool {
    matches!(c, '\u{E0000}'..='\u{E007F}')
}

/// Whether `c` is a variation selector (Unicode 16.0, `PropList.txt`, `Variation_Selector`): the
/// Mongolian free variation selectors U+180B to U+180D and U+180F, U+FE00 to U+FE0F, or U+E0100 to
/// U+E01EF. One after a base character selects a glyph (an
/// emoji's presentation, an ideographic variant); a run of them selects nothing a person sees.
#[must_use]
pub const fn is_variation_selector(c: char) -> bool {
    matches!(
        c,
        '\u{180B}'..='\u{180D}' | '\u{180F}' | '\u{FE00}'..='\u{FE0F}' | '\u{E0100}'..='\u{E01EF}'
    )
}

/// Whether `c` is a default-ignorable code point (Unicode 16.0, `DerivedCoreProperties.txt`,
/// `Default_Ignorable_Code_Point`): invisible, so no base for a variation selector.
const fn is_default_ignorable(c: char) -> bool {
    matches!(
        c,
        '\u{AD}'
            | '\u{34F}'
            | '\u{61C}'
            | '\u{115F}'..='\u{1160}'
            | '\u{17B4}'..='\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF0}'..='\u{FFF8}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E0FFF}'
    )
}

/// Whether `c` is a CJK unified ideograph (Unicode 16.0, `PropList.txt`, `Unified_Ideograph`), the
/// only base an
/// ideographic variation selector, U+E0100 to U+E01EF, takes (UTS #37).
const fn is_unified_ideograph(c: char) -> bool {
    matches!(
        c,
        '\u{3400}'..='\u{4DBF}'
            | '\u{4E00}'..='\u{9FFF}'
            | '\u{FA0E}'..='\u{FA0F}'
            | '\u{FA11}'
            | '\u{FA13}'..='\u{FA14}'
            | '\u{FA1F}'
            | '\u{FA21}'
            | '\u{FA23}'..='\u{FA24}'
            | '\u{FA27}'..='\u{FA29}'
            | '\u{20000}'..='\u{2A6DF}'
            | '\u{2A700}'..='\u{2B739}'
            | '\u{2B740}'..='\u{2B81D}'
            | '\u{2B820}'..='\u{2CEA1}'
            | '\u{2CEB0}'..='\u{2EBE0}'
            | '\u{2EBF0}'..='\u{2EE5D}'
            | '\u{30000}'..='\u{3134A}'
            | '\u{31350}'..='\u{323AF}'
    )
}

/// Text a module adds to a request: bounded, in any language and kept byte for byte, without
/// control characters but newlines, carriage returns and tabs, without explicit bidirectional
/// controls, tag characters, and variation selectors that follow no visible base (an ideographic
/// one follows a CJK ideograph). Like every outbound byte, it is detected and final-scanned by the
/// kernel.
#[derive(Clone, PartialEq, Eq)]
pub struct ModuleText(String);

impl ModuleText {
    /// Checks and wraps `text`, unchanged: no normalization, no case folding.
    ///
    /// # Errors
    /// [`TextError`] if it is too long, or holds a control character, an explicit bidirectional
    /// control, a tag character, or a variation selector that follows no visible base
    /// (whitespace, a control and a default-ignorable code point are none), or an ideographic
    /// one after anything but a CJK unified ideograph.
    pub fn new(text: impl Into<String>) -> Result<Self, TextError> {
        let text = text.into();
        if text.len() > MAX_MODULE_TEXT {
            return Err(TextError::TooLong);
        }
        if text.chars().any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t')) {
            return Err(TextError::Control);
        }
        if text.chars().any(is_explicit_bidi) {
            return Err(TextError::Bidi);
        }
        if text.chars().any(is_tag) {
            return Err(TextError::Tag);
        }
        // The visible character a variation selector may follow, if the last one was one.
        let mut base: Option<char> = None;
        for c in text.chars() {
            if is_variation_selector(c) {
                // An ideographic selector selects a glyph of a CJK ideograph only (UTS #37).
                let ideographic = c >= '\u{E0100}';
                if !base.is_some_and(|b| !ideographic || is_unified_ideograph(b)) {
                    return Err(TextError::VariationRun);
                }
                // A second selector needs a base of its own.
                base = None;
            } else {
                base = (!c.is_whitespace() && !c.is_control() && !is_default_ignorable(c)).then_some(c);
            }
        }
        Ok(Self(text))
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ModuleText {
    // Its length only: the text is outbound content.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ModuleText").field("len", &self.0.len()).finish()
    }
}

/// Where an appended text goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum AppendSlot {
    /// The end of the newest human turn: the only place injections land.
    NewestHumanTurn,
}

/// A route candidate, as `route.decide` offers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CandidateId(u16);

impl CandidateId {
    /// The candidate at position `n` of the offer.
    #[must_use]
    pub const fn new(n: u16) -> Self {
        Self(n)
    }

    /// Its position.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// An event a module emits: a declared code and at most [`MAX_EVENT_VALUES`] numbers, each under
/// a value name its [`crate::EventDecl`] declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleEvent {
    code: Code,
    values: Vec<(Code, i64)>,
}

impl ModuleEvent {
    /// An event with no values.
    #[must_use]
    pub const fn new(code: Code) -> Self {
        Self {
            code,
            values: Vec::new(),
        }
    }

    /// Adds a named value.
    ///
    /// # Errors
    /// The event, unchanged, once it holds [`MAX_EVENT_VALUES`] values or already holds `name`.
    pub fn value(mut self, name: Code, value: i64) -> Result<Self, Self> {
        if self.values.len() >= MAX_EVENT_VALUES || self.values.iter().any(|(n, _)| *n == name) {
            return Err(self);
        }
        self.values.push((name, value));
        Ok(self)
    }

    /// Its code.
    #[must_use]
    pub const fn code(&self) -> &Code {
        &self.code
    }

    /// Its values.
    #[must_use]
    pub fn values(&self) -> &[(Code, i64)] {
        &self.values
    }
}

/// What a child Operation carries.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChildBody {
    /// A prompt, for a model call or a token count.
    Prompt(ModuleText),
    /// A query of another pocket's memory.
    MemoryQuery {
        /// The pocket to read.
        source: PocketId,
        /// What to look for.
        query: ModuleText,
    },
    /// A configuration change to request (policy answers with an approval).
    ConfigChange {
        /// The key.
        key: Code,
        /// The new value, as text.
        value: ModuleText,
    },
    /// A tool call.
    ToolCall {
        /// The tool.
        tool: Code,
        /// Its input.
        input: ModuleText,
    },
}

impl ChildBody {
    const fn fits(&self, kind: ChildKind) -> bool {
        matches!(
            (kind, self),
            (ChildKind::ModelCall | ChildKind::CountTokens, Self::Prompt(_))
                | (ChildKind::MemoryRead, Self::MemoryQuery { .. })
                | (ChildKind::ConfigChange, Self::ConfigChange { .. })
                | (ChildKind::ToolCall, Self::ToolCall { .. })
        )
    }
}

/// A request for one child Operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildOpRequest {
    kind: ChildKind,
    body: ChildBody,
    grant: Option<GrantRef>,
    correlate: u16,
}

impl ChildOpRequest {
    /// A request of `kind` carrying `body`, tagged `correlate` so the outcome can be matched. The
    /// tag is a number, never a word: it reaches the journal's metadata.
    ///
    /// # Errors
    /// The body back if it does not fit the kind.
    pub fn new(kind: ChildKind, body: ChildBody, correlate: u16) -> Result<Self, ChildBody> {
        if !body.fits(kind) {
            return Err(body);
        }
        Ok(Self {
            kind,
            body,
            grant: None,
            correlate,
        })
    }

    /// Carries a grant.
    #[must_use]
    pub const fn with_grant(mut self, grant: GrantRef) -> Self {
        self.grant = Some(grant);
        self
    }

    /// Its kind.
    #[must_use]
    pub const fn kind(&self) -> ChildKind {
        self.kind
    }

    /// Its body.
    #[must_use]
    pub const fn body(&self) -> &ChildBody {
        &self.body
    }

    /// The grant it carries, if any.
    #[must_use]
    pub const fn grant(&self) -> Option<GrantRef> {
        self.grant
    }

    /// Its correlation tag.
    #[must_use]
    pub const fn correlate(&self) -> u16 {
        self.correlate
    }
}

/// One thing a module asks the kernel to do.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Decl {
    /// Removes what the selector selects, outside every forbidden role.
    Strip(Selector),
    /// Appends text.
    Append {
        /// Where.
        slot: AppendSlot,
        /// What.
        text: ModuleText,
    },
    /// Denies the Operation.
    Veto(Code),
    /// Cancels the stream from the next frame.
    Cancel(Code),
    /// Adds a label; risk only rises.
    Label(Code),
    /// Ranks, or narrows, the route candidates offered: 1 to [`MAX_RANK`], none twice. An empty
    /// ranking would veto the route without a reason, so it is a strike; the host strikes an id
    /// outside the offer.
    Rank(Vec<CandidateId>),
    /// Emits an event.
    Emit(ModuleEvent),
    /// Requests a child Operation.
    Request(ChildOpRequest),
    /// Cancels one of the module's own child Operations.
    CancelOp(OperationId),
    /// Persists the module's state for this pocket.
    Checkpoint,
}

impl Decl {
    /// Whether this declaration is allowed at `point`, or from `on_event` when `point` is `None`.
    #[must_use]
    pub const fn allowed_at(&self, point: Option<HookPoint>) -> bool {
        use HookPoint as P;
        matches!(
            (self, point),
            (Self::Emit(_) | Self::Request(_) | Self::CancelOp(_), _)
                | (Self::Checkpoint, None | Some(P::ContextAssemble | P::ResponsePost))
                | (Self::Strip(_), Some(P::IngressParsed | P::ToolResult))
                | (Self::Append { .. }, Some(P::IngressParsed | P::ContextAssemble))
                | (Self::Veto(_), Some(P::ToolResult))
                | (Self::Cancel(_), Some(P::StreamAssert))
                | (Self::Label(_), Some(P::Classify))
                | (Self::Rank(_), Some(P::RouteDecide))
        )
    }

    /// Whether an observe-mode hook may return it.
    #[must_use]
    pub const fn observes(&self) -> bool {
        matches!(
            self,
            Self::Emit(_) | Self::Request(_) | Self::CancelOp(_) | Self::Checkpoint
        )
    }
}

/// Why one hook call's declarations are refused: the module gets a strike and none of the call's
/// declarations apply. A static strike (from [`check_decls`]) and [`Strike::StateExceeded`] also
/// discard the call's state changes; a host-side strike ([`Strike::NotOwnChild`],
/// [`Strike::UnknownCandidate`], [`Strike::BudgetExceeded`]) keeps them.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Strike {
    /// More declarations than the manifest's `max_decls`.
    #[error("more declarations than the manifest allows")]
    TooMany,
    /// Declarations at a point the manifest does not hook.
    #[error("declarations at a point the manifest does not hook")]
    NotHooked,
    /// A declaration past a bound: an empty ranking, one longer than [`MAX_RANK`], or one that
    /// names a candidate twice.
    #[error("a declaration past its bound")]
    BoundExceeded,
    /// The call grew the module's state past its bound ([`crate::ModuleState::exceeded`]).
    #[error("the call grew the module's state past its bound")]
    StateExceeded,
    /// A `CancelOp` naming an Operation that is not one of the module's own children; the host
    /// checks it, since only the host knows the children.
    #[error("a cancellation of an Operation that is not the module's own child")]
    NotOwnChild,
    /// A ranking naming a candidate outside the offer; the host checks it against the offer.
    #[error("a ranking names a candidate outside the offer")]
    UnknownCandidate,
    /// The call's selectors ran past the host's visit budget ([`crate::Visits`]).
    #[error("the call's selectors ran past their visit budget")]
    BudgetExceeded,
    /// A declaration the point, or the hook's mode, does not allow.
    #[error("a declaration this point or mode does not allow")]
    NotAllowedHere,
    /// A reason, label or event code the manifest does not declare.
    #[error("a code the manifest does not declare")]
    UndeclaredCode,
    /// A child Operation of a kind the manifest does not declare.
    #[error("a child Operation the manifest does not declare")]
    UndeclaredAction,
    /// A declaration that needs a feature the manifest does not require.
    #[error("a declaration that needs `{}`, which the manifest does not require", .0.code())]
    FeatureNotRequired(KernelFeature),
}

impl Strike {
    /// A stable label for the kernel's explanation.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::TooMany => "too_many",
            Self::NotHooked => "not_hooked",
            Self::BoundExceeded => "bound_exceeded",
            Self::StateExceeded => "state_exceeded",
            Self::NotOwnChild => "not_own_child",
            Self::UnknownCandidate => "unknown_candidate",
            Self::BudgetExceeded => "budget_exceeded",
            Self::NotAllowedHere => "not_allowed_here",
            Self::UndeclaredCode => "undeclared_code",
            Self::UndeclaredAction => "undeclared_action",
            Self::FeatureNotRequired(_) => "feature_not_required",
        }
    }
}

/// Checks one call's declarations against the manifest and the point (`None` for `on_event`).
/// All or nothing: the first refusal refuses the whole call. The host also refuses a call whose
/// state copy is [`crate::ModuleState::exceeded`] ([`Strike::StateExceeded`]).
///
/// # Errors
/// The [`Strike`].
pub fn check_decls(manifest: &Manifest, point: Option<HookPoint>, decls: &[Decl]) -> Result<(), Strike> {
    if decls.len() > usize::from(manifest.max_decls()) {
        return Err(Strike::TooMany);
    }
    let observing = match point {
        None => true,
        Some(p) => manifest.hook(p).ok_or(Strike::NotHooked)?.mode() == HookMode::Observe,
    };
    for decl in decls {
        if !decl.allowed_at(point) || (observing && !decl.observes()) {
            return Err(Strike::NotAllowedHere);
        }
        match decl {
            Decl::Veto(code) | Decl::Cancel(code) if !manifest.declares_reason(code) => {
                return Err(Strike::UndeclaredCode);
            }
            Decl::Label(code) if !manifest.declares_label(code) => return Err(Strike::UndeclaredCode),
            Decl::Emit(event) => {
                let declared = manifest.event(event.code()).ok_or(Strike::UndeclaredCode)?;
                if !event.values().iter().all(|(name, _)| declared.fields.contains(name)) {
                    return Err(Strike::UndeclaredCode);
                }
            }
            Decl::Rank(ranked) => {
                let distinct: std::collections::BTreeSet<_> = ranked.iter().collect();
                if ranked.is_empty() || ranked.len() > MAX_RANK || distinct.len() != ranked.len() {
                    return Err(Strike::BoundExceeded);
                }
            }
            Decl::Request(request) => {
                if !manifest.actions().contains(&request.kind()) {
                    return Err(Strike::UndeclaredAction);
                }
                let target = match request.body() {
                    ChildBody::ToolCall { tool, .. } => Some(tool),
                    ChildBody::ConfigChange { key, .. } => Some(key),
                    ChildBody::Prompt(_) | ChildBody::MemoryQuery { .. } => None,
                };
                if target.is_some_and(|t| !manifest.declares_target(t)) {
                    return Err(Strike::UndeclaredCode);
                }
                if let Some(feature) = request
                    .kind()
                    .required_features()
                    .into_iter()
                    .find(|f| !manifest.requires().contains(f))
                {
                    return Err(Strike::FeatureNotRequired(feature));
                }
            }
            Decl::CancelOp(_) if !manifest.requires().contains(&KernelFeature::ChildOperations) => {
                return Err(Strike::FeatureNotRequired(KernelFeature::ChildOperations));
            }
            Decl::Checkpoint if !manifest.requires().contains(&KernelFeature::StateCheckpoints) => {
                return Err(Strike::FeatureNotRequired(KernelFeature::StateCheckpoints));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Collects one call's declarations, up to the manifest's bound.
#[derive(Clone, PartialEq, Eq)]
pub struct Decls {
    items: Vec<Decl>,
    max: u16,
}

/// A hook's handle on its call's declarations, handed over by value: the bound is the host's,
/// and a module can neither swap the collector for a larger one nor keep it past the call.
pub struct DeclsMut<'d> {
    decls: &'d mut Decls,
}

impl<'d> DeclsMut<'d> {
    /// A handle on `decls` for one call. The host builds it.
    #[must_use]
    pub const fn new(decls: &'d mut Decls) -> Self {
        Self { decls }
    }

    /// As [`Decls::push`].
    ///
    /// # Errors
    /// [`DeclError`] once the bound is reached.
    pub fn push(&mut self, decl: Decl) -> Result<(), DeclError> {
        self.decls.push(decl)
    }

    /// The declarations so far.
    #[must_use]
    pub fn as_slice(&self) -> &[Decl] {
        self.decls.as_slice()
    }
}

impl fmt::Debug for DeclsMut<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&*self.decls, f)
    }
}

/// A declaration past the call's bound.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("this call already holds its maximum of {max} declarations")]
pub struct DeclError {
    /// The bound.
    pub max: u16,
}

impl Decls {
    /// An empty collector for at most `max` declarations. The host builds it from the manifest.
    #[must_use]
    pub const fn new(max: u16) -> Self {
        Self { items: Vec::new(), max }
    }

    /// Adds a declaration.
    ///
    /// # Errors
    /// [`DeclError`] once the bound is reached; the collector is unchanged.
    pub fn push(&mut self, decl: Decl) -> Result<(), DeclError> {
        if self.items.len() >= usize::from(self.max) {
            return Err(DeclError { max: self.max });
        }
        self.items.push(decl);
        Ok(())
    }

    /// The declarations so far.
    #[must_use]
    pub fn as_slice(&self) -> &[Decl] {
        &self.items
    }

    /// Takes the declarations out.
    #[must_use]
    pub fn into_inner(self) -> Vec<Decl> {
        self.items
    }

    /// Whether there are none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

impl fmt::Debug for Decls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decls")
            .field("len", &self.items.len())
            .field("max", &self.max)
            .finish()
    }
}
