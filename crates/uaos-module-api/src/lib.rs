// SPDX-License-Identifier: Apache-2.0

//! # The UAOS module socket (`uaos.module/1`, `uaos.adapter/1`, draft)
//!
//! The types through which modules attach to the kernel, and nothing that runs them. The contract
//! is; the host that calls modules is the runtime's.
//!
//! **Modules describe; the kernel acts**. A module receives read-only views and returns
//! [`Decl`]arations. Every effect it wants is a child Operation the kernel runs through the full
//! pipeline. Nothing in this crate performs I/O or holds a handle that does: no file, socket,
//! process, clock, randomness or channel (`arch.toml` bans the crates that would).
//!
//! **Zero trust, as types.**
//! - [`Manifest`]s are built only through [`ManifestBuilder`] and validated whole; the kernel's
//!   [`KernelOffer`] admits a module only if it offers every [`KernelFeature`] the module
//!   requires, compared by set, so a module is never loaded in part.
//! - Declarations carry declared [`Code`]s, never free text; text a module adds is a bounded
//!   [`ModuleText`] that the kernel detects and scans like any outbound byte.
//! - [`ModuleState`] is bounded and per pocket; [`PocketCursor`] keeps it in step with the
//!   pocket's journaled events.
//! - A [`GrantRef`] only names a grant: authority is the live grant, which the host re-checks at
//!   every use.
//! - [`StructuralView`] shows content with every detected secret masked, in values and in keys
//!   ([`Mask`]).
//!
//! **Language-neutral.** Content in any language is bytes: nothing here normalizes, case-folds or
//! reorders it, and no type names a locale. What a person reads is a [`Code`] a surface translates;
//! what a model reads is [`ModuleText`], kept byte for byte.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod code;
mod codec;
mod decl;
mod grant_ref;
mod manifest;
mod module;
mod selector;
mod state;
mod view;

pub use code::{Code, CodeError, MAX_CODE_LEN};
// The tape types the view's API names, so a Ring 1 module needs no edge to `uaos-json`.
pub use codec::{
    CodecError, DialectCodec, EndpointClass, EndpointDecl, FrameKind, Method, PathError, PathPattern, Role, RoleMap,
    SseEvent, UsageReport, classify,
};
pub use decl::{
    AppendSlot, CandidateId, ChildBody, ChildOpRequest, Decl, DeclError, Decls, DeclsMut, MAX_EVENT_VALUES,
    MAX_MODULE_TEXT, MAX_RANK, ModuleEvent, ModuleText, Strike, TextError, check_decls, is_explicit_bidi, is_tag,
    is_variation_selector,
};
pub use grant_ref::GrantRef;
pub use manifest::{
    ChildKind, ConfigSchema, EventClass, EventDecl, GrantDecl, HookDecl, HookMode, HookPoint, KernelFeature,
    KernelOffer, MAX_CODES, MAX_CONFIG_SCHEMA_BYTES, MAX_DECLS, MAX_STATE_BYTES, Manifest, ManifestBuilder,
    ManifestError, ModuleApiVersion, ModuleVersion, OnFailure, Refusal, ViewKind,
};
pub use module::{Admitted, Candidate, CircuitState, EventView, HookCx, Module, OpMeta};
pub use selector::{
    MAX_PREDICATE_DEPTH, MAX_PREDICATE_VALUES, MAX_SELECTOR_STEPS, MAX_SELECTOR_TEXT, MAX_VISITS, Predicate, Selector,
    SelectorError, Step, Visits,
};
pub use state::{ModuleState, PocketCursor, StateCheckpoint, StateError, StateMut};
pub use uaos_json::{JsonError, Kind, NodeId};
pub use view::{Mask, MaskError, Sealed, StructuralView, ViewNode, ViewText};
