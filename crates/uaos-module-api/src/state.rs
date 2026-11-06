// SPDX-License-Identifier: Apache-2.0

//! Pocket-scoped module state and how it stays in step with the journal.
//!
//! A module that remembers keeps its state per (module, pocket), never shared between pockets. The
//! state reflects the pocket's journaled events up to a [`PocketCursor`]. A checkpoint is persisted
//! by the host as a chunk under the pocket's key, so shredding a pocket shreds its module states
//! with it; this crate defines the shapes, the host encrypts and stores.

use std::fmt;

use uaos_contracts::event::ModuleName;
use uaos_contracts::id::PocketId;
use uaos_contracts::wire::Seq;

use crate::manifest::MAX_STATE_BYTES;

/// A state change refused because it would pass the module's bound.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("module state is bounded at {limit} bytes; {wanted} were asked for")]
pub struct StateError {
    /// The bound.
    pub limit: u32,
    /// The size asked for.
    pub wanted: usize,
}

/// One module's state for one pocket: opaque bytes, at most the manifest's `state_bytes`, itself at
/// most [`MAX_STATE_BYTES`] (64 KiB).
///
/// **All or nothing per call**. Each change is atomic, and a refused one also marks the state
/// [`exceeded`](Self::exceeded). The host runs every call on a copy and keeps the copy only if it
/// is not exceeded and its declarations pass; otherwise the call is a strike
/// ([`crate::Strike::StateExceeded`]) and the state stays as it was before the call.
#[derive(Clone, PartialEq, Eq)]
pub struct ModuleState {
    bytes: Vec<u8>,
    limit: u32,
    exceeded: bool,
}

impl ModuleState {
    /// Empty state with the bound `limit`, clamped to [`MAX_STATE_BYTES`].
    #[must_use]
    pub fn new(limit: u32) -> Self {
        Self {
            bytes: Vec::new(),
            limit: limit.min(MAX_STATE_BYTES),
            exceeded: false,
        }
    }

    /// State restored from a checkpoint.
    ///
    /// # Errors
    /// [`StateError`] if `bytes` exceed the bound: a checkpoint never restores more than the
    /// module may hold.
    pub fn restore(limit: u32, bytes: Vec<u8>) -> Result<Self, StateError> {
        let mut state = Self::new(limit);
        state.check(bytes.len())?;
        state.bytes = bytes;
        Ok(state)
    }

    fn check(&mut self, wanted: usize) -> Result<(), StateError> {
        if u32::try_from(wanted).is_ok_and(|n| n <= self.limit) {
            Ok(())
        } else {
            self.exceeded = true;
            Err(StateError {
                limit: self.limit,
                wanted,
            })
        }
    }

    /// Whether a change was refused since this state was created or restored: the call that did
    /// it must not be kept.
    #[must_use]
    pub const fn exceeded(&self) -> bool {
        self.exceeded
    }

    /// The bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The bound, in bytes.
    #[must_use]
    pub const fn limit(&self) -> u32 {
        self.limit
    }

    /// Replaces the state whole, or leaves it unchanged.
    ///
    /// # Errors
    /// [`StateError`] if `bytes` exceed the bound; the state is then unchanged.
    pub fn replace(&mut self, bytes: &[u8]) -> Result<(), StateError> {
        self.check(bytes.len())?;
        self.bytes.clear();
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    /// Appends to the state, or leaves it unchanged.
    ///
    /// # Errors
    /// [`StateError`] if the result would exceed the bound; the state is then unchanged.
    pub fn append(&mut self, bytes: &[u8]) -> Result<(), StateError> {
        self.check(self.bytes.len().saturating_add(bytes.len()))?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    /// Empties the state.
    pub fn clear(&mut self) {
        self.bytes.clear();
    }
}

impl fmt::Debug for ModuleState {
    // Sizes only: a module's state may hold anything it derived from content.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ModuleState")
            .field("len", &self.bytes.len())
            .field("limit", &self.limit)
            .field("exceeded", &self.exceeded)
            .finish()
    }
}

/// A hook's handle on its pocket's state, handed over by value for one call: the only way a
/// module changes its state. It offers the bounded changes and nothing else, so a module can
/// neither swap the host's state for another (which would clear `exceeded` and raise its bound)
/// nor keep the handle past the call.
pub struct StateMut<'s> {
    state: &'s mut ModuleState,
}

impl<'s> StateMut<'s> {
    /// A handle on `state` for one call. The host builds it.
    #[must_use]
    pub const fn new(state: &'s mut ModuleState) -> Self {
        Self { state }
    }

    /// The bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.state.as_bytes()
    }

    /// The bound, in bytes.
    #[must_use]
    pub const fn limit(&self) -> u32 {
        self.state.limit()
    }

    /// As [`ModuleState::replace`].
    ///
    /// # Errors
    /// [`StateError`] past the bound; the state is unchanged and marked exceeded.
    pub fn replace(&mut self, bytes: &[u8]) -> Result<(), StateError> {
        self.state.replace(bytes)
    }

    /// As [`ModuleState::append`].
    ///
    /// # Errors
    /// [`StateError`] past the bound; the state is unchanged and marked exceeded.
    pub fn append(&mut self, bytes: &[u8]) -> Result<(), StateError> {
        self.state.append(bytes)
    }

    /// Empties the state.
    pub fn clear(&mut self) {
        self.state.clear();
    }
}

impl fmt::Debug for StateMut<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&*self.state, f)
    }
}

/// How far a module's state for a pocket reflects that pocket's journaled events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PocketCursor {
    pocket: PocketId,
    through: Option<Seq>,
}

impl PocketCursor {
    /// A cursor before the pocket's first event.
    #[must_use]
    pub const fn start(pocket: PocketId) -> Self {
        Self { pocket, through: None }
    }

    /// The pocket.
    #[must_use]
    pub const fn pocket(self) -> PocketId {
        self.pocket
    }

    /// The last event the state reflects, if any.
    #[must_use]
    pub const fn through(self) -> Option<Seq> {
        self.through
    }

    /// Whether the event at `seq` is after the cursor, and so still to be delivered.
    #[must_use]
    pub fn is_after(self, seq: Seq) -> bool {
        self.through.is_none_or(|through| seq.0 > through.0)
    }

    /// Moves the cursor to the event at `seq` of `pocket`, which must be this cursor's pocket and
    /// after it: events reach a module in journal order, each once per state lineage, and never
    /// from another pocket.
    ///
    /// # Errors
    /// The cursor, unchanged, if `pocket` is another pocket or `seq` is not after it.
    pub fn advance(&mut self, pocket: PocketId, seq: Seq) -> Result<(), Self> {
        if pocket == self.pocket && self.is_after(seq) {
            self.through = Some(seq);
            Ok(())
        } else {
            Err(*self)
        }
    }
}

/// What a checkpoint records about a module's state: the host stores the bytes as a chunk under
/// the pocket's key and journals this with the chunk's reference (`module.state_checkpoint`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateCheckpoint {
    /// The module.
    pub module: ModuleName,
    /// The cursor the state reflects; its pocket is the only pocket the checkpoint concerns.
    pub cursor: PocketCursor,
    /// The state's length, in bytes.
    pub len: u32,
}
