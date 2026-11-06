// SPDX-License-Identifier: Apache-2.0

//! The configuration snapshot, pinned per Operation.
//!
//! Text injected into a request is rendered once, in the locale of the snapshot its Operation
//! pinned, and journaled as bytes; replay reuses the bytes (prefix-stable rendering).
//! A publish therefore never changes a pinned snapshot: it reaches the next pin only.

use std::fmt;
use std::sync::{Arc, PoisonError, RwLock};

use uaos_contracts::wire::ConfigVersion;

/// The longest locale tag accepted, in bytes.
pub const MAX_LOCALE_TAG: usize = 35;

/// A locale, as an opaque tag shaped like BCP 47: a primary subtag of 2–3 or 5–8 ASCII letters,
/// then subtags of 1–8 ASCII letters or digits, joined by `-`; at most [`MAX_LOCALE_TAG`] bytes.
///
/// Kept exactly as given: never case-folded, and never matched against a list here. The list of GA
/// locales is a product decision and lives in the surface layer, so an eighth language changes no
/// kernel type.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct LocaleTag(Box<str>);

/// A string that is not a well-formed locale tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not a well-formed locale tag")]
pub struct LocaleError;

impl LocaleTag {
    /// A tag.
    ///
    /// # Errors
    /// [`LocaleError`] if `tag` is not shaped as the type describes.
    pub fn new(tag: &str) -> Result<Self, LocaleError> {
        if tag.is_empty() || tag.len() > MAX_LOCALE_TAG {
            return Err(LocaleError);
        }
        let mut subtags = tag.split('-');
        let primary = subtags.next().unwrap_or_default();
        let primary_ok = matches!(primary.len(), 2 | 3 | 5..=8) && primary.bytes().all(|b| b.is_ascii_alphabetic());
        let rest_ok = subtags.all(|s| (1..=8).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric()));
        if primary_ok && rest_ok {
            Ok(Self(tag.into()))
        } else {
            Err(LocaleError)
        }
    }

    /// The tag, as given.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for LocaleTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LocaleTag({})", self.0)
    }
}

/// One immutable configuration snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigSnapshot {
    version: ConfigVersion,
    locale: LocaleTag,
}

impl ConfigSnapshot {
    /// A snapshot.
    #[must_use]
    pub const fn new(version: ConfigVersion, locale: LocaleTag) -> Self {
        Self { version, locale }
    }

    /// Its version, recorded on every event of an Operation that pinned it.
    #[must_use]
    pub const fn version(&self) -> ConfigVersion {
        self.version
    }

    /// The locale text injected under it is rendered in.
    #[must_use]
    pub const fn locale(&self) -> &LocaleTag {
        &self.locale
    }
}

/// A publish that was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// The offered version is not newer than the current one.
    #[error("configuration version {offered} is not newer than {current}")]
    NotNewer {
        /// The version in force.
        current: ConfigVersion,
        /// The version offered.
        offered: ConfigVersion,
    },
}

/// Where snapshots are published and pinned.
pub struct ConfigCell {
    current: RwLock<Arc<ConfigSnapshot>>,
}

impl fmt::Debug for ConfigCell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigCell").field("current", &self.pin()).finish()
    }
}

impl ConfigCell {
    /// A cell holding `initial`.
    #[must_use]
    pub fn new(initial: ConfigSnapshot) -> Self {
        Self {
            current: RwLock::new(Arc::new(initial)),
        }
    }

    /// The snapshot in force, for an Operation to keep to its end.
    #[must_use]
    pub fn pin(&self) -> Arc<ConfigSnapshot> {
        // A snapshot is replaced whole, so a poisoned lock still holds a consistent one.
        Arc::clone(&self.current.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Publishes `next`. Pinned snapshots are unchanged; the next pin gets `next`.
    ///
    /// # Errors
    /// [`ConfigError::NotNewer`] unless `next`'s version is greater than the current one.
    pub fn publish(&self, next: ConfigSnapshot) -> Result<(), ConfigError> {
        let mut current = self.current.write().unwrap_or_else(PoisonError::into_inner);
        if next.version <= current.version {
            return Err(ConfigError::NotNewer {
                current: current.version,
                offered: next.version,
            });
        }
        *current = Arc::new(next);
        Ok(())
    }
}
