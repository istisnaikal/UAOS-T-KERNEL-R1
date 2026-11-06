// SPDX-License-Identifier: Apache-2.0

//! Cryptographic primitives. Thin wrappers over aws-lc-rs, the single audited family used for
//! hashing, MACs, AEAD and signatures. No custom constructions live here or anywhere else: this
//! module only adapts types and keeps key material out of reach of `Debug`, logs and long-lived
//! memory.

use std::fmt;

use aws_lc_rs::{aead, digest, hmac};
use uaos_contracts::digest::Sha256Digest;
use zeroize::Zeroizing;

use crate::{PlatformError, Rng};

/// SHA-256 of `bytes`.
#[must_use]
pub fn sha256(bytes: &[u8]) -> Sha256Digest {
    let d = digest::digest(&digest::SHA256, bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    Sha256Digest::from_bytes(out)
}

/// Incremental SHA-256 for inputs assembled from several parts.
#[derive(Clone)]
pub struct Sha256 {
    ctx: digest::Context,
}

impl fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha256 { .. }")
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self {
            ctx: digest::Context::new(&digest::SHA256),
        }
    }
}

impl Sha256 {
    /// Feeds more input.
    pub fn update(&mut self, bytes: &[u8]) {
        self.ctx.update(bytes);
    }

    /// Finishes and returns the digest.
    #[must_use]
    pub fn finish(self) -> Sha256Digest {
        let d = self.ctx.finish();
        let mut out = [0u8; 32];
        out.copy_from_slice(d.as_ref());
        Sha256Digest::from_bytes(out)
    }
}

/// Length of a symmetric key in bytes (256 bits).
pub const KEY_LEN: usize = 32;
/// Length of an AEAD nonce in bytes (96 bits, AES-256-GCM).
pub const NONCE_LEN: usize = 12;
/// Length of an AEAD authentication tag in bytes.
pub const TAG_LEN: usize = 16;

/// 256-bit secret key material. Wiped from memory when dropped; never printed.
pub struct SecretKey(Zeroizing<[u8; KEY_LEN]>);

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(..)")
    }
}

impl SecretKey {
    /// Generates a fresh key from `rng` (the OS CSPRNG in production).
    ///
    /// # Errors
    /// [`PlatformError::RandomUnavailable`] if the random source failed.
    pub fn generate(rng: &dyn Rng) -> Result<Self, PlatformError> {
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        rng.fill(bytes.as_mut())?;
        Ok(Self(bytes))
    }

    /// Wraps existing key bytes (for example unwrapped from storage).
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Exposes the raw key bytes. Only for wrapping this key under another key; never log,
    /// serialize or copy the result into long-lived memory.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// HMAC-SHA-256 of `data` under `key`.
#[must_use]
pub fn hmac_sha256(key: &SecretKey, data: &[u8]) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key.expose_secret());
    let tag = hmac::sign(&key, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// AEAD failure. Deliberately carries no detail: callers must not distinguish causes of an
/// authentication failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// Encryption failed (key setup).
    #[error("encryption failed")]
    Seal,
    /// Decryption failed: wrong key, wrong context, or the data was altered.
    #[error("authentication failed: wrong key, wrong context, or altered data")]
    Open,
}

fn aes_key(key: &SecretKey) -> Result<aead::RandomizedNonceKey, CryptoError> {
    aead::RandomizedNonceKey::new(&aead::AES_256_GCM, key.expose_secret()).map_err(|_| CryptoError::Seal)
}

/// Output of [`seal`]: the nonce aws-lc chose, and the ciphertext followed by the tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    /// Nonce generated inside aws-lc for this message. Store it alongside the ciphertext.
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext followed by the authentication tag.
    pub ciphertext: Vec<u8>,
}

/// Encrypts and authenticates `plaintext` with AES-256-GCM, binding `aad`.
///
/// **UAOS code never chooses a nonce.** aws-lc generates a fresh random nonce inside the AEAD
/// and returns it, so nonce reuse or a constant nonce cannot be introduced by a caller. (This
/// is the one randomness source not routed through `uaos_platform::Rng`: nonce generation
/// belongs to the audited crypto library, and no test depends on nonce values.)
///
/// # Errors
/// [`CryptoError::Seal`] if the key cannot be set up or encryption fails.
pub fn seal(key: &SecretKey, aad: &[u8], plaintext: &[u8]) -> Result<Sealed, CryptoError> {
    let key = aes_key(key)?;
    let mut ciphertext = plaintext.to_vec();
    let nonce = key
        .seal_in_place_append_tag(aead::Aad::from(aad), &mut ciphertext)
        .map_err(|_| CryptoError::Seal)?;
    Ok(Sealed {
        nonce: *nonce.as_ref(),
        ciphertext,
    })
}

/// Verifies and decrypts the output of [`seal`], given the nonce stored with it.
///
/// # Errors
/// [`CryptoError::Open`] if the key, nonce or `aad` differ, or the data was altered.
pub fn open(
    key: &SecretKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let key = aes_key(key).map_err(|_| CryptoError::Open)?;
    let mut in_out = ciphertext_and_tag.to_vec();
    let plaintext_len = key
        .open_in_place(aead::Nonce::from(nonce), aead::Aad::from(aad), &mut in_out)
        .map_err(|_| CryptoError::Open)?
        .len();
    in_out.truncate(plaintext_len);
    Ok(in_out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sim::SimRng;

    #[test]
    fn sha256_known_answers() {
        // FIPS 180-2 test vectors.
        assert_eq!(
            sha256(b"abc").to_string(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256(b"").to_string(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let mut inc = Sha256::default();
        inc.update(b"a");
        inc.update(b"bc");
        assert_eq!(inc.finish(), sha256(b"abc"));
    }

    #[test]
    fn hmac_known_answer() {
        // RFC 4231 test case 2 uses a 4-byte key; with a 32-byte key we check determinism and
        // key separation instead, and the RFC vector through aws-lc-rs directly.
        let rfc = hmac::Key::new(hmac::HMAC_SHA256, b"Jefe");
        assert_eq!(
            hmac::sign(&rfc, b"what do ya want for nothing?").as_ref(),
            [
                0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7, 0x5a,
                0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43
            ]
        );
        let a = SecretKey::from_bytes([1; KEY_LEN]);
        let b = SecretKey::from_bytes([2; KEY_LEN]);
        assert_eq!(hmac_sha256(&a, b"x"), hmac_sha256(&a, b"x"));
        assert_ne!(hmac_sha256(&a, b"x"), hmac_sha256(&b, b"x"));
    }

    #[test]
    fn aead_round_trip_and_binding() {
        let key = SecretKey::generate(&SimRng::new(1)).unwrap();
        let other = SecretKey::generate(&SimRng::new(2)).unwrap();
        let sealed = seal(&key, b"ctx", b"hello").unwrap();
        assert_eq!(sealed.ciphertext.len(), 5 + TAG_LEN);
        assert_eq!(open(&key, &sealed.nonce, b"ctx", &sealed.ciphertext).unwrap(), b"hello");
        assert_eq!(
            open(&key, &sealed.nonce, b"other", &sealed.ciphertext),
            Err(CryptoError::Open)
        );
        let mut wrong_nonce = sealed.nonce;
        wrong_nonce[0] ^= 1;
        assert_eq!(
            open(&key, &wrong_nonce, b"ctx", &sealed.ciphertext),
            Err(CryptoError::Open)
        );
        assert_eq!(
            open(&other, &sealed.nonce, b"ctx", &sealed.ciphertext),
            Err(CryptoError::Open)
        );
        let mut tampered = sealed.ciphertext.clone();
        tampered[0] ^= 1;
        assert_eq!(open(&key, &sealed.nonce, b"ctx", &tampered), Err(CryptoError::Open));
        let again = seal(&key, b"ctx", b"hello").unwrap();
        assert_ne!(again.nonce, sealed.nonce, "every message gets a fresh nonce");
    }

    #[test]
    fn secret_key_debug_hides_material() {
        let key = SecretKey::from_bytes([0xAB; KEY_LEN]);
        assert_eq!(format!("{key:?}"), "SecretKey(..)");
    }
}
