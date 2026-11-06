// SPDX-License-Identifier: Apache-2.0

//! On-disk encodings. Fixed layouts, parsed strictly; every field has a known length.
//!
//! ```text
//! chunk file  "UAOSCHK1" | nonce (12) | AES-256-GCM(data key, plaintext, aad = chunk context)
//! key file    "UAOSKEY1" | KEK version (u32 LE) | nonce (12) | AES-256-GCM(KEK, data key, aad = key context)
//! ```
//!
//! The authenticated contexts bind each ciphertext to its pocket and reference (and the key
//! file also to its KEK version), so files cannot be swapped between chunks or pockets.

use uaos_contracts::digest::ChunkRef;
use uaos_contracts::id::PocketId;
use uaos_platform::crypto::{KEY_LEN, NONCE_LEN, TAG_LEN};

use super::keyring::KekVersion;

const CHUNK_MAGIC: &[u8; 8] = b"UAOSCHK1";
const KEY_MAGIC: &[u8; 8] = b"UAOSKEY1";

/// Authenticated context of a chunk's ciphertext.
pub(crate) fn chunk_aad(pocket: PocketId, chunk: ChunkRef) -> Vec<u8> {
    format!("uaos.chunk/1|{pocket}|{chunk}").into_bytes()
}

/// Authenticated context of a wrapped data key.
pub(crate) fn key_aad(pocket: PocketId, chunk: ChunkRef, version: KekVersion) -> Vec<u8> {
    format!("uaos.dek/1|{pocket}|{chunk}|{}", version.0).into_bytes()
}

pub(crate) fn encode_chunk(nonce: [u8; NONCE_LEN], sealed: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(CHUNK_MAGIC.len() + NONCE_LEN + sealed.len());
    out.extend_from_slice(CHUNK_MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(sealed);
    out
}

/// Returns `(nonce, sealed)` or `None` if the bytes are not a well-formed chunk file.
pub(crate) fn decode_chunk(bytes: &[u8]) -> Option<([u8; NONCE_LEN], &[u8])> {
    let rest = bytes.strip_prefix(CHUNK_MAGIC)?;
    let (nonce, sealed) = rest.split_first_chunk::<NONCE_LEN>()?;
    (sealed.len() >= TAG_LEN).then_some((*nonce, sealed))
}

/// Length of a well-formed key file.
const KEY_FILE_LEN: usize = KEY_MAGIC.len() + 4 + NONCE_LEN + KEY_LEN + TAG_LEN;

pub(crate) fn encode_key(version: KekVersion, nonce: [u8; NONCE_LEN], wrapped: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(KEY_FILE_LEN);
    out.extend_from_slice(KEY_MAGIC);
    out.extend_from_slice(&version.0.to_le_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(wrapped);
    out
}

/// Returns `(version, nonce, wrapped)` or `None` if malformed.
pub(crate) fn decode_key(bytes: &[u8]) -> Option<(KekVersion, [u8; NONCE_LEN], &[u8])> {
    if bytes.len() != KEY_FILE_LEN {
        return None;
    }
    let rest = bytes.strip_prefix(KEY_MAGIC)?;
    let (version, rest) = rest.split_first_chunk::<4>()?;
    let (nonce, wrapped) = rest.split_first_chunk::<NONCE_LEN>()?;
    Some((KekVersion(u32::from_le_bytes(*version)), *nonce, wrapped))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn round_trips() {
        use uaos_platform::crypto::{SecretKey, seal};
        use uaos_platform::sim::SimRng;
        let key = SecretKey::generate(&SimRng::new(1)).unwrap();
        let sealed = seal(&key, b"aad", b"content").unwrap();
        let c = encode_chunk(sealed.nonce, &sealed.ciphertext);
        assert_eq!(decode_chunk(&c), Some((sealed.nonce, &sealed.ciphertext[..])));

        let wrapped = seal(&key, b"aad", &[5; KEY_LEN]).unwrap();
        let k = encode_key(KekVersion(7), wrapped.nonce, &wrapped.ciphertext);
        assert_eq!(
            decode_key(&k),
            Some((KekVersion(7), wrapped.nonce, &wrapped.ciphertext[..]))
        );
    }

    proptest! {
        /// Arbitrary bytes never panic the decoders.
        #[test]
        fn decoders_are_total(bytes in prop::collection::vec(any::<u8>(), 0..128)) {
            let _chunk = decode_chunk(&bytes);
            let _key = decode_key(&bytes);
        }
    }
}
