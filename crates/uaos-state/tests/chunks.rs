// SPDX-License-Identifier: Apache-2.0

//! Chunk store: confidentiality, integrity, durability and crypto-shredding, including the
//! attacks shredding exists to defeat (a restored backup of a shredded key file) and a crash in
//! the middle of key rotation.

#![allow(
    clippy::unwrap_used,
    reason = "test harness helpers outside #[test] fns: a failed fixture must abort the test"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use proptest::prelude::*;
use uaos_contracts::id::{PocketId, TypedId};
use uaos_platform::Rng;
use uaos_platform::crypto::sha256;
use uaos_platform::fs::Fs;
use uaos_platform::sim::SimRng;
use uaos_platform::sim::fs::SimFs;
use uaos_state::chunks::keyring::{KekVersion, MemoryKeyring, PocketKeyring};
use uaos_state::chunks::{CHUNKS_DIR, ChunkError, ChunkStore};

struct World {
    fs: SimFs,
    rng: Arc<SimRng>,
    keys: Arc<MemoryKeyring>,
    data: PathBuf,
}

impl World {
    fn new(seed: u64) -> Self {
        let fs = SimFs::new();
        let data = PathBuf::from("/data");
        fs.create_dir_all(&data).unwrap();
        let rng = Arc::new(SimRng::new(seed));
        let keys = Arc::new(MemoryKeyring::new(rng.clone()));
        Self { fs, rng, keys, data }
    }

    fn store(&self) -> ChunkStore {
        let rng: Arc<dyn Rng> = self.rng.clone();
        let keys: Arc<dyn PocketKeyring> = self.keys.clone();
        ChunkStore::open(Arc::new(self.fs.clone()), rng, keys, &self.data).unwrap()
    }

    fn files(&self, pocket: PocketId, sub: &str) -> Vec<PathBuf> {
        self.fs
            .list_dir(&self.data.join(CHUNKS_DIR).join(pocket.to_string()).join(sub))
            .unwrap_or_default()
    }
}

fn pocket(n: u64) -> PocketId {
    PocketId::from_parts(n, [n.to_le_bytes()[0]; 10])
}

#[test]
fn round_trip_and_deduplication() {
    let w = World::new(1);
    let s = w.store();
    let p = pocket(1);
    let a = s.put(p, b"the prompt").unwrap();
    let again = s.put(p, b"the prompt").unwrap();
    assert_eq!(a, again);
    assert_eq!(w.files(p, "data").len(), 1, "same content stored once");
    assert_eq!(s.get(p, a).unwrap(), b"the prompt");
}

#[test]
fn references_are_keyed_and_unlinkable_across_pockets() {
    let w = World::new(2);
    let s = w.store();
    let in_one = s.put(pocket(1), b"same content").unwrap();
    let in_two = s.put(pocket(2), b"same content").unwrap();
    assert_ne!(in_one, in_two, "equal content in two pockets must not be linkable");
    assert_ne!(
        in_one.as_bytes(),
        sha256(b"same content").as_bytes(),
        "a plain hash would allow guess confirmation"
    );
}

#[test]
fn content_is_not_stored_in_plaintext() {
    let w = World::new(3);
    let s = w.store();
    let p = pocket(1);
    s.put(p, b"SECRET-MARKER-0123456789").unwrap();
    for file in w.files(p, "data").into_iter().chain(w.files(p, "keys")) {
        let bytes = w.fs.read(&file).unwrap();
        assert!(
            !bytes.windows(13).any(|win| win == b"SECRET-MARKER"),
            "plaintext found on disk"
        );
    }
}

#[test]
fn tampering_is_detected() {
    let w = World::new(4);
    let s = w.store();
    let p = pocket(1);
    let r = s.put(p, b"payload").unwrap();
    let file = w.files(p, "data").remove(0);
    let bytes = w.fs.read(&file).unwrap();
    // The tag comes from an OS-random nonce, so its last byte is 0 one run in 256: flip it
    // rather than write a fixed value, or the "tampering" is sometimes a no-op.
    assert!(w.fs.overwrite_byte(&file, bytes.len() - 1, !*bytes.last().unwrap()));
    assert_eq!(s.get(p, r), Err(ChunkError::Corrupt));
}

#[test]
fn ciphertexts_cannot_be_swapped_between_chunks() {
    let world = World::new(5);
    let store = world.store();
    let pkt = pocket(1);
    let alpha = store.put(pkt, b"alpha").unwrap();
    let bravo = store.put(pkt, b"bravo").unwrap();
    // Swap both the chunk files and the key files of the two chunks.
    for files in [world.files(pkt, "data"), world.files(pkt, "keys")] {
        let first = world.fs.read(&files[0]).unwrap();
        let second = world.fs.read(&files[1]).unwrap();
        world.fs.write_atomic(&files[0], &second).unwrap();
        world.fs.write_atomic(&files[1], &first).unwrap();
    }
    assert_eq!(store.get(pkt, alpha), Err(ChunkError::Corrupt));
    assert_eq!(store.get(pkt, bravo), Err(ChunkError::Corrupt));
}

#[test]
fn put_is_durable_against_power_loss() {
    let w = World::new(6);
    let p = pocket(1);
    let r = w.store().put(p, b"durable").unwrap();
    w.fs.power_loss();
    assert_eq!(w.store().get(p, r).unwrap(), b"durable");
}

#[test]
fn shredding_defeats_a_restored_backup_of_the_key() {
    let w = World::new(7);
    let s = w.store();
    let p = pocket(1);
    let doomed = s.put(p, b"to be forgotten").unwrap();
    let kept = s.put(p, b"to be kept").unwrap();

    // The attacker's "backup": copies of the doomed chunk's files taken before the shred.
    let doomed_files: Vec<(PathBuf, Vec<u8>)> = w
        .files(p, "data")
        .into_iter()
        .chain(w.files(p, "keys"))
        .map(|f| (f.clone(), w.fs.read(&f).unwrap()))
        .collect();

    let report = s.shred(p, doomed).unwrap();
    assert!(report.removed);
    assert_eq!(report.rewrapped, 1, "the surviving chunk is re-wrapped");
    assert_eq!(
        w.keys.kek_versions(p).unwrap(),
        [report.kek_version],
        "older KEK versions destroyed"
    );
    assert_eq!(s.get(p, doomed), Err(ChunkError::Unavailable));
    assert_eq!(s.get(p, kept).unwrap(), b"to be kept");

    // Restore every pre-shred file the attacker kept, except those the kept chunk now owns.
    let kept_now: BTreeSet<PathBuf> = w.files(p, "data").into_iter().chain(w.files(p, "keys")).collect();
    for (path, bytes) in &doomed_files {
        if !kept_now.contains(path) {
            w.fs.write_atomic(path, bytes).unwrap();
        }
    }
    assert_eq!(
        s.get(p, doomed),
        Err(ChunkError::Unavailable),
        "the old KEK is gone: the backup is useless"
    );
    assert_eq!(
        s.shred(p, doomed).unwrap().kek_version,
        KekVersion(report.kek_version.0 + 1),
        "shred is idempotent"
    );
}

#[test]
fn crash_during_key_rotation_is_finished_on_open() {
    let w = World::new(8);
    let s = w.store();
    let p = pocket(1);
    let doomed = s.put(p, b"doomed").unwrap();
    let survivors: Vec<_> = (0..4)
        .map(|i| s.put(p, format!("survivor {i}").as_bytes()).unwrap())
        .collect();

    w.fs.fail_sync_after(2); // two directory syncs succeed; the first re-wrap's flush fails
    assert!(s.shred(p, doomed).is_err());
    assert_eq!(w.keys.kek_versions(p).unwrap().len(), 2, "rotation left unfinished");
    assert_eq!(s.get(p, doomed), Err(ChunkError::Unavailable), "already unreadable");

    w.fs.crash();
    drop(s);
    let s = w.store();
    assert_eq!(w.keys.kek_versions(p).unwrap().len(), 1, "open finished the rotation");
    for (i, r) in survivors.iter().enumerate() {
        assert_eq!(s.get(p, *r).unwrap(), format!("survivor {i}").as_bytes());
    }
}

#[test]
fn oversized_content_is_refused() {
    let w = World::new(9);
    let big = vec![0u8; 16 * 1024 * 1024 + 1];
    assert_eq!(w.store().put(pocket(1), &big), Err(ChunkError::TooLarge));
}

// ── Model-based property test ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum Op {
    Put(u8, u8),
    Get(u8, u8),
    Shred(u8, u8),
    Reopen,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        5 => (0u8..2, 0u8..6).prop_map(|(p, c)| Op::Put(p, c)),
        5 => (0u8..2, 0u8..6).prop_map(|(p, c)| Op::Get(p, c)),
        2 => (0u8..2, 0u8..6).prop_map(|(p, c)| Op::Shred(p, c)),
        1 => Just(Op::Reopen),
    ]
}

fn content(c: u8) -> Vec<u8> {
    format!("content #{c} ").repeat(usize::from(c) + 1).into_bytes()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// `get` returns exactly what was stored unless it was shredded afterwards, across reopens.
    #[test]
    fn behaves_like_a_map_with_shredding(seed in any::<u64>(), ops in prop::collection::vec(op(), 1..60)) {
        let w = World::new(seed);
        let mut s = w.store();
        let mut live: BTreeMap<(u8, u8), bool> = BTreeMap::new();
        for op in ops {
            match op {
                Op::Put(p, c) => {
                    s.put(pocket(u64::from(p)), &content(c)).unwrap();
                    live.insert((p, c), true);
                }
                Op::Get(p, c) => {
                    let r = s.reference(pocket(u64::from(p)), &content(c)).unwrap();
                    let got = s.get(pocket(u64::from(p)), r);
                    if live.get(&(p, c)).copied().unwrap_or(false) {
                        prop_assert_eq!(got.unwrap(), content(c));
                    } else {
                        prop_assert_eq!(got, Err(ChunkError::Unavailable));
                    }
                }
                Op::Shred(p, c) => {
                    let r = s.reference(pocket(u64::from(p)), &content(c)).unwrap();
                    s.shred(pocket(u64::from(p)), r).unwrap();
                    live.insert((p, c), false);
                    prop_assert_eq!(w.keys.kek_versions(pocket(u64::from(p))).unwrap().len(), 1);
                }
                Op::Reopen => {
                    w.fs.crash();
                    drop(s);
                    s = w.store();
                }
            }
        }
    }
}

#[test]
fn data_dir_layout_is_per_pocket() {
    let w = World::new(10);
    let s = w.store();
    s.put(pocket(1), b"x").unwrap();
    s.put(pocket(2), b"y").unwrap();
    let mut pockets = s.pockets().unwrap();
    pockets.sort();
    let mut expected = vec![pocket(1), pocket(2)];
    expected.sort();
    assert_eq!(pockets, expected);
    assert!(Path::new(CHUNKS_DIR).is_relative());
}
