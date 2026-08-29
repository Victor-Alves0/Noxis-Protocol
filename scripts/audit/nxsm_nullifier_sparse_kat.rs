//! Standalone external KAT generator for the published NXSM v1 candidate.
//!
//! Copy this program into the temporary Horizen audit clone before running it.
//! It uses the upstream P24 permutation and repeats only published NXSM
//! framing: re-derived IVs, BytePack3LE, deterministic sparse positions and
//! the NXSV v1 evidence layout.

use std::{collections::BTreeMap, convert::TryInto, fs};

use ark_ff::PrimeField;
use sha2::{Digest as _, Sha256};
use zkhash::{
    fields::babybear::FpBabyBear,
    poseidon2::{poseidon2::Poseidon2, poseidon2_instance_babybear::POSEIDON2_BABYBEAR_24_PARAMS},
};

const MODULUS: u32 = 2_013_265_921;
const RATE: usize = 15;
const WIDTH: usize = 24;
const DEPTH: usize = 512;
const CANDIDATE_ID: [u8; 32] = [
    0x17, 0x6a, 0x86, 0x8c, 0x85, 0x5f, 0x3c, 0xc5, 0x21, 0xbf, 0x15, 0x33, 0x89, 0xa8, 0x3e, 0x03,
    0xb4, 0xae, 0x26, 0xfc, 0x42, 0x6a, 0x33, 0x04, 0xca, 0xed, 0x59, 0xec, 0x74, 0x87, 0x9a, 0xf1,
];
const PARENT_NXPH_ID: [u8; 32] = [
    0x57, 0xe2, 0x27, 0xfd, 0x9d, 0x4c, 0xbc, 0xc6, 0x97, 0x19, 0x03, 0x72, 0xb8, 0x98, 0x3d, 0x2b,
    0xdc, 0x5e, 0x33, 0x94, 0x17, 0x75, 0x10, 0xee, 0xa5, 0x4f, 0x9f, 0x90, 0xf3, 0x63, 0x4b, 0x8e,
];
const IV_KDF_PREFIX: &[u8] = b"NOXIS/POSEIDON2-NULLIFIER-SPARSE-MERKLE-IV/V1\0";
const LEAF_LABEL: &[u8] = b"NOXIS/POSEIDON2-PRIVACY/V1/NULLIFIER-SPARSE-LEAF\0";
const NODE_LABEL: &[u8] = b"NOXIS/POSEIDON2-PRIVACY/V1/NULLIFIER-SPARSE-NODE\0";
const EMPTY_LABEL: &[u8] = b"NOXIS/POSEIDON2-PRIVACY/V1/NULLIFIER-SPARSE-EMPTY\0";

type Digest = [u32; 16];
type Nullifier = [u8; 64];

fn pack(input: &[u8]) -> Vec<u32> {
    input
        .chunks(3)
        .map(|chunk| {
            chunk.iter().enumerate().fold(0_u32, |word, (index, byte)| {
                word | (u32::from(*byte) << (index * 8))
            })
        })
        .collect()
}

fn hash(input: &[u8], iv: &[u32; 9]) -> Digest {
    hash_words(&pack(input), iv)
}

fn hash_words(packed: &[u32], iv: &[u32; 9]) -> Digest {
    let permutation = Poseidon2::new(&POSEIDON2_BABYBEAR_24_PARAMS);
    let mut state = vec![FpBabyBear::from(0_u64); WIDTH];
    for (lane, value) in iv.iter().enumerate() {
        state[RATE + lane] = FpBabyBear::from(u64::from(*value));
    }
    if packed.is_empty() {
        state = permutation.permutation(&state);
    } else {
        for block in packed.chunks(RATE) {
            for (lane, value) in block.iter().enumerate() {
                state[lane] += FpBabyBear::from(u64::from(*value));
            }
            state = permutation.permutation(&state);
        }
    }
    let mut digest = [0_u32; 16];
    for (lane, value) in state.iter().take(RATE).enumerate() {
        digest[lane] = value.into_bigint().as_ref()[0] as u32;
    }
    state = permutation.permutation(&state);
    digest[15] = state[0].into_bigint().as_ref()[0] as u32;
    digest
}

fn derive_iv(label: &[u8]) -> [u32; 9] {
    let mut output = [0_u32; 9];
    let mut accepted = 0;
    let mut counter = 0_u32;
    while accepted < output.len() {
        let mut hasher = Sha256::new();
        hasher.update(IV_KDF_PREFIX);
        hasher.update(PARENT_NXPH_ID);
        hasher.update(label);
        hasher.update(counter.to_be_bytes());
        for chunk in hasher.finalize().chunks_exact(4) {
            let candidate = u32::from_be_bytes(chunk.try_into().expect("SHA-256 word"));
            if candidate < MODULUS {
                output[accepted] = candidate;
                accepted += 1;
                if accepted == output.len() {
                    break;
                }
            }
        }
        counter = counter
            .checked_add(1)
            .expect("IV rejection sampling overflow");
    }
    output
}

fn digest_bytes(digest: Digest) -> [u8; 64] {
    let mut bytes = [0_u8; 64];
    for (index, value) in digest.into_iter().enumerate() {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

fn leaf(nullifier: Nullifier) -> Digest {
    hash(&nullifier, &derive_iv(LEAF_LABEL))
}

fn node(left: Digest, right: Digest) -> Digest {
    let mut bytes = [0_u8; 128];
    bytes[..64].copy_from_slice(&digest_bytes(left));
    bytes[64..].copy_from_slice(&digest_bytes(right));
    hash(&bytes, &derive_iv(NODE_LABEL))
}

fn empty_values() -> [Digest; DEPTH + 1] {
    let mut empty = [[0_u32; 16]; DEPTH + 1];
    empty[0] = hash(&[], &derive_iv(EMPTY_LABEL));
    for level in 1..=DEPTH {
        empty[level] = node(empty[level - 1], empty[level - 1]);
    }
    empty
}

fn sparse_root(nullifiers: &[Nullifier], empty: &[Digest; DEPTH + 1]) -> Digest {
    let mut nodes: BTreeMap<(usize, Nullifier), Digest> = BTreeMap::new();
    for nullifier in nullifiers {
        let mut key = *nullifier;
        let mut current = leaf(*nullifier);
        assert!(nodes.insert((0, key), current).is_none());
        for level in 0..DEPTH {
            let mut sibling_key = key;
            sibling_key[level / 8] ^= 1 << (level % 8);
            let sibling = nodes
                .get(&(level, sibling_key))
                .copied()
                .unwrap_or(empty[level]);
            current = if ((key[level / 8] >> (level % 8)) & 1) == 1 {
                node(sibling, current)
            } else {
                node(current, sibling)
            };
            key[level / 8] &= !(1 << (level % 8));
            nodes.insert((level + 1, key), current);
        }
    }
    nodes
        .get(&(DEPTH, [0; 64]))
        .copied()
        .unwrap_or(empty[DEPTH])
}

fn nullifier(elements: [u32; 16]) -> Nullifier {
    assert!(elements.iter().all(|element| *element < MODULUS));
    let mut bytes = [0_u8; 64];
    for (index, element) in elements.into_iter().enumerate() {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&element.to_le_bytes());
    }
    bytes
}

fn record(tag: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(6 + payload.len());
    bytes.extend_from_slice(&[tag, 0]);
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&payload);
    bytes
}

fn main() {
    let baseline = nullifier([1; 16]);
    let boundary = nullifier([
        0,
        1,
        MODULUS - 2,
        MODULUS - 1,
        42,
        65_535,
        65_536,
        16_909_060,
        987_654_321,
        5,
        6,
        7,
        8,
        9,
        10,
        MODULUS - 1,
    ]);
    let baseline_leaf = leaf(baseline);
    let boundary_leaf = leaf(boundary);
    let empty = empty_values();
    let mut records = Vec::new();

    for (nullifier, digest) in [(baseline, baseline_leaf), (boundary, boundary_leaf)] {
        let mut payload = Vec::with_capacity(128);
        payload.extend_from_slice(&nullifier);
        payload.extend_from_slice(&digest_bytes(digest));
        records.push(record(1, payload));
    }
    for (left, right) in [
        (baseline_leaf, boundary_leaf),
        (boundary_leaf, baseline_leaf),
    ] {
        let mut payload = Vec::with_capacity(192);
        payload.extend_from_slice(&digest_bytes(left));
        payload.extend_from_slice(&digest_bytes(right));
        payload.extend_from_slice(&digest_bytes(node(left, right)));
        records.push(record(2, payload));
    }
    for level in [0_usize, 1, 2, 32, 255, 511, 512] {
        let mut payload = Vec::with_capacity(66);
        payload.extend_from_slice(&(level as u16).to_be_bytes());
        payload.extend_from_slice(&digest_bytes(empty[level]));
        records.push(record(3, payload));
    }
    for mut set in [
        vec![],
        vec![baseline],
        vec![boundary],
        vec![baseline, boundary],
    ] {
        set.sort_unstable();
        let mut payload = Vec::with_capacity(1 + set.len() * 64 + 64);
        payload.push(set.len() as u8);
        for nullifier in &set {
            payload.extend_from_slice(nullifier);
        }
        payload.extend_from_slice(&digest_bytes(sparse_root(&set, &empty)));
        records.push(record(4, payload));
    }
    records.sort();
    assert_eq!(records.len(), 15);

    let mut corpus = Vec::new();
    corpus.extend_from_slice(b"NXSV");
    corpus.extend_from_slice(&1_u16.to_be_bytes());
    corpus.extend_from_slice(&0_u16.to_be_bytes());
    corpus.extend_from_slice(&CANDIDATE_ID);
    corpus.extend_from_slice(&1_u16.to_be_bytes());
    corpus.extend_from_slice(&(records.len() as u16).to_be_bytes());
    for record in records {
        corpus.extend_from_slice(&record);
    }
    fs::write("nxsm_nullifier_sparse_kat_v1.bin", corpus).expect("write external NXSM KAT corpus");
}
