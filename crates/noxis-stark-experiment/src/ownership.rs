//! One private ownership-binding relation for the frozen P24 candidates.
//!
//! This AIR is deliberately narrower than a transfer. It uses one private
//! witness to prove `H_ADDR(key)`, `H_NOTE(note_preimage)` and
//! `H_NULLIFIER(key || rho || note_commitment || position)` and
//! `H_LEAF(note_commitment)` together. The note's recipient bytes must encode
//! the `H_ADDR` digest, and the nullifier bytes must encode the same key, the
//! note's `rho`, the exact note digest and a private big-endian leaf position.
//! The nullifier and a depth-32 candidate-tree root are public. Every other
//! value, including the Merkle path, stays in the private trace.

use noxis_poseidon2_privacy_reference::Poseidon2P24PrivacyReference;
use noxis_poseidon2_reference::{BabyBearDigestV2, P24_WIDTH, Poseidon2P24Reference};
use noxis_tree_params::{
    CandidatePoseidon2P24ManifestV2, CandidatePoseidon2P24NoteDomainsManifestV1,
    Poseidon2P24NoteDomainV1, Poseidon2P24TreeDomainV1,
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{Proof, prove, verify};

use crate::{
    P24_ROUNDS, Poseidon2P24Air, StarkExperimentError, Val, make_hiding_config_with_log_blowup,
    matrix_expression, matrix_values, round_values,
};

const KEY_BYTES: usize = 32;
const NOTE_BYTES: usize = 178;
const POSITION_BYTES: usize = 4;
const DIGEST_LANES: usize = 16;
const DIGEST_BYTES: usize = DIGEST_LANES * 4;
const BITS_PER_BYTE: usize = 8;
const RATE: usize = 15;
const ADDR_ELEMENTS: usize = 11;
const NOTE_ELEMENTS: usize = 60;
const NULLIFIER_ELEMENTS: usize = 44;
const ADDR_PHASES: usize = 2;
const NOTE_PHASES: usize = 5;
const NULLIFIER_PHASES: usize = 4;
const LEAF_PHASES: usize = 3;
const NODE_PHASES_PER_HASH: usize = 4;
/// Candidate tree depth. This is deliberately the same 32-bit position that
/// is serialized into `H_NULLIFIER`, so no second, unbound direction witness
/// exists.
const MEMBERSHIP_DEPTH: usize = 32;
const NODE_PHASES: usize = NODE_PHASES_PER_HASH * MEMBERSHIP_DEPTH;
const TOTAL_PHASES: usize =
    ADDR_PHASES + NOTE_PHASES + NULLIFIER_PHASES + LEAF_PHASES + NODE_PHASES;
const TOTAL_STEPS: usize = TOTAL_PHASES * P24_ROUNDS;
/// `TOTAL_STEPS` needs 4260 rows; the FRI trace is a power of two.
const TRACE_ROWS: usize = 8192;
const ROUND_SELECTOR_OFFSET: usize = P24_WIDTH;
const PHASE_SELECTOR_OFFSET: usize = ROUND_SELECTOR_OFFSET + P24_ROUNDS;
const DONE_OFFSET: usize = PHASE_SELECTOR_OFFSET + TOTAL_PHASES;
const WITNESS_OFFSET: usize = DONE_OFFSET + 1;
const PROVER_STACK_BYTES: usize = 64 * 1024 * 1024;

const KEY_BYTES_OFFSET: usize = 0;
const KEY_BITS_OFFSET: usize = KEY_BYTES_OFFSET + KEY_BYTES;
const NOTE_BYTES_OFFSET: usize = KEY_BITS_OFFSET + (KEY_BYTES * BITS_PER_BYTE);
const NOTE_BITS_OFFSET: usize = NOTE_BYTES_OFFSET + NOTE_BYTES;
const POSITION_BYTES_OFFSET: usize = NOTE_BITS_OFFSET + (NOTE_BYTES * BITS_PER_BYTE);
const POSITION_BITS_OFFSET: usize = POSITION_BYTES_OFFSET + POSITION_BYTES;
const RECIPIENT_DIGEST_OFFSET: usize = POSITION_BITS_OFFSET + (POSITION_BYTES * BITS_PER_BYTE);
const NOTE_COMMITMENT_BYTES_OFFSET: usize = RECIPIENT_DIGEST_OFFSET + DIGEST_LANES;
const NOTE_COMMITMENT_BITS_OFFSET: usize = NOTE_COMMITMENT_BYTES_OFFSET + DIGEST_BYTES;
const NOTE_DIGEST_OFFSET: usize = NOTE_COMMITMENT_BITS_OFFSET + (DIGEST_BYTES * BITS_PER_BYTE);
const TREE_LEAF_DIGEST_OFFSET: usize = NOTE_DIGEST_OFFSET + DIGEST_LANES;
const MERKLE_SIBLINGS_OFFSET: usize = TREE_LEAF_DIGEST_OFFSET + DIGEST_LANES;
const MERKLE_INTERMEDIATE_OFFSET: usize =
    MERKLE_SIBLINGS_OFFSET + (MEMBERSHIP_DEPTH * DIGEST_LANES);
const WITNESS_ELEMENTS: usize =
    MERKLE_INTERMEDIATE_OFFSET + ((MEMBERSHIP_DEPTH - 1) * DIGEST_LANES);
const TRACE_WIDTH: usize = WITNESS_OFFSET + WITNESS_ELEMENTS;

const ADDR_BLOCK_PHASE: usize = 0;
const ADDR_SQUEEZE_PHASE: usize = 1;
const NOTE_FIRST_PHASE: usize = ADDR_PHASES;
const NOTE_LAST_BLOCK_PHASE: usize = NOTE_FIRST_PHASE + 3;
const NOTE_SQUEEZE_PHASE: usize = NOTE_FIRST_PHASE + 4;
const NULLIFIER_FIRST_PHASE: usize = ADDR_PHASES + NOTE_PHASES;
const NULLIFIER_LAST_BLOCK_PHASE: usize = NULLIFIER_FIRST_PHASE + 2;
const NULLIFIER_SQUEEZE_PHASE: usize = NULLIFIER_FIRST_PHASE + 3;
const LEAF_FIRST_PHASE: usize = NULLIFIER_SQUEEZE_PHASE + 1;
const LEAF_SECOND_PHASE: usize = LEAF_FIRST_PHASE + 1;
const LEAF_SQUEEZE_PHASE: usize = LEAF_SECOND_PHASE + 1;
const NODE_FIRST_PHASE: usize = LEAF_SQUEEZE_PHASE + 1;

const fn node_phase(level: usize, phase_in_hash: usize) -> usize {
    NODE_FIRST_PHASE + (level * NODE_PHASES_PER_HASH) + phase_in_hash
}

const NOTE_VERSION_OFFSET: usize = 0;
const NOTE_RECIPIENT_OFFSET: usize = 50;
const NOTE_RHO_OFFSET: usize = 114;

/// Public result after an independently verified ownership-binding proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Poseidon2P24OwnershipExperimentResult {
    /// One of two public 16-element values: the deterministic nullifier.
    pub nullifier: BabyBearDigestV2,
    /// Public root after 32 private ordered candidate node hashes.
    pub root: BabyBearDigestV2,
    /// Number of rows in the fixed private trace.
    pub trace_rows: usize,
}

/// In-memory hiding-FRI proof for the private ownership relation.
///
/// The Plonky3 proof remains deliberately opaque. This separates a local
/// prover from a local verifier without inventing a network or storage format
/// before the candidate, proof parameters and serialization profile are
/// selected and independently reviewed.
pub struct Poseidon2P24OwnershipProof {
    /// The exact local Plonky3 configuration that committed to this proof.
    /// It remains opaque together with the proof and is not a selected
    /// verifier profile or transferable key material.
    config: crate::Config,
    proof: Proof<crate::Config>,
    public_result: Poseidon2P24OwnershipExperimentResult,
}

impl Poseidon2P24OwnershipProof {
    /// Returns the public nullifier, candidate root and fixed trace shape
    /// bound by this proof.
    pub const fn public_result(&self) -> &Poseidon2P24OwnershipExperimentResult {
        &self.public_result
    }
}

#[derive(Clone, Copy)]
struct OwnershipTraceWitness {
    nullifier_key: [u8; KEY_BYTES],
    note_preimage: [u8; NOTE_BYTES],
    leaf_position: u32,
    recipient_commitment: BabyBearDigestV2,
    note_commitment: BabyBearDigestV2,
    tree_leaf: BabyBearDigestV2,
    siblings: [BabyBearDigestV2; MEMBERSHIP_DEPTH],
    /// The 31 non-root path values; all remain private.
    intermediates: [BabyBearDigestV2; MEMBERSHIP_DEPTH - 1],
}

/// AIR for one key-to-note-to-nullifier-to-leaf ownership binding.
#[derive(Clone, Debug)]
struct Poseidon2P24OwnershipAir {
    permutation: Poseidon2P24Air,
    addr_iv: [u32; 9],
    note_iv: [u32; 9],
    nullifier_iv: [u32; 9],
    leaf_iv: [u32; 9],
    node_iv: [u32; 9],
}

impl Poseidon2P24OwnershipAir {
    fn from_reference(reference: &Poseidon2P24Reference) -> Result<Self, StarkExperimentError> {
        let manifest = CandidatePoseidon2P24NoteDomainsManifestV1::new();
        let tree_manifest = CandidatePoseidon2P24ManifestV2::new();
        Ok(Self {
            permutation: Poseidon2P24Air::from_reference(reference),
            addr_iv: manifest.iv(Poseidon2P24NoteDomainV1::Addr)?,
            note_iv: manifest.iv(Poseidon2P24NoteDomainV1::Note)?,
            nullifier_iv: manifest.iv(Poseidon2P24NoteDomainV1::Nullifier)?,
            leaf_iv: tree_manifest.iv(Poseidon2P24TreeDomainV1::Leaf)?,
            node_iv: tree_manifest.iv(Poseidon2P24TreeDomainV1::Node)?,
        })
    }

    fn initial_state_expression<AB: AirBuilder>(
        &self,
        witness: &[AB::Var],
        domain: Poseidon2P24NoteDomainV1,
    ) -> Vec<AB::Expr> {
        let iv = match domain {
            Poseidon2P24NoteDomainV1::Addr => self.addr_iv,
            Poseidon2P24NoteDomainV1::Note => self.note_iv,
            Poseidon2P24NoteDomainV1::Nullifier => self.nullifier_iv,
        };
        let raw = (0..P24_WIDTH)
            .map(|lane| {
                if lane < RATE {
                    match domain {
                        Poseidon2P24NoteDomainV1::Addr if lane < ADDR_ELEMENTS => {
                            self.key_packed_expression::<AB>(witness, lane)
                        }
                        Poseidon2P24NoteDomainV1::Addr => AB::Expr::ZERO,
                        Poseidon2P24NoteDomainV1::Note => {
                            self.note_packed_expression::<AB>(witness, lane)
                        }
                        Poseidon2P24NoteDomainV1::Nullifier => {
                            self.nullifier_packed_expression::<AB>(witness, lane)
                        }
                    }
                } else {
                    AB::Expr::from_u32(iv[lane - RATE])
                }
            })
            .collect::<Vec<AB::Expr>>();
        matrix_expression::<AB>(&self.permutation.external_matrix, &raw)
    }

    fn initial_leaf_state_expression<AB: AirBuilder>(&self, witness: &[AB::Var]) -> Vec<AB::Expr> {
        let raw = (0..P24_WIDTH)
            .map(|lane| {
                if lane < RATE {
                    witness[NOTE_DIGEST_OFFSET + lane].into()
                } else {
                    AB::Expr::from_u32(self.leaf_iv[lane - RATE])
                }
            })
            .collect::<Vec<AB::Expr>>();
        matrix_expression::<AB>(&self.permutation.external_matrix, &raw)
    }

    fn initial_node_state_expression<AB: AirBuilder>(
        &self,
        witness: &[AB::Var],
        node_index: usize,
    ) -> Vec<AB::Expr> {
        let raw = (0..P24_WIDTH)
            .map(|lane| {
                if lane < RATE {
                    self.node_input_expression::<AB>(witness, node_index, lane)
                } else {
                    AB::Expr::from_u32(self.node_iv[lane - RATE])
                }
            })
            .collect::<Vec<AB::Expr>>();
        matrix_expression::<AB>(&self.permutation.external_matrix, &raw)
    }

    fn node_input_expression<AB: AirBuilder>(
        &self,
        witness: &[AB::Var],
        node_index: usize,
        input_index: usize,
    ) -> AB::Expr {
        let lane = input_index % DIGEST_LANES;
        let current: AB::Expr = if node_index == 0 {
            witness[TREE_LEAF_DIGEST_OFFSET + lane].into()
        } else {
            witness[MERKLE_INTERMEDIATE_OFFSET + ((node_index - 1) * DIGEST_LANES) + lane].into()
        };
        let sibling: AB::Expr =
            witness[MERKLE_SIBLINGS_OFFSET + (node_index * DIGEST_LANES) + lane].into();
        let direction = self.position_direction_expression::<AB>(witness, node_index);
        if input_index < DIGEST_LANES {
            current.clone() + direction.clone() * (sibling.clone() - current)
        } else {
            sibling.clone() + direction * (current - sibling)
        }
    }

    fn position_direction_expression<AB: AirBuilder>(
        &self,
        witness: &[AB::Var],
        level: usize,
    ) -> AB::Expr {
        let byte_index = POSITION_BYTES - 1 - (level / BITS_PER_BYTE);
        witness[POSITION_BITS_OFFSET + (byte_index * BITS_PER_BYTE) + (level % BITS_PER_BYTE)]
            .into()
    }

    fn key_packed_expression<AB: AirBuilder>(
        &self,
        witness: &[AB::Var],
        packed_index: usize,
    ) -> AB::Expr {
        (0..3).fold(AB::Expr::ZERO, |packed, byte_offset| {
            let byte_index = (packed_index * 3) + byte_offset;
            if byte_index < KEY_BYTES {
                packed
                    + AB::Expr::from(witness[KEY_BYTES_OFFSET + byte_index])
                        * AB::F::from_u32(1_u32 << (byte_offset * 8))
            } else {
                packed
            }
        })
    }

    fn note_packed_expression<AB: AirBuilder>(
        &self,
        witness: &[AB::Var],
        packed_index: usize,
    ) -> AB::Expr {
        (0..3).fold(AB::Expr::ZERO, |packed, byte_offset| {
            let byte_index = (packed_index * 3) + byte_offset;
            if byte_index < NOTE_BYTES {
                packed
                    + AB::Expr::from(witness[NOTE_BYTES_OFFSET + byte_index])
                        * AB::F::from_u32(1_u32 << (byte_offset * 8))
            } else {
                packed
            }
        })
    }

    fn nullifier_packed_expression<AB: AirBuilder>(
        &self,
        witness: &[AB::Var],
        packed_index: usize,
    ) -> AB::Expr {
        if packed_index >= NULLIFIER_ELEMENTS {
            return AB::Expr::ZERO;
        }
        self.packed_expression::<AB>(packed_index, |byte_index| {
            self.nullifier_byte_expression::<AB>(witness, byte_index)
        })
    }

    fn packed_expression<AB: AirBuilder>(
        &self,
        packed_index: usize,
        byte: impl Fn(usize) -> AB::Expr,
    ) -> AB::Expr {
        (0..3).fold(AB::Expr::ZERO, |packed, byte_offset| {
            let byte_index = (packed_index * 3) + byte_offset;
            packed + byte(byte_index) * AB::F::from_u32(1_u32 << (byte_offset * 8))
        })
    }

    fn nullifier_byte_expression<AB: AirBuilder>(
        &self,
        witness: &[AB::Var],
        byte_index: usize,
    ) -> AB::Expr {
        match byte_index {
            0..32 => witness[KEY_BYTES_OFFSET + byte_index].into(),
            32..64 => witness[NOTE_BYTES_OFFSET + NOTE_RHO_OFFSET + (byte_index - 32)].into(),
            64..128 => witness[NOTE_COMMITMENT_BYTES_OFFSET + (byte_index - 64)].into(),
            128..132 => witness[POSITION_BYTES_OFFSET + (byte_index - 128)].into(),
            _ => unreachable!("H_NULLIFIER has exactly 132 input bytes"),
        }
    }

    fn assert_private_byte_group<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        witness: &[AB::Var],
        bytes_offset: usize,
        bits_offset: usize,
        byte_count: usize,
    ) {
        for byte_index in 0..byte_count {
            let mut recomposed: AB::Expr = AB::Expr::ZERO;
            for bit_index in 0..BITS_PER_BYTE {
                let bit: AB::Expr =
                    witness[bits_offset + (byte_index * BITS_PER_BYTE) + bit_index].into();
                builder.assert_zero(bit.clone() * (bit.clone() - AB::Expr::ONE));
                recomposed += bit * AB::F::from_u32(1_u32 << bit_index);
            }
            builder.assert_eq(witness[bytes_offset + byte_index], recomposed);
        }
    }

    fn assert_static_witness<AB: AirBuilder>(&self, builder: &mut AB, witness: &[AB::Var]) {
        self.assert_private_byte_group::<AB>(
            builder,
            witness,
            KEY_BYTES_OFFSET,
            KEY_BITS_OFFSET,
            KEY_BYTES,
        );
        self.assert_private_byte_group::<AB>(
            builder,
            witness,
            NOTE_BYTES_OFFSET,
            NOTE_BITS_OFFSET,
            NOTE_BYTES,
        );
        self.assert_private_byte_group::<AB>(
            builder,
            witness,
            POSITION_BYTES_OFFSET,
            POSITION_BITS_OFFSET,
            POSITION_BYTES,
        );
        self.assert_private_byte_group::<AB>(
            builder,
            witness,
            NOTE_COMMITMENT_BYTES_OFFSET,
            NOTE_COMMITMENT_BITS_OFFSET,
            DIGEST_BYTES,
        );

        builder.assert_eq(
            witness[NOTE_BYTES_OFFSET + NOTE_VERSION_OFFSET],
            AB::Expr::ZERO,
        );
        builder.assert_eq(
            witness[NOTE_BYTES_OFFSET + NOTE_VERSION_OFFSET + 1],
            AB::Expr::ONE,
        );
        for lane in 0..DIGEST_LANES {
            let recipient = self.four_bytes_expression::<AB>(
                witness,
                NOTE_BYTES_OFFSET + NOTE_RECIPIENT_OFFSET + (lane * 4),
            );
            builder.assert_eq(witness[RECIPIENT_DIGEST_OFFSET + lane], recipient);

            let commitment = self
                .four_bytes_expression::<AB>(witness, NOTE_COMMITMENT_BYTES_OFFSET + (lane * 4));
            builder.assert_eq(witness[NOTE_DIGEST_OFFSET + lane], commitment);
        }
    }

    fn four_bytes_expression<AB: AirBuilder>(
        &self,
        witness: &[AB::Var],
        offset: usize,
    ) -> AB::Expr {
        (0..4).fold(AB::Expr::ZERO, |value, byte_offset| {
            value
                + AB::Expr::from(witness[offset + byte_offset])
                    * AB::F::from_u32(1_u32 << (byte_offset * 8))
        })
    }
}

impl<F> BaseAir<F> for Poseidon2P24OwnershipAir {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }

    fn num_public_values(&self) -> usize {
        DIGEST_LANES * 2
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        // Compact phase selectors multiply the ordered-node input (which
        // already contains the private position direction) through the P24
        // transition. This matches the degree budget of the standalone
        // depth-32 Merkle-path AIR.
        Some(10)
    }
}

impl<AB: AirBuilder> Air<AB> for Poseidon2P24OwnershipAir {
    fn eval(&self, builder: &mut AB) {
        let public_values = builder.public_values().to_vec();
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let local_state = &local[..P24_WIDTH];
        let next_state = &next[..P24_WIDTH];
        let round_selectors = &local[ROUND_SELECTOR_OFFSET..ROUND_SELECTOR_OFFSET + P24_ROUNDS];
        let next_round_selectors = &next[ROUND_SELECTOR_OFFSET..ROUND_SELECTOR_OFFSET + P24_ROUNDS];
        let phase_selectors = &local[PHASE_SELECTOR_OFFSET..PHASE_SELECTOR_OFFSET + TOTAL_PHASES];
        let next_phase_selectors =
            &next[PHASE_SELECTOR_OFFSET..PHASE_SELECTOR_OFFSET + TOTAL_PHASES];
        let done = local[DONE_OFFSET];
        let next_done = next[DONE_OFFSET];
        let witness = &local[WITNESS_OFFSET..];
        let next_witness = &next[WITNESS_OFFSET..];

        self.assert_static_witness::<AB>(builder, witness);
        for lane in 0..WITNESS_ELEMENTS {
            builder
                .when_transition()
                .assert_eq(next_witness[lane], witness[lane]);
        }

        let initial_addr =
            self.initial_state_expression::<AB>(witness, Poseidon2P24NoteDomainV1::Addr);
        for lane in 0..P24_WIDTH {
            builder
                .when_first_row()
                .assert_eq(local_state[lane], initial_addr[lane].clone());
        }
        for (selector, round_selector) in round_selectors.iter().enumerate() {
            builder.when_first_row().assert_eq(
                *round_selector,
                AB::F::from_u8(if selector == 0 { 1 } else { 0 }),
            );
        }
        for (phase, phase_selector) in phase_selectors.iter().enumerate() {
            builder.when_first_row().assert_eq(
                *phase_selector,
                AB::F::from_u8(if phase == 0 { 1 } else { 0 }),
            );
        }
        builder.when_first_row().assert_eq(done, AB::F::ZERO);
        let done_expr: AB::Expr = done.into();
        builder.assert_zero(done_expr.clone() * (done_expr.clone() - AB::Expr::ONE));

        let terminal: AB::Expr =
            round_selectors[P24_ROUNDS - 1] * phase_selectors[TOTAL_PHASES - 1];
        builder.when_transition().assert_eq(
            next_done,
            done_expr.clone() + terminal * (AB::Expr::ONE - done_expr.clone()),
        );
        builder.when_transition().assert_eq(
            next_round_selectors[0],
            round_selectors[P24_ROUNDS - 1]
                * (AB::Expr::ONE - AB::Expr::from(phase_selectors[TOTAL_PHASES - 1])),
        );
        for selector in 1..P24_ROUNDS - 1 {
            builder.when_transition().assert_eq(
                next_round_selectors[selector],
                round_selectors[selector - 1],
            );
        }
        builder.when_transition().assert_eq(
            next_round_selectors[P24_ROUNDS - 1],
            round_selectors[P24_ROUNDS - 2]
                + (round_selectors[P24_ROUNDS - 1] * phase_selectors[TOTAL_PHASES - 1]),
        );
        for phase in 0..TOTAL_PHASES - 1 {
            let previous: AB::Expr = if phase == 0 {
                AB::Expr::ZERO
            } else {
                phase_selectors[phase - 1].into()
            };
            builder.when_transition().assert_eq(
                next_phase_selectors[phase],
                phase_selectors[phase]
                    + round_selectors[P24_ROUNDS - 1]
                        * (previous - AB::Expr::from(phase_selectors[phase])),
            );
        }
        builder.when_transition().assert_eq(
            next_phase_selectors[TOTAL_PHASES - 1],
            phase_selectors[TOTAL_PHASES - 1]
                + (round_selectors[P24_ROUNDS - 1] * phase_selectors[TOTAL_PHASES - 2]),
        );

        let round_states: Vec<Vec<AB::Expr>> = (0..P24_ROUNDS)
            .map(|round| self.permutation.round_expression::<AB>(local_state, round))
            .collect();
        let phase_completions: Vec<Vec<AB::Expr>> = (0..TOTAL_PHASES)
            .map(|phase| {
                self.phase_transition_target::<AB>(phase, &round_states[P24_ROUNDS - 1], witness)
            })
            .collect();
        for lane in 0..P24_WIDTH {
            let mut final_round_target: AB::Expr = local_state[lane].into();
            for phase in 0..TOTAL_PHASES {
                final_round_target += phase_selectors[phase]
                    * (phase_completions[phase][lane].clone() - local_state[lane]);
            }
            let mut expected_next: AB::Expr = local_state[lane].into();
            for round in 0..P24_ROUNDS {
                let target = if round + 1 == P24_ROUNDS {
                    final_round_target.clone()
                } else {
                    round_states[round][lane].clone()
                };
                expected_next += (AB::Expr::ONE - done_expr.clone())
                    * round_selectors[round]
                    * (target - local_state[lane]);
            }
            builder
                .when_transition()
                .assert_eq(next_state[lane], expected_next);
        }

        let recipient_output = witness
            [RECIPIENT_DIGEST_OFFSET..RECIPIENT_DIGEST_OFFSET + DIGEST_LANES]
            .iter()
            .copied()
            .map(Into::into)
            .collect::<Vec<AB::Expr>>();
        self.assert_digest_at_phase::<AB>(
            builder,
            round_selectors[P24_ROUNDS - 1],
            phase_selectors,
            done,
            &round_states[P24_ROUNDS - 1],
            ADDR_BLOCK_PHASE,
            ADDR_SQUEEZE_PHASE,
            &recipient_output,
        );
        let note_output = witness[NOTE_DIGEST_OFFSET..NOTE_DIGEST_OFFSET + DIGEST_LANES]
            .iter()
            .copied()
            .map(Into::into)
            .collect::<Vec<AB::Expr>>();
        self.assert_digest_at_phase::<AB>(
            builder,
            round_selectors[P24_ROUNDS - 1],
            phase_selectors,
            done,
            &round_states[P24_ROUNDS - 1],
            NOTE_LAST_BLOCK_PHASE,
            NOTE_SQUEEZE_PHASE,
            &note_output,
        );
        let public_nullifier = public_values[..DIGEST_LANES]
            .iter()
            .copied()
            .map(Into::into)
            .collect::<Vec<AB::Expr>>();
        self.assert_digest_at_phase::<AB>(
            builder,
            round_selectors[P24_ROUNDS - 1],
            phase_selectors,
            done,
            &round_states[P24_ROUNDS - 1],
            NULLIFIER_LAST_BLOCK_PHASE,
            NULLIFIER_SQUEEZE_PHASE,
            &public_nullifier,
        );
        let tree_leaf_output = witness
            [TREE_LEAF_DIGEST_OFFSET..TREE_LEAF_DIGEST_OFFSET + DIGEST_LANES]
            .iter()
            .copied()
            .map(Into::into)
            .collect::<Vec<AB::Expr>>();
        self.assert_digest_at_phase::<AB>(
            builder,
            round_selectors[P24_ROUNDS - 1],
            phase_selectors,
            done,
            &round_states[P24_ROUNDS - 1],
            LEAF_SECOND_PHASE,
            LEAF_SQUEEZE_PHASE,
            &tree_leaf_output,
        );
        for level in 0..MEMBERSHIP_DEPTH {
            let output = if level + 1 == MEMBERSHIP_DEPTH {
                public_values[DIGEST_LANES..]
                    .iter()
                    .copied()
                    .map(Into::into)
                    .collect::<Vec<AB::Expr>>()
            } else {
                witness[MERKLE_INTERMEDIATE_OFFSET + (level * DIGEST_LANES)
                    ..MERKLE_INTERMEDIATE_OFFSET + ((level + 1) * DIGEST_LANES)]
                    .iter()
                    .copied()
                    .map(Into::into)
                    .collect::<Vec<AB::Expr>>()
            };
            self.assert_digest_at_phase::<AB>(
                builder,
                round_selectors[P24_ROUNDS - 1],
                phase_selectors,
                done,
                &round_states[P24_ROUNDS - 1],
                node_phase(level, 2),
                node_phase(level, 3),
                &output,
            );
        }
    }
}

impl Poseidon2P24OwnershipAir {
    fn phase_transition_target<AB: AirBuilder>(
        &self,
        phase: usize,
        round_state: &[AB::Expr],
        witness: &[AB::Var],
    ) -> Vec<AB::Expr> {
        if phase >= NODE_FIRST_PHASE {
            let node_phase_index = phase - NODE_FIRST_PHASE;
            let level = node_phase_index / NODE_PHASES_PER_HASH;
            return match node_phase_index % NODE_PHASES_PER_HASH {
                0 => self.node_absorb_expression::<AB>(round_state, witness, level, 15),
                1 => self.node_absorb_expression::<AB>(round_state, witness, level, 30),
                2 => matrix_expression::<AB>(&self.permutation.external_matrix, round_state),
                3 if level + 1 < MEMBERSHIP_DEPTH => {
                    self.initial_node_state_expression::<AB>(witness, level + 1)
                }
                3 => round_state.to_vec(),
                _ => unreachable!("node phase is reduced modulo its fixed permutation count"),
            };
        }
        match phase {
            ADDR_BLOCK_PHASE
            | NOTE_LAST_BLOCK_PHASE
            | NULLIFIER_LAST_BLOCK_PHASE
            | LEAF_SECOND_PHASE => {
                matrix_expression::<AB>(&self.permutation.external_matrix, round_state)
            }
            ADDR_SQUEEZE_PHASE => {
                self.initial_state_expression::<AB>(witness, Poseidon2P24NoteDomainV1::Note)
            }
            NOTE_SQUEEZE_PHASE => {
                self.initial_state_expression::<AB>(witness, Poseidon2P24NoteDomainV1::Nullifier)
            }
            NOTE_FIRST_PHASE..=4 => {
                let next_block = phase - NOTE_FIRST_PHASE + 1;
                self.absorb_then_permute_expression::<AB>(
                    round_state,
                    |packed_index| self.note_packed_expression::<AB>(witness, packed_index),
                    next_block,
                )
            }
            NULLIFIER_FIRST_PHASE..=8 => {
                let next_block = phase - NULLIFIER_FIRST_PHASE + 1;
                self.absorb_then_permute_expression::<AB>(
                    round_state,
                    |packed_index| self.nullifier_packed_expression::<AB>(witness, packed_index),
                    next_block,
                )
            }
            NULLIFIER_SQUEEZE_PHASE => self.initial_leaf_state_expression::<AB>(witness),
            LEAF_FIRST_PHASE => self.leaf_second_block_expression::<AB>(round_state, witness),
            LEAF_SQUEEZE_PHASE => self.initial_node_state_expression::<AB>(witness, 0),
            _ => unreachable!("every P24 ownership phase is fixed"),
        }
    }

    fn absorb_then_permute_expression<AB: AirBuilder>(
        &self,
        round_state: &[AB::Expr],
        packed: impl Fn(usize) -> AB::Expr,
        block: usize,
    ) -> Vec<AB::Expr> {
        let absorbed = (0..P24_WIDTH)
            .map(|state_lane| {
                if state_lane < RATE {
                    round_state[state_lane].clone() + packed((block * RATE) + state_lane)
                } else {
                    round_state[state_lane].clone()
                }
            })
            .collect::<Vec<AB::Expr>>();
        matrix_expression::<AB>(&self.permutation.external_matrix, &absorbed)
    }

    fn leaf_second_block_expression<AB: AirBuilder>(
        &self,
        round_state: &[AB::Expr],
        witness: &[AB::Var],
    ) -> Vec<AB::Expr> {
        let mut absorbed = round_state.to_vec();
        absorbed[0] = absorbed[0].clone() + witness[NOTE_DIGEST_OFFSET + 15];
        matrix_expression::<AB>(&self.permutation.external_matrix, &absorbed)
    }

    fn node_absorb_expression<AB: AirBuilder>(
        &self,
        round_state: &[AB::Expr],
        witness: &[AB::Var],
        node_index: usize,
        input_start: usize,
    ) -> Vec<AB::Expr> {
        let absorbed = (0..P24_WIDTH)
            .map(|state_lane| {
                if state_lane < RATE && input_start + state_lane < DIGEST_LANES * 2 {
                    round_state[state_lane].clone()
                        + self.node_input_expression::<AB>(
                            witness,
                            node_index,
                            input_start + state_lane,
                        )
                } else {
                    round_state[state_lane].clone()
                }
            })
            .collect::<Vec<AB::Expr>>();
        matrix_expression::<AB>(&self.permutation.external_matrix, &absorbed)
    }

    #[allow(clippy::too_many_arguments)] // AIR evaluation context is intentionally explicit.
    fn assert_digest_at_phase<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        final_round_selector: AB::Var,
        phase_selectors: &[AB::Var],
        done: AB::Var,
        final_round_state: &[AB::Expr],
        final_block_phase: usize,
        squeeze_phase: usize,
        digest: &[AB::Expr],
    ) {
        let active: AB::Expr = AB::Expr::ONE - AB::Expr::from(done);
        let first_squeeze_selector: AB::Expr =
            active.clone() * final_round_selector * phase_selectors[final_block_phase];
        for lane in 0..RATE {
            builder.assert_zero(
                first_squeeze_selector.clone()
                    * (final_round_state[lane].clone() - digest[lane].clone()),
            );
        }
        let final_squeeze_selector: AB::Expr =
            active * final_round_selector * phase_selectors[squeeze_phase];
        builder.assert_zero(
            final_squeeze_selector * (final_round_state[0].clone() - digest[15].clone()),
        );
    }
}

/// Produces and independently verifies a hiding-FRI STARK that binds one
/// private key, canonical note preimage and private leaf position to one public
/// nullifier and one public candidate depth-32 tree root.
///
/// This is not a spend authorization: it does not yet prove nullifier absence,
/// state-anchor acceptance, asset/value rules or ledger acceptance.
pub fn prove_and_verify_p24_note_ownership(
    nullifier_key: [u8; KEY_BYTES],
    note_preimage: [u8; NOTE_BYTES],
    leaf_position: u32,
) -> Result<Poseidon2P24OwnershipExperimentResult, StarkExperimentError> {
    prove_and_verify_p24_note_ownership_path32(
        nullifier_key,
        note_preimage,
        leaf_position,
        synthetic_merkle_siblings(),
    )
}

/// Produces one ownership proof with 32 private ordered Merkle steps. The
/// direction at every level is derived from the corresponding bit of the same
/// private position serialized in `H_NULLIFIER`; only the nullifier and root
/// are public. Call [`verify_p24_note_ownership_proof`] in a verifier context.
pub fn prove_p24_note_ownership_path32(
    nullifier_key: [u8; KEY_BYTES],
    note_preimage: [u8; NOTE_BYTES],
    leaf_position: u32,
    siblings: [BabyBearDigestV2; MEMBERSHIP_DEPTH],
) -> Result<Poseidon2P24OwnershipProof, StarkExperimentError> {
    let reference = Poseidon2P24Reference::load_candidate()?;
    let private_reference = Poseidon2P24PrivacyReference::load_candidate()?;
    let recipient_commitment = private_reference.hash_addr(&nullifier_key)?;
    let note_commitment = private_reference.hash_note(&note_preimage)?;
    let tree_leaf = reference.leaf(note_commitment)?;
    let directions: [bool; MEMBERSHIP_DEPTH] =
        core::array::from_fn(|level| ((leaf_position >> level) & 1) == 1);
    let mut current = tree_leaf;
    let mut intermediates = [[0_u32; DIGEST_LANES]; MEMBERSHIP_DEPTH - 1];
    for level in 0..MEMBERSHIP_DEPTH {
        current = candidate_node(&reference, current, siblings[level], directions[level])?;
        if level + 1 < MEMBERSHIP_DEPTH {
            intermediates[level] = current;
        }
    }
    let root = current;
    let nullifier_preimage =
        make_nullifier_preimage(nullifier_key, note_preimage, note_commitment, leaf_position);
    let nullifier = private_reference.hash_nullifier_preimage(&nullifier_preimage)?;
    let air = Poseidon2P24OwnershipAir::from_reference(&reference)?;
    let witness = OwnershipTraceWitness {
        nullifier_key,
        note_preimage,
        leaf_position,
        recipient_commitment,
        note_commitment,
        tree_leaf,
        siblings,
        intermediates,
    };
    let trace = build_ownership_trace(&air, &witness);
    let public_values = nullifier
        .into_iter()
        .chain(root)
        .map(Val::from_u32)
        .collect::<Vec<_>>();
    // The composed depth-32 relation builds a substantially larger AIR than
    // the shallow ownership experiment. Keep the prover on the same explicit
    // 64 MiB stack budget as the standalone full-depth path prover.
    let prover = std::thread::Builder::new()
        .name("noxis-p24-ownership-path32-prover".to_owned())
        .stack_size(PROVER_STACK_BYTES)
        .spawn(move || {
            // The composed AIR has the same private direction/input degree as
            // the full-depth path AIR, which requires a four-bit FRI blowup.
            // The generic three-bit research configuration is insufficient
            // here and yields an invalid quotient opening at verification.
            let config = make_hiding_config_with_log_blowup(4);
            let proof = prove(&config, &air, trace, &public_values);
            Ok(Poseidon2P24OwnershipProof {
                config,
                proof,
                public_result: Poseidon2P24OwnershipExperimentResult {
                    nullifier,
                    root,
                    trace_rows: TRACE_ROWS,
                },
            })
        })
        .map_err(|_| StarkExperimentError::ProverThreadFailed)?;
    prover
        .join()
        .map_err(|_| StarkExperimentError::ProverThreadFailed)?
}

/// Independently verifies a locally held ownership proof against exactly the
/// public nullifier and depth-32 root stored with it.
///
/// The proof type has no encoder by design: it is not a transaction artifact,
/// wire format or selected verifier integration.
pub fn verify_p24_note_ownership_proof(
    ownership_proof: &Poseidon2P24OwnershipProof,
) -> Result<Poseidon2P24OwnershipExperimentResult, StarkExperimentError> {
    let reference = Poseidon2P24Reference::load_candidate()?;
    let air = Poseidon2P24OwnershipAir::from_reference(&reference)?;
    let public_values = ownership_proof
        .public_result
        .nullifier
        .into_iter()
        .chain(ownership_proof.public_result.root)
        .map(Val::from_u32)
        .collect::<Vec<_>>();
    verify(
        &ownership_proof.config,
        &air,
        &ownership_proof.proof,
        &public_values,
    )
    .map_err(|_| StarkExperimentError::VerificationFailed)?;
    Ok(ownership_proof.public_result.clone())
}

/// Compatibility convenience entry point that produces and verifies a
/// depth-32 ownership proof in one process.
pub fn prove_and_verify_p24_note_ownership_path32(
    nullifier_key: [u8; KEY_BYTES],
    note_preimage: [u8; NOTE_BYTES],
    leaf_position: u32,
    siblings: [BabyBearDigestV2; MEMBERSHIP_DEPTH],
) -> Result<Poseidon2P24OwnershipExperimentResult, StarkExperimentError> {
    let proof =
        prove_p24_note_ownership_path32(nullifier_key, note_preimage, leaf_position, siblings)?;
    verify_p24_note_ownership_proof(&proof)
}

/// Compatibility entry point retained while callers migrate to the explicit
/// depth-32 API. It places the two supplied siblings at levels 0 and 1 and
/// uses the deterministic research siblings for the remaining private levels.
/// It is not a two-level proof; use [`prove_and_verify_p24_note_ownership_path32`]
/// in new code.
pub fn prove_and_verify_p24_note_ownership_path2(
    nullifier_key: [u8; KEY_BYTES],
    note_preimage: [u8; NOTE_BYTES],
    leaf_position: u32,
    siblings: [BabyBearDigestV2; 2],
) -> Result<Poseidon2P24OwnershipExperimentResult, StarkExperimentError> {
    let mut full_siblings = synthetic_merkle_siblings();
    full_siblings[..2].copy_from_slice(&siblings);
    prove_and_verify_p24_note_ownership_path32(
        nullifier_key,
        note_preimage,
        leaf_position,
        full_siblings,
    )
}

/// Command-friendly proof for one synthetic, internally consistent note.
pub fn run_p24_note_ownership_research_smoke()
-> Result<Poseidon2P24OwnershipExperimentResult, StarkExperimentError> {
    let reference = Poseidon2P24PrivacyReference::load_candidate()?;
    let key = core::array::from_fn(|index| index as u8);
    let recipient = reference.hash_addr(&key)?;
    let note = synthetic_note_preimage(recipient);
    prove_and_verify_p24_note_ownership(key, note, 42)
}

fn build_ownership_trace(
    air: &Poseidon2P24OwnershipAir,
    witness: &OwnershipTraceWitness,
) -> RowMajorMatrix<Val> {
    let key_packed = byte_pack3le(&witness.nullifier_key, ADDR_ELEMENTS);
    let note_packed = byte_pack3le(&witness.note_preimage, NOTE_ELEMENTS);
    let nullifier_preimage = make_nullifier_preimage(
        witness.nullifier_key,
        witness.note_preimage,
        witness.note_commitment,
        witness.leaf_position,
    );
    let nullifier_packed = byte_pack3le(&nullifier_preimage, NULLIFIER_ELEMENTS);
    let mut values = Val::zero_vec(TRACE_ROWS * TRACE_WIDTH);
    let mut state = initial_state_values(&air.permutation, air.addr_iv, &key_packed);

    for row in 0..TRACE_ROWS {
        let offset = row * TRACE_WIDTH;
        values[offset..offset + P24_WIDTH].copy_from_slice(&state);
        write_witness(&mut values[offset + WITNESS_OFFSET..], witness);
        if row < TOTAL_STEPS {
            let phase = row / P24_ROUNDS;
            let round = row % P24_ROUNDS;
            values[offset + ROUND_SELECTOR_OFFSET + round] = Val::ONE;
            values[offset + PHASE_SELECTOR_OFFSET + phase] = Val::ONE;
            state = round_values(&air.permutation, state, round);
            if round + 1 == P24_ROUNDS {
                state = ownership_phase_transition_values(
                    air,
                    state,
                    witness,
                    &note_packed,
                    &nullifier_packed,
                    phase,
                );
            }
        } else {
            values[offset + ROUND_SELECTOR_OFFSET + P24_ROUNDS - 1] = Val::ONE;
            values[offset + PHASE_SELECTOR_OFFSET + TOTAL_PHASES - 1] = Val::ONE;
            values[offset + DONE_OFFSET] = Val::ONE;
        }
    }
    RowMajorMatrix::new(values, TRACE_WIDTH)
}

fn ownership_phase_transition_values(
    air: &Poseidon2P24OwnershipAir,
    mut state: [Val; P24_WIDTH],
    witness: &OwnershipTraceWitness,
    note_packed: &[u32],
    nullifier_packed: &[u32],
    phase: usize,
) -> [Val; P24_WIDTH] {
    if phase >= NODE_FIRST_PHASE {
        let node_phase_index = phase - NODE_FIRST_PHASE;
        let level = node_phase_index / NODE_PHASES_PER_HASH;
        let current = if level == 0 {
            witness.tree_leaf
        } else {
            witness.intermediates[level - 1]
        };
        let direction = ((witness.leaf_position >> level) & 1) == 1;
        return match node_phase_index % NODE_PHASES_PER_HASH {
            0 => node_absorb_then_permute(
                &air.permutation,
                state,
                current,
                witness.siblings[level],
                direction,
                15,
            ),
            1 => node_absorb_then_permute(
                &air.permutation,
                state,
                current,
                witness.siblings[level],
                direction,
                30,
            ),
            2 => matrix_values(&air.permutation.external_matrix, &state),
            3 if level + 1 < MEMBERSHIP_DEPTH => initial_node_state_values(
                &air.permutation,
                air.node_iv,
                witness.intermediates[level],
                witness.siblings[level + 1],
                ((witness.leaf_position >> (level + 1)) & 1) == 1,
            ),
            3 => state,
            _ => unreachable!("node phase is reduced modulo its fixed permutation count"),
        };
    }
    match phase {
        ADDR_BLOCK_PHASE => matrix_values(&air.permutation.external_matrix, &state),
        ADDR_SQUEEZE_PHASE => initial_state_values(&air.permutation, air.note_iv, note_packed),
        NOTE_FIRST_PHASE..=4 => absorb_then_initial_permute(
            &air.permutation,
            state,
            note_packed,
            phase - NOTE_FIRST_PHASE + 1,
        ),
        NOTE_LAST_BLOCK_PHASE => matrix_values(&air.permutation.external_matrix, &state),
        NOTE_SQUEEZE_PHASE => {
            initial_state_values(&air.permutation, air.nullifier_iv, nullifier_packed)
        }
        NULLIFIER_FIRST_PHASE..=8 => absorb_then_initial_permute(
            &air.permutation,
            state,
            nullifier_packed,
            phase - NULLIFIER_FIRST_PHASE + 1,
        ),
        NULLIFIER_LAST_BLOCK_PHASE => matrix_values(&air.permutation.external_matrix, &state),
        NULLIFIER_SQUEEZE_PHASE => initial_state_values(
            &air.permutation,
            air.leaf_iv,
            &witness.note_commitment[..RATE],
        ),
        LEAF_FIRST_PHASE => {
            state[0] += Val::from_u32(witness.note_commitment[15]);
            matrix_values(&air.permutation.external_matrix, &state)
        }
        LEAF_SECOND_PHASE => matrix_values(&air.permutation.external_matrix, &state),
        LEAF_SQUEEZE_PHASE => initial_node_state_values(
            &air.permutation,
            air.node_iv,
            witness.tree_leaf,
            witness.siblings[0],
            (witness.leaf_position & 1) == 1,
        ),
        _ => unreachable!("every non-node P24 ownership phase is fixed"),
    }
}

fn initial_state_values(
    permutation: &Poseidon2P24Air,
    iv: [u32; 9],
    packed: &[u32],
) -> [Val; P24_WIDTH] {
    let mut raw = [Val::ZERO; P24_WIDTH];
    for (lane, value) in packed.iter().copied().take(RATE).enumerate() {
        raw[lane] = Val::from_u32(value);
    }
    for (lane, value) in iv.into_iter().enumerate() {
        raw[RATE + lane] = Val::from_u32(value);
    }
    matrix_values(&permutation.external_matrix, &raw)
}

fn initial_node_state_values(
    permutation: &Poseidon2P24Air,
    iv: [u32; 9],
    current: BabyBearDigestV2,
    sibling: BabyBearDigestV2,
    current_is_right: bool,
) -> [Val; P24_WIDTH] {
    let input = ordered_node_input(current, sibling, current_is_right);
    initial_state_values(permutation, iv, &input)
}

fn node_absorb_then_permute(
    permutation: &Poseidon2P24Air,
    mut state: [Val; P24_WIDTH],
    current: BabyBearDigestV2,
    sibling: BabyBearDigestV2,
    current_is_right: bool,
    input_start: usize,
) -> [Val; P24_WIDTH] {
    let input = ordered_node_input(current, sibling, current_is_right);
    for (lane, state_lane) in state.iter_mut().enumerate().take(RATE) {
        if let Some(value) = input.get(input_start + lane) {
            *state_lane += Val::from_u32(*value);
        }
    }
    matrix_values(&permutation.external_matrix, &state)
}

fn absorb_then_initial_permute(
    permutation: &Poseidon2P24Air,
    mut state: [Val; P24_WIDTH],
    packed: &[u32],
    block: usize,
) -> [Val; P24_WIDTH] {
    for (lane, state_lane) in state.iter_mut().enumerate().take(RATE) {
        if let Some(value) = packed.get((block * RATE) + lane) {
            *state_lane += Val::from_u32(*value);
        }
    }
    matrix_values(&permutation.external_matrix, &state)
}

fn write_witness(witness: &mut [Val], input: &OwnershipTraceWitness) {
    write_bytes_and_bits(
        witness,
        KEY_BYTES_OFFSET,
        KEY_BITS_OFFSET,
        &input.nullifier_key,
    );
    write_bytes_and_bits(
        witness,
        NOTE_BYTES_OFFSET,
        NOTE_BITS_OFFSET,
        &input.note_preimage,
    );
    write_bytes_and_bits(
        witness,
        POSITION_BYTES_OFFSET,
        POSITION_BITS_OFFSET,
        &input.leaf_position.to_be_bytes(),
    );
    for (lane, value) in input.recipient_commitment.into_iter().enumerate() {
        witness[RECIPIENT_DIGEST_OFFSET + lane] = Val::from_u32(value);
    }
    let note_commitment_bytes = digest_bytes(input.note_commitment);
    write_bytes_and_bits(
        witness,
        NOTE_COMMITMENT_BYTES_OFFSET,
        NOTE_COMMITMENT_BITS_OFFSET,
        &note_commitment_bytes,
    );
    for (lane, value) in input.note_commitment.into_iter().enumerate() {
        witness[NOTE_DIGEST_OFFSET + lane] = Val::from_u32(value);
    }
    for (lane, value) in input.tree_leaf.into_iter().enumerate() {
        witness[TREE_LEAF_DIGEST_OFFSET + lane] = Val::from_u32(value);
    }
    for (level, sibling) in input.siblings.into_iter().enumerate() {
        for (lane, value) in sibling.into_iter().enumerate() {
            witness[MERKLE_SIBLINGS_OFFSET + (level * DIGEST_LANES) + lane] = Val::from_u32(value);
        }
    }
    for (level, intermediate) in input.intermediates.into_iter().enumerate() {
        for (lane, value) in intermediate.into_iter().enumerate() {
            witness[MERKLE_INTERMEDIATE_OFFSET + (level * DIGEST_LANES) + lane] =
                Val::from_u32(value);
        }
    }
}

fn ordered_node_input(
    current: BabyBearDigestV2,
    sibling: BabyBearDigestV2,
    current_is_right: bool,
) -> [u32; DIGEST_LANES * 2] {
    let (left, right) = if current_is_right {
        (sibling, current)
    } else {
        (current, sibling)
    };
    let mut input = [0_u32; DIGEST_LANES * 2];
    input[..DIGEST_LANES].copy_from_slice(&left);
    input[DIGEST_LANES..].copy_from_slice(&right);
    input
}

fn candidate_node(
    reference: &Poseidon2P24Reference,
    current: BabyBearDigestV2,
    sibling: BabyBearDigestV2,
    current_is_right: bool,
) -> Result<BabyBearDigestV2, StarkExperimentError> {
    Ok(reference.node(
        if current_is_right { sibling } else { current },
        if current_is_right { current } else { sibling },
    )?)
}

fn synthetic_merkle_siblings() -> [BabyBearDigestV2; MEMBERSHIP_DEPTH] {
    core::array::from_fn(|level| {
        core::array::from_fn(|lane| ((level as u32 + 1) * 101) + lane as u32 + 1)
    })
}

fn write_bytes_and_bits(
    witness: &mut [Val],
    bytes_offset: usize,
    bits_offset: usize,
    bytes: &[u8],
) {
    for (byte_index, byte) in bytes.iter().copied().enumerate() {
        witness[bytes_offset + byte_index] = Val::from_u8(byte);
        for bit_index in 0..BITS_PER_BYTE {
            witness[bits_offset + (byte_index * BITS_PER_BYTE) + bit_index] =
                Val::from_u8((byte >> bit_index) & 1);
        }
    }
}

fn make_nullifier_preimage(
    key: [u8; KEY_BYTES],
    note: [u8; NOTE_BYTES],
    note_commitment: BabyBearDigestV2,
    leaf_position: u32,
) -> [u8; 132] {
    let mut bytes = [0_u8; 132];
    bytes[..32].copy_from_slice(&key);
    bytes[32..64].copy_from_slice(&note[NOTE_RHO_OFFSET..NOTE_RHO_OFFSET + 32]);
    bytes[64..128].copy_from_slice(&digest_bytes(note_commitment));
    bytes[128..].copy_from_slice(&leaf_position.to_be_bytes());
    bytes
}

fn byte_pack3le(input: &[u8], elements: usize) -> Vec<u32> {
    assert_eq!(input.len().div_ceil(3), elements);
    input
        .chunks(3)
        .map(|chunk| {
            chunk
                .iter()
                .enumerate()
                .fold(0_u32, |packed, (offset, byte)| {
                    packed | (u32::from(*byte) << (offset * 8))
                })
        })
        .collect()
}

fn digest_bytes(digest: BabyBearDigestV2) -> [u8; DIGEST_BYTES] {
    let mut bytes = [0_u8; DIGEST_BYTES];
    for (lane, value) in digest.into_iter().enumerate() {
        bytes[lane * 4..(lane + 1) * 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

fn synthetic_note_preimage(recipient: BabyBearDigestV2) -> [u8; NOTE_BYTES] {
    let mut note = core::array::from_fn(|index| (index as u8).wrapping_mul(19).wrapping_add(7));
    note[..2].copy_from_slice(&1_u16.to_be_bytes());
    note[NOTE_RECIPIENT_OFFSET..NOTE_RECIPIENT_OFFSET + DIGEST_BYTES]
        .copy_from_slice(&digest_bytes(recipient));
    note
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_witness() -> ([u8; KEY_BYTES], [u8; NOTE_BYTES], u32) {
        let reference = Poseidon2P24PrivacyReference::load_candidate().unwrap();
        let key = core::array::from_fn(|index| (index as u8).wrapping_mul(13).wrapping_add(3));
        let recipient = reference.hash_addr(&key).unwrap();
        (key, synthetic_note_preimage(recipient), 0x89ab_cdef)
    }

    #[test]
    fn ownership_stark_binds_one_private_key_note_position_leaf_and_path_to_the_public_root() {
        let (key, note, position) = valid_witness();
        let mut proof =
            prove_p24_note_ownership_path32(key, note, position, synthetic_merkle_siblings())
                .unwrap();
        let result = verify_p24_note_ownership_proof(&proof).unwrap();
        let reference = Poseidon2P24PrivacyReference::load_candidate().unwrap();
        let commitment = reference.hash_note(&note).unwrap();
        let expected = reference
            .hash_nullifier_preimage(&make_nullifier_preimage(key, note, commitment, position))
            .unwrap();

        assert_eq!(result.nullifier, expected);
        let tree_reference = Poseidon2P24Reference::load_candidate().unwrap();
        let tree_leaf = tree_reference.leaf(commitment).unwrap();
        let siblings = synthetic_merkle_siblings();
        let mut root = tree_leaf;
        for (level, sibling) in siblings.iter().enumerate() {
            root = candidate_node(
                &tree_reference,
                root,
                *sibling,
                ((position >> level) & 1) == 1,
            )
            .unwrap();
        }
        assert_eq!(result.root, root);
        assert_eq!(result.trace_rows, TRACE_ROWS);

        proof.public_result.root[0] = proof.public_result.root[0].wrapping_add(1);
        assert!(matches!(
            verify_p24_note_ownership_proof(&proof),
            Err(StarkExperimentError::VerificationFailed)
        ));
    }

    #[test]
    fn ownership_air_rejects_a_changed_nullifier_or_broken_key_to_recipient_binding() {
        let (key, note, position) = valid_witness();
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        let private_reference = Poseidon2P24PrivacyReference::load_candidate().unwrap();
        let recipient = private_reference.hash_addr(&key).unwrap();
        let commitment = private_reference.hash_note(&note).unwrap();
        let tree_leaf = reference.leaf(commitment).unwrap();
        let siblings = synthetic_merkle_siblings();
        let directions: [bool; MEMBERSHIP_DEPTH] =
            core::array::from_fn(|level| ((position >> level) & 1) == 1);
        let mut current = tree_leaf;
        let mut intermediates = [[0_u32; DIGEST_LANES]; MEMBERSHIP_DEPTH - 1];
        for level in 0..MEMBERSHIP_DEPTH {
            current =
                candidate_node(&reference, current, siblings[level], directions[level]).unwrap();
            if level + 1 < MEMBERSHIP_DEPTH {
                intermediates[level] = current;
            }
        }
        let root = current;
        let nullifier = private_reference
            .hash_nullifier_preimage(&make_nullifier_preimage(key, note, commitment, position))
            .unwrap()
            .map(Val::from_u32);
        let public_values = core::array::from_fn(|index| {
            if index < DIGEST_LANES {
                nullifier[index]
            } else {
                Val::from_u32(root[index - DIGEST_LANES])
            }
        });
        let air = Poseidon2P24OwnershipAir::from_reference(&reference).unwrap();
        let witness = OwnershipTraceWitness {
            nullifier_key: key,
            note_preimage: note,
            leaf_position: position,
            recipient_commitment: recipient,
            note_commitment: commitment,
            tree_leaf,
            siblings,
            intermediates,
        };
        let trace = build_ownership_trace(&air, &witness);
        p3_air::check_constraints(&air, &trace, &public_values);

        let assert_rejected =
            |trace: &RowMajorMatrix<Val>, public_values: &[Val; DIGEST_LANES * 2]| {
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        p3_air::check_constraints(&air, trace, public_values);
                    }))
                    .is_err()
                );
            };

        let mut changed_nullifier = public_values;
        changed_nullifier[0] += Val::ONE;
        assert_rejected(&trace, &changed_nullifier);

        let mut changed_root = public_values;
        changed_root[DIGEST_LANES] += Val::ONE;
        assert_rejected(&trace, &changed_root);

        let mut broken_recipient = trace.clone();
        for row in 0..TRACE_ROWS {
            broken_recipient.values
                [row * TRACE_WIDTH + WITNESS_OFFSET + NOTE_BYTES_OFFSET + NOTE_RECIPIENT_OFFSET] +=
                Val::ONE;
        }
        assert_rejected(&broken_recipient, &public_values);

        let mut broken_note_commitment = trace.clone();
        for row in 0..TRACE_ROWS {
            broken_note_commitment.values
                [row * TRACE_WIDTH + WITNESS_OFFSET + NOTE_COMMITMENT_BYTES_OFFSET] += Val::ONE;
        }
        assert_rejected(&broken_note_commitment, &public_values);

        let mut broken_tree_leaf = trace.clone();
        for row in 0..TRACE_ROWS {
            broken_tree_leaf.values
                [row * TRACE_WIDTH + WITNESS_OFFSET + TREE_LEAF_DIGEST_OFFSET] += Val::ONE;
        }
        assert_rejected(&broken_tree_leaf, &public_values);

        let mut broken_first_sibling = trace.clone();
        for row in 0..TRACE_ROWS {
            broken_first_sibling.values
                [row * TRACE_WIDTH + WITNESS_OFFSET + MERKLE_SIBLINGS_OFFSET] += Val::ONE;
        }
        assert_rejected(&broken_first_sibling, &public_values);

        // Exercise the terminal level explicitly, not only the first ordered
        // node. This demonstrates that the public root remains linked through
        // the entire private 32-level path.
        let mut broken_last_sibling = trace.clone();
        for row in 0..TRACE_ROWS {
            broken_last_sibling.values[row * TRACE_WIDTH
                + WITNESS_OFFSET
                + MERKLE_SIBLINGS_OFFSET
                + ((MEMBERSHIP_DEPTH - 1) * DIGEST_LANES)] += Val::ONE;
        }
        assert_rejected(&broken_last_sibling, &public_values);

        let mut broken_last_intermediate = trace;
        for row in 0..TRACE_ROWS {
            broken_last_intermediate.values[row * TRACE_WIDTH
                + WITNESS_OFFSET
                + MERKLE_INTERMEDIATE_OFFSET
                + ((MEMBERSHIP_DEPTH - 2) * DIGEST_LANES)] += Val::ONE;
        }
        assert_rejected(&broken_last_intermediate, &public_values);
    }
}
