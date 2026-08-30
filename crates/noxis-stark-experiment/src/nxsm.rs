//! Bounded private-prefix experiment for the candidate `NXSM` sparse tree.
//!
//! The real sparse tree has 512 levels. This module proves an exact eight-level
//! segment using the real `NXSM` empty leaf and node domain. It also offers a
//! bounded-memory local preflight that sequences all 64 segments. Neither is a
//! portable absence proof for the full 512-level tree.

use noxis_nullifier_tree_reference::NullifierSparseTreeReferenceV1;
use noxis_poseidon2_reference::{BabyBearDigestV2, P24_WIDTH, Poseidon2P24Reference};
use noxis_privacy_types::NullifierV2;
use noxis_tree_params::{
    CandidatePoseidon2P24NullifierSparseManifestV1, Poseidon2P24NullifierSparseDomainV1,
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{Proof, prove, verify};

use crate::{
    P24_ROUNDS, Poseidon2P24Air, StarkExperimentError, Val, make_hiding_config_with_log_blowup,
    matrix_expression, matrix_values, round_values,
};

const DIGEST_LANES: usize = 16;
const PREFIX_DEPTH: usize = 8;
const NXSM_DEPTH: usize = 512;
const SEGMENT_COUNT: usize = NXSM_DEPTH / PREFIX_DEPTH;
const NODE_PHASES_PER_HASH: usize = 4;
const TOTAL_PHASES: usize = PREFIX_DEPTH * NODE_PHASES_PER_HASH;
const TOTAL_STEPS: usize = TOTAL_PHASES * P24_ROUNDS;
const TRACE_ROWS: usize = 1024;
const ROUND_SELECTOR_OFFSET: usize = P24_WIDTH;
const PHASE_SELECTOR_OFFSET: usize = ROUND_SELECTOR_OFFSET + P24_ROUNDS;
const DONE_OFFSET: usize = PHASE_SELECTOR_OFFSET + TOTAL_PHASES;
const WITNESS_OFFSET: usize = DONE_OFFSET + 1;
const DIGEST_BYTES: usize = DIGEST_LANES * 4;
const BITS_PER_BYTE: usize = 8;
const SIBLING_BYTES_OFFSET: usize = 0;
const SIBLING_BITS_OFFSET: usize = SIBLING_BYTES_OFFSET + (PREFIX_DEPTH * DIGEST_BYTES);
const INTERMEDIATE_BYTES_OFFSET: usize =
    SIBLING_BITS_OFFSET + (PREFIX_DEPTH * DIGEST_BYTES * BITS_PER_BYTE);
const INTERMEDIATE_BITS_OFFSET: usize =
    INTERMEDIATE_BYTES_OFFSET + ((PREFIX_DEPTH - 1) * DIGEST_BYTES);
const WITNESS_ELEMENTS: usize =
    INTERMEDIATE_BITS_OFFSET + ((PREFIX_DEPTH - 1) * DIGEST_BYTES * BITS_PER_BYTE);
const TRACE_WIDTH: usize = WITNESS_OFFSET + WITNESS_ELEMENTS;
const PUBLIC_ROOT_OFFSET: usize = 0;
const PUBLIC_PREFIX_BYTE_OFFSET: usize = PUBLIC_ROOT_OFFSET + DIGEST_LANES;
const PUBLIC_DIRECTION_BITS_OFFSET: usize = PUBLIC_PREFIX_BYTE_OFFSET + 1;
const PUBLIC_VALUES: usize = PUBLIC_DIRECTION_BITS_OFFSET + PREFIX_DEPTH;
const PROVER_STACK_BYTES: usize = 32 * 1024 * 1024;

const fn phase(level: usize, phase_in_hash: usize) -> usize {
    (level * NODE_PHASES_PER_HASH) + phase_in_hash
}

/// Public result of one exact private eight-level `NXSM` prefix relation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Poseidon2P24NxsmPrefix8ExperimentResult {
    /// The canonical public nullifier whose selected byte orders the segment.
    pub nullifier: NullifierV2,
    /// The byte index in the canonical nullifier encoding used by this segment.
    pub byte_index: u8,
    /// The local node from which this eight-level segment starts.
    pub start: BabyBearDigestV2,
    /// The node reached after applying levels zero through seven to `E0`.
    pub boundary: BabyBearDigestV2,
    /// Fixed trace size for this bounded research component.
    pub trace_rows: usize,
}

/// Public result of a complete local 512-level sequential `NXSM` preflight.
///
/// This is not a proof object: every bounded proof has already been verified
/// and dropped before this receipt is returned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Poseidon2P24NxsmSequentialAbsencePreflightResult {
    /// The canonical nullifier checked from the empty leaf to this root.
    pub nullifier: NullifierV2,
    /// The supplied candidate sparse-tree root reached after all 64 segments.
    pub root: BabyBearDigestV2,
    /// Number of independently verified and discarded eight-level segments.
    pub segments_verified: usize,
}

/// Opaque in-memory proof for the bounded `NXSM` prefix relation.
///
/// It intentionally has no encoder or selected verifier profile. The exact
/// local Plonky3 configuration remains with the proof so it can be verified
/// inside this research process only.
pub struct Poseidon2P24NxsmPrefix8Proof {
    config: crate::Config,
    proof: Proof<crate::Config>,
    public_result: Poseidon2P24NxsmPrefix8ExperimentResult,
}

impl Poseidon2P24NxsmPrefix8Proof {
    /// Returns the public nullifier, prefix boundary and fixed trace shape.
    pub const fn public_result(&self) -> &Poseidon2P24NxsmPrefix8ExperimentResult {
        &self.public_result
    }
}

#[derive(Clone, Copy)]
struct PrefixWitness {
    siblings: [BabyBearDigestV2; PREFIX_DEPTH],
    intermediates: [BabyBearDigestV2; PREFIX_DEPTH - 1],
}

#[derive(Clone, Debug)]
struct NxsmPrefix8Air {
    permutation: Poseidon2P24Air,
    node_iv: [u32; 9],
    start: BabyBearDigestV2,
}

impl NxsmPrefix8Air {
    fn load_candidate(start: BabyBearDigestV2) -> Result<Self, StarkExperimentError> {
        let reference = Poseidon2P24Reference::load_candidate()?;
        let manifest = CandidatePoseidon2P24NullifierSparseManifestV1::new();
        Ok(Self {
            permutation: Poseidon2P24Air::from_reference(&reference),
            node_iv: manifest.iv(Poseidon2P24NullifierSparseDomainV1::Node)?,
            start,
        })
    }

    fn initial_node_state_expression<AB: AirBuilder>(
        &self,
        witness: &[AB::Var],
        public_values: &[AB::PublicVar],
        level: usize,
    ) -> Vec<AB::Expr> {
        let raw = (0..P24_WIDTH)
            .map(|lane| {
                if lane < 15 {
                    self.node_input_expression::<AB>(witness, public_values, level, lane)
                } else {
                    AB::Expr::from_u32(self.node_iv[lane - 15])
                }
            })
            .collect::<Vec<_>>();
        matrix_expression::<AB>(&self.permutation.external_matrix, &raw)
    }

    fn node_input_expression<AB: AirBuilder>(
        &self,
        witness: &[AB::Var],
        public_values: &[AB::PublicVar],
        level: usize,
        input_index: usize,
    ) -> AB::Expr {
        (0..3).fold(AB::Expr::ZERO, |packed, byte_offset| {
            let byte_index = (input_index * 3) + byte_offset;
            if byte_index >= DIGEST_BYTES * 2 {
                packed
            } else {
                packed
                    + self.ordered_node_byte_expression::<AB>(
                        witness,
                        public_values,
                        level,
                        byte_index,
                    ) * AB::F::from_u32(1_u32 << (byte_offset * 8))
            }
        })
    }

    fn ordered_node_byte_expression<AB: AirBuilder>(
        &self,
        witness: &[AB::Var],
        public_values: &[AB::PublicVar],
        level: usize,
        byte_index: usize,
    ) -> AB::Expr {
        let byte_in_digest = byte_index % DIGEST_BYTES;
        let current = self.current_byte_expression::<AB>(witness, level, byte_in_digest);
        let sibling: AB::Expr =
            witness[SIBLING_BYTES_OFFSET + (level * DIGEST_BYTES) + byte_in_digest].into();
        let direction: AB::Expr = public_values[PUBLIC_DIRECTION_BITS_OFFSET + level].into();
        if byte_index < DIGEST_BYTES {
            current.clone() + direction.clone() * (sibling.clone() - current)
        } else {
            sibling.clone() + direction * (current - sibling)
        }
    }

    fn current_byte_expression<AB: AirBuilder>(
        &self,
        witness: &[AB::Var],
        level: usize,
        byte_index: usize,
    ) -> AB::Expr {
        if level == 0 {
            AB::Expr::from_u32(u32::from(digest_bytes(self.start)[byte_index]))
        } else {
            witness[INTERMEDIATE_BYTES_OFFSET + ((level - 1) * DIGEST_BYTES) + byte_index].into()
        }
    }

    fn intermediate_digest_expression<AB: AirBuilder>(
        &self,
        witness: &[AB::Var],
        level: usize,
    ) -> Vec<AB::Expr> {
        (0..DIGEST_LANES)
            .map(|lane| {
                self.four_bytes_expression::<AB>(
                    witness,
                    INTERMEDIATE_BYTES_OFFSET + (level * DIGEST_BYTES) + (lane * 4),
                )
            })
            .collect()
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

    fn assert_private_bytes<AB: AirBuilder>(
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

    fn node_absorb_expression<AB: AirBuilder>(
        &self,
        round_state: &[AB::Expr],
        witness: &[AB::Var],
        public_values: &[AB::PublicVar],
        level: usize,
        input_start: usize,
    ) -> Vec<AB::Expr> {
        let absorbed = (0..P24_WIDTH)
            .map(|lane| {
                if lane < 15 && input_start + lane < 43 {
                    round_state[lane].clone()
                        + self.node_input_expression::<AB>(
                            witness,
                            public_values,
                            level,
                            input_start + lane,
                        )
                } else {
                    round_state[lane].clone()
                }
            })
            .collect::<Vec<_>>();
        matrix_expression::<AB>(&self.permutation.external_matrix, &absorbed)
    }

    fn phase_transition_target<AB: AirBuilder>(
        &self,
        phase_index: usize,
        round_state: &[AB::Expr],
        witness: &[AB::Var],
        public_values: &[AB::PublicVar],
    ) -> Vec<AB::Expr> {
        let level = phase_index / NODE_PHASES_PER_HASH;
        match phase_index % NODE_PHASES_PER_HASH {
            0 => self.node_absorb_expression::<AB>(round_state, witness, public_values, level, 15),
            1 => self.node_absorb_expression::<AB>(round_state, witness, public_values, level, 30),
            2 => matrix_expression::<AB>(&self.permutation.external_matrix, round_state),
            3 if level + 1 < PREFIX_DEPTH => {
                self.initial_node_state_expression::<AB>(witness, public_values, level + 1)
            }
            3 => round_state.to_vec(),
            _ => unreachable!("phase index is reduced modulo the fixed node hash shape"),
        }
    }

    #[allow(clippy::too_many_arguments)] // AIR gate context is intentionally explicit.
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
        let first_gate: AB::Expr =
            active.clone() * final_round_selector * phase_selectors[final_block_phase];
        for lane in 0..15 {
            builder.assert_zero(
                first_gate.clone() * (final_round_state[lane].clone() - digest[lane].clone()),
            );
        }
        let final_gate: AB::Expr = active * final_round_selector * phase_selectors[squeeze_phase];
        builder.assert_zero(final_gate * (final_round_state[0].clone() - digest[15].clone()));
    }
}

impl<F> BaseAir<F> for NxsmPrefix8Air {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }

    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(10)
    }
}

impl<AB: AirBuilder> Air<AB> for NxsmPrefix8Air {
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

        for lane in 0..WITNESS_ELEMENTS {
            builder
                .when_transition()
                .assert_eq(next_witness[lane], witness[lane]);
        }
        self.assert_private_bytes::<AB>(
            builder,
            witness,
            SIBLING_BYTES_OFFSET,
            SIBLING_BITS_OFFSET,
            PREFIX_DEPTH * DIGEST_BYTES,
        );
        self.assert_private_bytes::<AB>(
            builder,
            witness,
            INTERMEDIATE_BYTES_OFFSET,
            INTERMEDIATE_BITS_OFFSET,
            (PREFIX_DEPTH - 1) * DIGEST_BYTES,
        );
        for level in 0..PREFIX_DEPTH {
            let direction: AB::Expr = public_values[PUBLIC_DIRECTION_BITS_OFFSET + level].into();
            builder.assert_zero(direction.clone() * (direction - AB::Expr::ONE));
        }
        let prefix_byte: AB::Expr = public_values[PUBLIC_PREFIX_BYTE_OFFSET].into();
        let reconstructed_prefix = (0..BITS_PER_BYTE).fold(AB::Expr::ZERO, |byte, bit_index| {
            let bit: AB::Expr = public_values[PUBLIC_DIRECTION_BITS_OFFSET + bit_index].into();
            byte + bit * AB::F::from_u32(1_u32 << bit_index)
        });
        builder.assert_eq(prefix_byte, reconstructed_prefix);

        let initial = self.initial_node_state_expression::<AB>(witness, &public_values, 0);
        for lane in 0..P24_WIDTH {
            builder
                .when_first_row()
                .assert_eq(local_state[lane], initial[lane].clone());
        }
        for (selector, round_selector) in round_selectors.iter().enumerate() {
            builder.when_first_row().assert_eq(
                *round_selector,
                AB::F::from_u8(if selector == 0 { 1 } else { 0 }),
            );
        }
        for (index, phase_selector) in phase_selectors.iter().enumerate() {
            builder.when_first_row().assert_eq(
                *phase_selector,
                AB::F::from_u8(if index == 0 { 1 } else { 0 }),
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
        for phase_index in 0..TOTAL_PHASES - 1 {
            let previous: AB::Expr = if phase_index == 0 {
                AB::Expr::ZERO
            } else {
                phase_selectors[phase_index - 1].into()
            };
            builder.when_transition().assert_eq(
                next_phase_selectors[phase_index],
                phase_selectors[phase_index]
                    + round_selectors[P24_ROUNDS - 1]
                        * (previous - AB::Expr::from(phase_selectors[phase_index])),
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
            .map(|phase_index| {
                self.phase_transition_target::<AB>(
                    phase_index,
                    &round_states[P24_ROUNDS - 1],
                    witness,
                    &public_values,
                )
            })
            .collect();
        for lane in 0..P24_WIDTH {
            let mut final_round_target: AB::Expr = local_state[lane].into();
            for phase_index in 0..TOTAL_PHASES {
                final_round_target += phase_selectors[phase_index]
                    * (phase_completions[phase_index][lane].clone() - local_state[lane]);
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

        for level in 0..PREFIX_DEPTH {
            let digest = if level + 1 == PREFIX_DEPTH {
                public_values[PUBLIC_ROOT_OFFSET..PUBLIC_ROOT_OFFSET + DIGEST_LANES]
                    .iter()
                    .copied()
                    .map(Into::into)
                    .collect::<Vec<AB::Expr>>()
            } else {
                self.intermediate_digest_expression::<AB>(witness, level)
            };
            self.assert_digest_at_phase::<AB>(
                builder,
                round_selectors[P24_ROUNDS - 1],
                phase_selectors,
                done,
                &round_states[P24_ROUNDS - 1],
                phase(level, 2),
                phase(level, 3),
                &digest,
            );
        }
    }
}

/// Produces a hiding-FRI proof for one exact private eight-level `NXSM`
/// segment. The caller-selected byte index is bounded to the 64 canonical
/// nullifier bytes; it determines the eight path-direction bits.
pub fn prove_p24_nxsm_absence_segment8(
    nullifier: NullifierV2,
    byte_index: u8,
    start: BabyBearDigestV2,
    siblings: [BabyBearDigestV2; PREFIX_DEPTH],
) -> Result<Poseidon2P24NxsmPrefix8Proof, StarkExperimentError> {
    let sparse = NullifierSparseTreeReferenceV1::load_candidate()?;
    let directions = segment_directions(nullifier, byte_index)?;
    let mut current = start;
    let mut intermediates = [[0_u32; DIGEST_LANES]; PREFIX_DEPTH - 1];
    for level in 0..PREFIX_DEPTH {
        current = if directions[level] {
            sparse.node(siblings[level], current)?
        } else {
            sparse.node(current, siblings[level])?
        };
        if level + 1 < PREFIX_DEPTH {
            intermediates[level] = current;
        }
    }
    let boundary = current;
    let air = NxsmPrefix8Air::load_candidate(start)?;
    let witness = PrefixWitness {
        siblings,
        intermediates,
    };
    let trace = build_trace(&air, &witness, directions);
    let public_values = public_values(nullifier, byte_index, boundary, directions);
    #[cfg(test)]
    p3_air::check_constraints(&air, &trace, &public_values);
    let prover = std::thread::Builder::new()
        .name("noxis-nxsm-prefix8-prover".to_owned())
        .stack_size(PROVER_STACK_BYTES)
        .spawn(move || {
            let config = make_hiding_config_with_log_blowup(4);
            let proof = prove(&config, &air, trace, &public_values);
            Ok(Poseidon2P24NxsmPrefix8Proof {
                config,
                proof,
                public_result: Poseidon2P24NxsmPrefix8ExperimentResult {
                    nullifier,
                    byte_index,
                    start,
                    boundary,
                    trace_rows: TRACE_ROWS,
                },
            })
        })
        .map_err(|_| StarkExperimentError::ProverThreadFailed)?;
    prover
        .join()
        .map_err(|_| StarkExperimentError::ProverThreadFailed)?
}

/// Produces the fixed first segment of an absent `NXSM` path, starting from
/// the frozen `E0` empty leaf.
pub fn prove_p24_nxsm_absence_prefix8(
    nullifier: NullifierV2,
    siblings: [BabyBearDigestV2; PREFIX_DEPTH],
) -> Result<Poseidon2P24NxsmPrefix8Proof, StarkExperimentError> {
    let sparse = NullifierSparseTreeReferenceV1::load_candidate()?;
    prove_p24_nxsm_absence_segment8(nullifier, 0, sparse.empty_values()[0], siblings)
}

/// Verifies one locally held bounded `NXSM` prefix proof.
pub fn verify_p24_nxsm_absence_prefix8_proof(
    prefix_proof: &Poseidon2P24NxsmPrefix8Proof,
) -> Result<Poseidon2P24NxsmPrefix8ExperimentResult, StarkExperimentError> {
    let air = NxsmPrefix8Air::load_candidate(prefix_proof.public_result.start)?;
    let directions = segment_directions(
        prefix_proof.public_result.nullifier,
        prefix_proof.public_result.byte_index,
    )?;
    let public_values = public_values(
        prefix_proof.public_result.nullifier,
        prefix_proof.public_result.byte_index,
        prefix_proof.public_result.boundary,
        directions,
    );
    verify(
        &prefix_proof.config,
        &air,
        &prefix_proof.proof,
        &public_values,
    )
    .map_err(|_| StarkExperimentError::VerificationFailed)?;
    Ok(prefix_proof.public_result.clone())
}

/// Compatibility entry point for one bounded private `NXSM` prefix proof.
pub fn prove_and_verify_p24_nxsm_absence_prefix8(
    nullifier: NullifierV2,
    siblings: [BabyBearDigestV2; PREFIX_DEPTH],
) -> Result<Poseidon2P24NxsmPrefix8ExperimentResult, StarkExperimentError> {
    let proof = prove_p24_nxsm_absence_prefix8(nullifier, siblings)?;
    verify_p24_nxsm_absence_prefix8_proof(&proof)
}

/// Executes the full 512-level candidate absence path as 64 locally verified,
/// private eight-level proofs. Each opaque proof is dropped before the next
/// segment begins; this keeps the current research backend's memory bounded.
///
/// The returned value is a local preflight receipt, not an aggregate proof or
/// a portable verifier artifact.
pub fn run_p24_nxsm_absence_path512_sequential_preflight(
    nullifier: NullifierV2,
    siblings: [BabyBearDigestV2; NXSM_DEPTH],
    expected_root: BabyBearDigestV2,
) -> Result<Poseidon2P24NxsmSequentialAbsencePreflightResult, StarkExperimentError> {
    let sparse = NullifierSparseTreeReferenceV1::load_candidate()?;
    let mut current = sparse.empty_values()[0];
    for byte_index in 0..SEGMENT_COUNT {
        let start = byte_index * PREFIX_DEPTH;
        let segment_siblings: [BabyBearDigestV2; PREFIX_DEPTH] = siblings
            [start..start + PREFIX_DEPTH]
            .try_into()
            .expect("fixed NXSM depth splits into exact eight-level segments");
        let proof = prove_p24_nxsm_absence_segment8(
            nullifier,
            byte_index as u8,
            current,
            segment_siblings,
        )?;
        current = verify_p24_nxsm_absence_prefix8_proof(&proof)?.boundary;
    }
    if current != expected_root {
        return Err(StarkExperimentError::NxsmSequentialRootMismatch);
    }
    Ok(Poseidon2P24NxsmSequentialAbsencePreflightResult {
        nullifier,
        root: current,
        segments_verified: SEGMENT_COUNT,
    })
}

fn segment_directions(
    nullifier: NullifierV2,
    byte_index: u8,
) -> Result<[bool; PREFIX_DEPTH], StarkExperimentError> {
    let byte_index = usize::from(byte_index);
    let byte = *nullifier
        .as_bytes()
        .get(byte_index)
        .ok_or(StarkExperimentError::InvalidNxsmSegmentByteIndex { actual: byte_index })?;
    Ok(core::array::from_fn(|bit| ((byte >> bit) & 1) == 1))
}

fn public_values(
    nullifier: NullifierV2,
    byte_index: u8,
    boundary: BabyBearDigestV2,
    directions: [bool; PREFIX_DEPTH],
) -> Vec<Val> {
    boundary
        .into_iter()
        .chain([u32::from(nullifier.as_bytes()[usize::from(byte_index)])])
        .chain(directions.map(u32::from))
        .map(Val::from_u32)
        .collect()
}

fn build_trace(
    air: &NxsmPrefix8Air,
    witness: &PrefixWitness,
    directions: [bool; PREFIX_DEPTH],
) -> RowMajorMatrix<Val> {
    let mut values = Val::zero_vec(TRACE_ROWS * TRACE_WIDTH);
    let mut state = initial_node_state_values(
        &air.permutation,
        air.node_iv,
        air.start,
        witness.siblings[0],
        directions[0],
    );
    for row in 0..TRACE_ROWS {
        let offset = row * TRACE_WIDTH;
        values[offset..offset + P24_WIDTH].copy_from_slice(&state);
        write_witness(&mut values[offset + WITNESS_OFFSET..], witness);
        if row < TOTAL_STEPS {
            let phase_index = row / P24_ROUNDS;
            let round = row % P24_ROUNDS;
            values[offset + ROUND_SELECTOR_OFFSET + round] = Val::ONE;
            values[offset + PHASE_SELECTOR_OFFSET + phase_index] = Val::ONE;
            state = round_values(&air.permutation, state, round);
            if round + 1 == P24_ROUNDS {
                state = phase_transition_values(air, state, witness, directions, phase_index);
            }
        } else {
            values[offset + ROUND_SELECTOR_OFFSET + P24_ROUNDS - 1] = Val::ONE;
            values[offset + PHASE_SELECTOR_OFFSET + TOTAL_PHASES - 1] = Val::ONE;
            values[offset + DONE_OFFSET] = Val::ONE;
        }
    }
    RowMajorMatrix::new(values, TRACE_WIDTH)
}

fn phase_transition_values(
    air: &NxsmPrefix8Air,
    state: [Val; P24_WIDTH],
    witness: &PrefixWitness,
    directions: [bool; PREFIX_DEPTH],
    phase_index: usize,
) -> [Val; P24_WIDTH] {
    let level = phase_index / NODE_PHASES_PER_HASH;
    match phase_index % NODE_PHASES_PER_HASH {
        0 => node_absorb_then_permute(
            &air.permutation,
            state,
            level_current(air, witness, level),
            witness.siblings[level],
            directions[level],
            15,
        ),
        1 => node_absorb_then_permute(
            &air.permutation,
            state,
            level_current(air, witness, level),
            witness.siblings[level],
            directions[level],
            30,
        ),
        2 => matrix_values(&air.permutation.external_matrix, &state),
        3 if level + 1 < PREFIX_DEPTH => initial_node_state_values(
            &air.permutation,
            air.node_iv,
            witness.intermediates[level],
            witness.siblings[level + 1],
            directions[level + 1],
        ),
        3 => state,
        _ => unreachable!("phase index is reduced modulo the fixed node hash shape"),
    }
}

fn level_current(air: &NxsmPrefix8Air, witness: &PrefixWitness, level: usize) -> BabyBearDigestV2 {
    if level == 0 {
        air.start
    } else {
        witness.intermediates[level - 1]
    }
}

fn initial_node_state_values(
    permutation: &Poseidon2P24Air,
    iv: [u32; 9],
    current: BabyBearDigestV2,
    sibling: BabyBearDigestV2,
    current_is_right: bool,
) -> [Val; P24_WIDTH] {
    let input = packed_node_input(current, sibling, current_is_right);
    let mut raw = [Val::ZERO; P24_WIDTH];
    for (lane, value) in input.into_iter().take(15).enumerate() {
        raw[lane] = Val::from_u32(value);
    }
    for (lane, value) in iv.into_iter().enumerate() {
        raw[15 + lane] = Val::from_u32(value);
    }
    matrix_values(&permutation.external_matrix, &raw)
}

fn node_absorb_then_permute(
    permutation: &Poseidon2P24Air,
    mut state: [Val; P24_WIDTH],
    current: BabyBearDigestV2,
    sibling: BabyBearDigestV2,
    current_is_right: bool,
    input_start: usize,
) -> [Val; P24_WIDTH] {
    let input = packed_node_input(current, sibling, current_is_right);
    for (lane, state_lane) in state.iter_mut().enumerate().take(15) {
        if let Some(value) = input.get(input_start + lane) {
            *state_lane += Val::from_u32(*value);
        }
    }
    matrix_values(&permutation.external_matrix, &state)
}

fn packed_node_input(
    current: BabyBearDigestV2,
    sibling: BabyBearDigestV2,
    current_is_right: bool,
) -> [u32; 43] {
    let mut bytes = [0_u8; DIGEST_BYTES * 2];
    let (left, right) = if current_is_right {
        (sibling, current)
    } else {
        (current, sibling)
    };
    bytes[..DIGEST_BYTES].copy_from_slice(&digest_bytes(left));
    bytes[DIGEST_BYTES..].copy_from_slice(&digest_bytes(right));
    core::array::from_fn(|packed_index| {
        (0..3).fold(0_u32, |value, byte_offset| {
            let byte_index = (packed_index * 3) + byte_offset;
            if byte_index < bytes.len() {
                value | (u32::from(bytes[byte_index]) << (byte_offset * 8))
            } else {
                value
            }
        })
    })
}

fn write_witness(destination: &mut [Val], witness: &PrefixWitness) {
    for (level, sibling) in witness.siblings.iter().enumerate() {
        write_bytes_and_bits(
            destination,
            SIBLING_BYTES_OFFSET + (level * DIGEST_BYTES),
            SIBLING_BITS_OFFSET + (level * DIGEST_BYTES * BITS_PER_BYTE),
            &digest_bytes(*sibling),
        );
    }
    for (level, intermediate) in witness.intermediates.iter().enumerate() {
        write_bytes_and_bits(
            destination,
            INTERMEDIATE_BYTES_OFFSET + (level * DIGEST_BYTES),
            INTERMEDIATE_BITS_OFFSET + (level * DIGEST_BYTES * BITS_PER_BYTE),
            &digest_bytes(*intermediate),
        );
    }
}

fn digest_bytes(digest: BabyBearDigestV2) -> [u8; DIGEST_BYTES] {
    let mut bytes = [0_u8; DIGEST_BYTES];
    for (lane, value) in digest.into_iter().enumerate() {
        bytes[lane * 4..lane * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

fn write_bytes_and_bits(
    destination: &mut [Val],
    bytes_offset: usize,
    bits_offset: usize,
    input: &[u8],
) {
    for (byte_index, byte) in input.iter().copied().enumerate() {
        destination[bytes_offset + byte_index] = Val::from_u32(u32::from(byte));
        for bit_index in 0..BITS_PER_BYTE {
            destination[bits_offset + (byte_index * BITS_PER_BYTE) + bit_index] =
                Val::from_u32(u32::from((byte >> bit_index) & 1));
        }
    }
}

#[cfg(test)]
mod tests {
    use noxis_nullifier_tree_state::NullifierSparseTreeStateV1;

    use super::*;

    fn nullifier(value: u32) -> NullifierV2 {
        NullifierV2::from_elements([value; DIGEST_LANES]).unwrap()
    }

    #[test]
    fn private_nxsm_prefix_binds_real_empty_leaf_node_domain_and_nullifier_bits() {
        let mut tree = NullifierSparseTreeStateV1::new_candidate().unwrap();
        tree.mark_spent(nullifier(3)).unwrap();
        tree.mark_spent(nullifier(9)).unwrap();
        let target = nullifier(10);
        let path = tree.prove(target);
        let siblings: [BabyBearDigestV2; PREFIX_DEPTH] =
            path.siblings()[..PREFIX_DEPTH].try_into().unwrap();
        let mut proof = prove_p24_nxsm_absence_prefix8(target, siblings).unwrap();
        let result = verify_p24_nxsm_absence_prefix8_proof(&proof).unwrap();
        let reference = NullifierSparseTreeReferenceV1::load_candidate().unwrap();
        let mut expected = reference.empty_values()[0];
        for (level, sibling) in siblings.into_iter().enumerate() {
            expected = if segment_directions(target, 0).unwrap()[level] {
                reference.node(sibling, expected).unwrap()
            } else {
                reference.node(expected, sibling).unwrap()
            };
        }
        assert_eq!(result.nullifier, target);
        assert_eq!(result.boundary, expected);
        assert_eq!(result.trace_rows, TRACE_ROWS);

        proof.public_result.nullifier = nullifier(11);
        assert!(matches!(
            verify_p24_nxsm_absence_prefix8_proof(&proof),
            Err(StarkExperimentError::VerificationFailed)
        ));
        proof.public_result.nullifier = target;
        proof.public_result.boundary[0] = proof.public_result.boundary[0].wrapping_add(1);
        assert!(matches!(
            verify_p24_nxsm_absence_prefix8_proof(&proof),
            Err(StarkExperimentError::VerificationFailed)
        ));
    }

    #[test]
    fn private_nxsm_terminal_segment_reaches_an_actual_sparse_tree_root() {
        let mut tree = NullifierSparseTreeStateV1::new_candidate().unwrap();
        tree.mark_spent(nullifier(3)).unwrap();
        tree.mark_spent(nullifier(9)).unwrap();
        let target = nullifier(10);
        let path = tree.prove(target);
        let reference = NullifierSparseTreeReferenceV1::load_candidate().unwrap();
        let mut start = reference.empty_values()[0];
        for level in 0..NXSM_DEPTH - PREFIX_DEPTH {
            let byte = target.as_bytes()[level / BITS_PER_BYTE];
            start = if ((byte >> (level % BITS_PER_BYTE)) & 1) == 1 {
                reference.node(path.siblings()[level], start).unwrap()
            } else {
                reference.node(start, path.siblings()[level]).unwrap()
            };
        }
        let byte_index = (SEGMENT_COUNT - 1) as u8;
        let siblings: [BabyBearDigestV2; PREFIX_DEPTH] = path.siblings()
            [NXSM_DEPTH - PREFIX_DEPTH..]
            .try_into()
            .unwrap();
        let proof = prove_p24_nxsm_absence_segment8(target, byte_index, start, siblings).unwrap();
        let result = verify_p24_nxsm_absence_prefix8_proof(&proof).unwrap();

        assert_eq!(result.byte_index, byte_index);
        assert_eq!(result.start, start);
        assert_eq!(result.boundary, tree.root().unwrap().elements());
    }

    #[test]
    #[ignore = "runs 64 private eight-level proofs; execute explicitly in release mode"]
    fn sequential_private_segments_reach_a_complete_candidate_nxsm_root() {
        let mut tree = NullifierSparseTreeStateV1::new_candidate().unwrap();
        tree.mark_spent(nullifier(3)).unwrap();
        tree.mark_spent(nullifier(9)).unwrap();
        let target = nullifier(10);
        let path = tree.prove(target);
        let siblings: [BabyBearDigestV2; NXSM_DEPTH] = path.siblings().try_into().unwrap();

        let result = run_p24_nxsm_absence_path512_sequential_preflight(
            target,
            siblings,
            tree.root().unwrap().elements(),
        )
        .unwrap();

        assert_eq!(result.nullifier, target);
        assert_eq!(result.root, tree.root().unwrap().elements());
        assert_eq!(result.segments_verified, SEGMENT_COUNT);
    }
}
