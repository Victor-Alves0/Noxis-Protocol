//! Public `H_INTENT` STARK relation for the candidate private-transfer frame.
//!
//! The 640-byte `PrivateTransferIntentV2` is deliberately public in the v0.1
//! candidate statement. This AIR consumes its 214 canonical `BytePack3LE`
//! elements and proves the exact candidate `H_INTENT` sponge evaluation. It is
//! the first executable constraint family from `NXAR v1`, not a private
//! transfer, a proof deployment, or an authorization to settle funds.

use noxis_poseidon2_privacy_reference::Poseidon2P24PrivacyReference;
use noxis_poseidon2_reference::{P24_WIDTH, Poseidon2P24Reference};
use noxis_privacy_types::{PrivateTransferIntentCommitmentV2, PrivateTransferIntentV2};
use noxis_tree_params::{
    CandidatePoseidon2P24IntentCommitmentManifestV1, P24_INTENT_COMMITMENT_INPUT_ELEMENTS,
    P24IntentVectorCorpusV1, Poseidon2P24IntentCommitmentDomainV1,
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{prove, verify};

use crate::{
    P24_ROUNDS, Poseidon2P24Air, StarkExperimentError, Val, make_hiding_config, matrix_expression,
    matrix_values, round_values,
};

pub(crate) const INTENT_ABSORB_PERMUTATIONS: usize =
    P24_INTENT_COMMITMENT_INPUT_ELEMENTS.div_ceil(15);
pub(crate) const INTENT_PERMUTATIONS: usize = INTENT_ABSORB_PERMUTATIONS + 1;
pub(crate) const INTENT_STEPS: usize = INTENT_PERMUTATIONS * P24_ROUNDS;
pub(crate) const INTENT_TRACE_ROWS: usize = 512;
pub(crate) const INTENT_SELECTOR_OFFSET: usize = P24_WIDTH;
pub(crate) const INTENT_WITNESS_OFFSET: usize = INTENT_SELECTOR_OFFSET + INTENT_STEPS;
pub(crate) const INTENT_BYTES: usize = PrivateTransferIntentV2::ENCODED_LENGTH;
const INTENT_BITS_PER_BYTE: usize = 8;
pub(crate) const INTENT_BYTES_OFFSET: usize = 0;
pub(crate) const INTENT_BITS_OFFSET: usize = INTENT_BYTES_OFFSET + INTENT_BYTES;
pub(crate) const INTENT_WITNESS_ELEMENTS: usize =
    INTENT_BITS_OFFSET + (INTENT_BYTES * INTENT_BITS_PER_BYTE);
pub(crate) const INTENT_TRACE_WIDTH: usize = INTENT_WITNESS_OFFSET + INTENT_WITNESS_ELEMENTS;
pub(crate) const INTENT_PUBLIC_VALUES: usize = P24_INTENT_COMMITMENT_INPUT_ELEMENTS + 16;
pub(crate) const INTENT_COMMITMENT_OFFSET: usize = P24_INTENT_COMMITMENT_INPUT_ELEMENTS;

/// Public result after a verified `H_INTENT(intent.encode())` candidate proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Poseidon2P24IntentExperimentResult {
    /// Candidate commitment to the complete canonical public intent encoding.
    pub intent_commitment: PrivateTransferIntentCommitmentV2,
    /// Fixed trace size for this first public AIR component.
    pub trace_rows: usize,
}

/// AIR for `NXIC v1` over the 214 public `BytePack3LE` intent elements.
#[derive(Clone, Debug)]
pub(crate) struct Poseidon2P24IntentAir {
    permutation: Poseidon2P24Air,
    iv: [u32; 9],
}

impl Poseidon2P24IntentAir {
    pub(crate) fn from_reference(
        reference: &Poseidon2P24Reference,
    ) -> Result<Self, StarkExperimentError> {
        Ok(Self {
            permutation: Poseidon2P24Air::from_reference(reference),
            iv: CandidatePoseidon2P24IntentCommitmentManifestV1::new()
                .iv(Poseidon2P24IntentCommitmentDomainV1::Intent)?,
        })
    }
}

impl<F> BaseAir<F> for Poseidon2P24IntentAir {
    fn width(&self) -> usize {
        INTENT_TRACE_WIDTH
    }

    fn num_public_values(&self) -> usize {
        INTENT_PUBLIC_VALUES
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(8)
    }
}

impl<AB: AirBuilder> Air<AB> for Poseidon2P24IntentAir {
    fn eval(&self, builder: &mut AB) {
        let public_values = builder.public_values().to_vec();
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        self.eval_relation(builder, local, next, &public_values);
    }
}

impl Poseidon2P24IntentAir {
    pub(crate) fn eval_relation<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        local: &[AB::Var],
        next: &[AB::Var],
        public_values: &[AB::PublicVar],
    ) {
        let local_state = &local[..P24_WIDTH];
        let next_state = &next[..P24_WIDTH];
        let selectors = &local[INTENT_SELECTOR_OFFSET..];
        let next_selectors = &next[INTENT_SELECTOR_OFFSET..];
        let witness = &local[INTENT_WITNESS_OFFSET..];
        let next_witness = &next[INTENT_WITNESS_OFFSET..];

        self.assert_canonical_packing::<AB>(builder, witness, public_values);
        for lane in 0..INTENT_WITNESS_ELEMENTS {
            builder
                .when_transition()
                .assert_eq(next_witness[lane], witness[lane]);
        }

        let raw = (0..P24_WIDTH)
            .map(|lane| {
                if lane < 15 {
                    public_values[lane].into()
                } else {
                    AB::Expr::from_u32(self.iv[lane - 15])
                }
            })
            .collect::<Vec<AB::Expr>>();
        let initial_state = matrix_expression::<AB>(&self.permutation.external_matrix, &raw);
        for lane in 0..P24_WIDTH {
            builder
                .when_first_row()
                .assert_eq(local_state[lane], initial_state[lane].clone());
        }

        for selector in 0..INTENT_STEPS {
            builder.when_first_row().assert_eq(
                selectors[selector],
                AB::F::from_u8(if selector == 0 { 1 } else { 0 }),
            );
            let expected_next_selector = if selector == 0 {
                AB::Expr::ZERO
            } else {
                selectors[selector - 1].into()
            };
            builder
                .when_transition()
                .assert_eq(next_selectors[selector], expected_next_selector);
        }

        let round_states: Vec<Vec<AB::Expr>> = (0..P24_ROUNDS)
            .map(|round| self.permutation.round_expression::<AB>(local_state, round))
            .collect();
        let public_output = public_values[INTENT_COMMITMENT_OFFSET..]
            .iter()
            .copied()
            .map(Into::into)
            .collect::<Vec<AB::Expr>>();
        for lane in 0..P24_WIDTH {
            let mut expected_next: AB::Expr = local_state[lane].into();
            for phase in 0..INTENT_PERMUTATIONS {
                for (round, round_state) in round_states.iter().enumerate() {
                    let selector = selectors[(phase * P24_ROUNDS) + round];
                    let target = if round + 1 == P24_ROUNDS && phase + 1 < INTENT_PERMUTATIONS {
                        let absorbed = (0..P24_WIDTH)
                            .map(|state_lane| {
                                let mut value = round_state[state_lane].clone();
                                let input_index = ((phase + 1) * 15) + state_lane;
                                if state_lane < 15
                                    && input_index < P24_INTENT_COMMITMENT_INPUT_ELEMENTS
                                {
                                    value += Into::<AB::Expr>::into(public_values[input_index]);
                                }
                                value
                            })
                            .collect::<Vec<AB::Expr>>();
                        matrix_expression::<AB>(&self.permutation.external_matrix, &absorbed)[lane]
                            .clone()
                    } else {
                        round_state[lane].clone()
                    };
                    expected_next += selector * (target - local_state[lane]);
                }
            }
            builder
                .when_transition()
                .assert_eq(next_state[lane], expected_next);
        }

        let first_squeeze_selector = selectors[(INTENT_ABSORB_PERMUTATIONS * P24_ROUNDS) - 1];
        for lane in 0..15 {
            builder.assert_zero(
                first_squeeze_selector
                    * (round_states[P24_ROUNDS - 1][lane].clone() - public_output[lane].clone()),
            );
        }
        let final_squeeze_selector = selectors[INTENT_STEPS - 1];
        builder.assert_zero(
            final_squeeze_selector
                * (round_states[P24_ROUNDS - 1][0].clone() - public_output[15].clone()),
        );
    }

    fn assert_canonical_packing<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        witness: &[AB::Var],
        public_values: &[AB::PublicVar],
    ) {
        for byte_index in 0..INTENT_BYTES {
            let mut recomposed: AB::Expr = AB::Expr::ZERO;
            for bit_index in 0..INTENT_BITS_PER_BYTE {
                let bit: AB::Expr = witness
                    [INTENT_BITS_OFFSET + (byte_index * INTENT_BITS_PER_BYTE) + bit_index]
                    .into();
                builder.assert_zero(bit.clone() * (bit.clone() - AB::Expr::ONE));
                recomposed += bit * AB::F::from_u32(1_u32 << bit_index);
            }
            builder.assert_eq(witness[INTENT_BYTES_OFFSET + byte_index], recomposed);
        }

        for (packed_index, public_value) in public_values
            .iter()
            .enumerate()
            .take(P24_INTENT_COMMITMENT_INPUT_ELEMENTS)
        {
            let mut recomposed: AB::Expr = AB::Expr::ZERO;
            for byte_offset in 0..3 {
                let byte_index = (packed_index * 3) + byte_offset;
                if byte_index >= INTENT_BYTES {
                    break;
                }
                let byte: AB::Expr = witness[INTENT_BYTES_OFFSET + byte_index].into();
                recomposed += byte * AB::F::from_u32(1_u32 << (byte_offset * 8));
            }
            builder.assert_eq(*public_value, recomposed);
        }
    }
}

/// Produces and independently verifies the candidate `H_INTENT` STARK.
///
/// Every packed intent element and the resulting digest are public values. The
/// typed intent is encoded canonically before proving, so this relation is an
/// executable public-statement binding rather than a privacy claim.
pub fn prove_and_verify_p24_intent(
    intent: &PrivateTransferIntentV2,
) -> Result<Poseidon2P24IntentExperimentResult, StarkExperimentError> {
    let reference = Poseidon2P24Reference::load_candidate()?;
    let private_reference = Poseidon2P24PrivacyReference::load_candidate()?;
    let intent_commitment = private_reference.hash_private_transfer_intent(intent)?;
    let encoded = intent.encode();
    let packed = byte_pack3le(encoded);
    let air = Poseidon2P24IntentAir::from_reference(&reference)?;
    let trace = build_p24_intent_trace(&air, encoded, packed);
    let public_values = packed
        .into_iter()
        .chain(intent_commitment.elements())
        .map(Val::from_u32)
        .collect::<Vec<_>>();
    proof_and_verify(&air, trace, &public_values)?;
    Ok(Poseidon2P24IntentExperimentResult {
        intent_commitment,
        trace_rows: INTENT_TRACE_ROWS,
    })
}

/// Command-friendly proof of the structural-baseline `NXIV` intent vector.
///
/// The input is a frozen externally generated vector whose bytes decode as one
/// canonical `PrivateTransferIntentV2`; it is not a wallet-created transfer.
pub fn run_p24_intent_research_smoke()
-> Result<Poseidon2P24IntentExperimentResult, StarkExperimentError> {
    let corpus = P24IntentVectorCorpusV1::frozen_external_kat_corpus();
    let intent = PrivateTransferIntentV2::decode(corpus.records()[0].intent())?;
    prove_and_verify_p24_intent(&intent)
}

fn proof_and_verify(
    air: &Poseidon2P24IntentAir,
    trace: RowMajorMatrix<Val>,
    public_values: &[Val],
) -> Result<(), StarkExperimentError> {
    let config = make_hiding_config();
    let proof = prove(&config, air, trace, public_values);
    verify(&config, air, &proof, public_values)
        .map_err(|_| StarkExperimentError::VerificationFailed)
}

pub(crate) fn build_p24_intent_trace(
    air: &Poseidon2P24IntentAir,
    encoded: [u8; INTENT_BYTES],
    packed: [u32; P24_INTENT_COMMITMENT_INPUT_ELEMENTS],
) -> RowMajorMatrix<Val> {
    build_p24_intent_trace_with_rows(air, encoded, packed, INTENT_TRACE_ROWS)
}

pub(crate) fn build_p24_intent_trace_with_rows(
    air: &Poseidon2P24IntentAir,
    encoded: [u8; INTENT_BYTES],
    packed: [u32; P24_INTENT_COMMITMENT_INPUT_ELEMENTS],
    trace_rows: usize,
) -> RowMajorMatrix<Val> {
    assert!(
        trace_rows >= INTENT_TRACE_ROWS,
        "intent trace must contain all selector steps"
    );
    let mut values = Val::zero_vec(trace_rows * INTENT_TRACE_WIDTH);
    let mut raw_state = [Val::ZERO; P24_WIDTH];
    for lane in 0..15 {
        raw_state[lane] = Val::from_u32(packed[lane]);
    }
    for (lane, value) in air.iv.into_iter().enumerate() {
        raw_state[15 + lane] = Val::from_u32(value);
    }
    let mut state = matrix_values(&air.permutation.external_matrix, &raw_state);

    for row in 0..trace_rows {
        let offset = row * INTENT_TRACE_WIDTH;
        values[offset..offset + P24_WIDTH].copy_from_slice(&state);
        write_canonical_intent_witness(&mut values[offset + INTENT_WITNESS_OFFSET..], encoded);
        if row < INTENT_STEPS {
            values[offset + INTENT_SELECTOR_OFFSET + row] = Val::ONE;
            let round = row % P24_ROUNDS;
            state = round_values(&air.permutation, state, round);
            if round + 1 == P24_ROUNDS {
                let phase = row / P24_ROUNDS;
                if phase + 1 < INTENT_PERMUTATIONS {
                    for (lane, state_lane) in state.iter_mut().enumerate().take(15) {
                        let input_index = ((phase + 1) * 15) + lane;
                        if input_index < P24_INTENT_COMMITMENT_INPUT_ELEMENTS {
                            *state_lane += Val::from_u32(packed[input_index]);
                        }
                    }
                    state = matrix_values(&air.permutation.external_matrix, &state);
                }
            }
        }
    }
    RowMajorMatrix::new(values, INTENT_TRACE_WIDTH)
}

fn write_canonical_intent_witness(witness: &mut [Val], encoded: [u8; INTENT_BYTES]) {
    for (byte_index, byte) in encoded.into_iter().enumerate() {
        witness[INTENT_BYTES_OFFSET + byte_index] = Val::from_u8(byte);
        for bit_index in 0..INTENT_BITS_PER_BYTE {
            witness[INTENT_BITS_OFFSET + (byte_index * INTENT_BITS_PER_BYTE) + bit_index] =
                Val::from_u8((byte >> bit_index) & 1);
        }
    }
}

pub(crate) fn byte_pack3le(
    input: [u8; PrivateTransferIntentV2::ENCODED_LENGTH],
) -> [u32; P24_INTENT_COMMITMENT_INPUT_ELEMENTS] {
    core::array::from_fn(|index| {
        input[index * 3..core::cmp::min((index + 1) * 3, input.len())]
            .iter()
            .enumerate()
            .fold(0_u32, |value, (offset, byte)| {
                value | (u32::from(*byte) << (offset * 8))
            })
    })
}

#[cfg(test)]
mod tests {
    use noxis_tree_params::P24IntentVectorCorpusV1;

    use super::*;

    #[test]
    fn intent_stark_matches_every_frozen_external_nxiv_vector() {
        let corpus = P24IntentVectorCorpusV1::frozen_external_kat_corpus();
        for record in corpus.records() {
            let intent = PrivateTransferIntentV2::decode(record.intent()).unwrap();
            let result = prove_and_verify_p24_intent(&intent).unwrap();

            assert_eq!(byte_pack3le(intent.encode()), *record.packed());
            assert_eq!(result.intent_commitment, record.digest());
            assert_eq!(result.trace_rows, INTENT_TRACE_ROWS);
        }
    }

    #[test]
    fn intent_air_rejects_changed_public_packing_commitment_or_private_bytes() {
        let corpus = P24IntentVectorCorpusV1::frozen_external_kat_corpus();
        let record = &corpus.records()[0];
        let intent = PrivateTransferIntentV2::decode(record.intent()).unwrap();
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        let air = Poseidon2P24IntentAir::from_reference(&reference).unwrap();
        let packed = byte_pack3le(intent.encode());
        let trace = build_p24_intent_trace(&air, intent.encode(), packed);
        let commitment = record.digest();
        let public_values = packed
            .into_iter()
            .chain(commitment.elements())
            .map(Val::from_u32)
            .collect::<Vec<_>>();
        p3_air::check_constraints(&air, &trace, &public_values);

        let assert_rejected = |trace: &RowMajorMatrix<Val>, public_values: &[Val]| {
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    p3_air::check_constraints(&air, trace, public_values);
                }))
                .is_err()
            );
        };

        let mut changed_packing = public_values.clone();
        changed_packing[19] += Val::ONE;
        assert_rejected(&trace, &changed_packing);

        let mut changed_commitment = public_values.clone();
        changed_commitment[INTENT_COMMITMENT_OFFSET] += Val::ONE;
        assert_rejected(&trace, &changed_commitment);

        let mut non_boolean_bit = trace.clone();
        for row in 0..INTENT_TRACE_ROWS {
            non_boolean_bit.values
                [row * INTENT_TRACE_WIDTH + INTENT_WITNESS_OFFSET + INTENT_BITS_OFFSET] =
                Val::from_u32(2);
        }
        assert_rejected(&non_boolean_bit, &public_values);

        let mut changed_byte = trace.clone();
        for row in 0..INTENT_TRACE_ROWS {
            changed_byte.values
                [row * INTENT_TRACE_WIDTH + INTENT_WITNESS_OFFSET + INTENT_BYTES_OFFSET] +=
                Val::ONE;
        }
        assert_rejected(&changed_byte, &public_values);

        let mut changed_last_byte = trace;
        for row in 0..INTENT_TRACE_ROWS {
            changed_last_byte.values[row * INTENT_TRACE_WIDTH
                + INTENT_WITNESS_OFFSET
                + INTENT_BYTES_OFFSET
                + INTENT_BYTES
                - 1] += Val::ONE;
        }
        assert_rejected(&changed_last_byte, &public_values);
    }
}
