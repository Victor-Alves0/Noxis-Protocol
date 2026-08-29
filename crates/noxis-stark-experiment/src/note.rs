//! Private `H_NOTE` STARK relation for the frozen P24 note-domain candidate.
//!
//! The witness is exactly the 178-byte canonical note preimage. The AIR
//! range-checks every byte with an eight-bit decomposition, reconstructs its
//! sixty `BytePack3LE` elements and proves the four absorption permutations
//! plus the prescribed squeezing permutation. Only the 16-element note
//! commitment is public.
//!
//! This is a byte-hash relation, not yet a semantic note-opening or
//! note-ownership relation. A later composed AIR must bind the recipient field
//! to `H_ADDR`, the randomness fields to `H_NULLIFIER`, and the remaining note
//! fields to transfer rules.

use noxis_poseidon2_privacy_reference::Poseidon2P24PrivacyReference;
use noxis_poseidon2_reference::{BabyBearDigestV2, P24_WIDTH, Poseidon2P24Reference};
use noxis_tree_params::{CandidatePoseidon2P24NoteDomainsManifestV1, Poseidon2P24NoteDomainV1};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{prove, verify};

use crate::{
    P24_ROUNDS, Poseidon2P24Air, StarkExperimentError, Val, make_hiding_config, matrix_expression,
    matrix_values, round_values,
};

const NOTE_INPUT_BYTES: usize = 178;
const NOTE_BITS_PER_BYTE: usize = 8;
const NOTE_INPUT_ELEMENTS: usize = 60;
const NOTE_ABSORB_PERMUTATIONS: usize = 4;
const NOTE_PERMUTATIONS: usize = NOTE_ABSORB_PERMUTATIONS + 1;
const NOTE_STEPS: usize = NOTE_PERMUTATIONS * P24_ROUNDS;
const NOTE_TRACE_ROWS: usize = 256;
const NOTE_SELECTOR_OFFSET: usize = P24_WIDTH;
const NOTE_WITNESS_OFFSET: usize = NOTE_SELECTOR_OFFSET + NOTE_STEPS;
const NOTE_BYTES_OFFSET: usize = 0;
const NOTE_BITS_OFFSET: usize = NOTE_BYTES_OFFSET + NOTE_INPUT_BYTES;
const NOTE_PACKED_OFFSET: usize = NOTE_BITS_OFFSET + (NOTE_INPUT_BYTES * NOTE_BITS_PER_BYTE);
const NOTE_WITNESS_ELEMENTS: usize = NOTE_PACKED_OFFSET + NOTE_INPUT_ELEMENTS;
const NOTE_TRACE_WIDTH: usize = NOTE_WITNESS_OFFSET + NOTE_WITNESS_ELEMENTS;
const NOTE_PUBLIC_VALUES: usize = 16;

/// Public result after an independently verified `H_NOTE` candidate proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Poseidon2P24NoteExperimentResult {
    /// The public 16-element note commitment.
    pub note_commitment: BabyBearDigestV2,
    /// Number of rows in the fixed private trace.
    pub trace_rows: usize,
}

/// AIR for the exact `NXPH v1` `H_NOTE(note_preimage)` relation.
#[derive(Clone, Debug)]
struct Poseidon2P24NoteAir {
    permutation: Poseidon2P24Air,
    iv: [u32; 9],
}

impl Poseidon2P24NoteAir {
    fn from_reference(reference: &Poseidon2P24Reference) -> Result<Self, StarkExperimentError> {
        Ok(Self {
            permutation: Poseidon2P24Air::from_reference(reference),
            iv: CandidatePoseidon2P24NoteDomainsManifestV1::new()
                .iv(Poseidon2P24NoteDomainV1::Note)?,
        })
    }
}

impl<F> BaseAir<F> for Poseidon2P24NoteAir {
    fn width(&self) -> usize {
        NOTE_TRACE_WIDTH
    }

    fn num_public_values(&self) -> usize {
        NOTE_PUBLIC_VALUES
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(8)
    }
}

impl<AB: AirBuilder> Air<AB> for Poseidon2P24NoteAir {
    fn eval(&self, builder: &mut AB) {
        let public_values = builder.public_values().to_vec();
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let local_state = &local[..P24_WIDTH];
        let next_state = &next[..P24_WIDTH];
        let selectors = &local[NOTE_SELECTOR_OFFSET..NOTE_WITNESS_OFFSET];
        let next_selectors = &next[NOTE_SELECTOR_OFFSET..NOTE_WITNESS_OFFSET];
        let witness = &local[NOTE_WITNESS_OFFSET..];
        let next_witness = &next[NOTE_WITNESS_OFFSET..];

        self.assert_private_preimage_bytes::<AB>(builder, witness);
        for lane in 0..NOTE_WITNESS_ELEMENTS {
            builder
                .when_transition()
                .assert_eq(next_witness[lane], witness[lane]);
        }

        let raw = (0..P24_WIDTH)
            .map(|lane| {
                if lane < 15 {
                    witness[NOTE_PACKED_OFFSET + lane].into()
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

        for selector in 0..NOTE_STEPS {
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
        let public_output = public_values
            .iter()
            .copied()
            .map(Into::into)
            .collect::<Vec<AB::Expr>>();
        for lane in 0..P24_WIDTH {
            let mut expected_next: AB::Expr = local_state[lane].into();
            for phase in 0..NOTE_PERMUTATIONS {
                for (round, round_state) in round_states.iter().enumerate() {
                    let selector = selectors[(phase * P24_ROUNDS) + round];
                    let target = if round + 1 == P24_ROUNDS && phase + 1 < NOTE_PERMUTATIONS {
                        let absorbed = (0..P24_WIDTH)
                            .map(|state_lane| {
                                let mut value = round_state[state_lane].clone();
                                if phase + 1 < NOTE_ABSORB_PERMUTATIONS && state_lane < 15 {
                                    value += witness
                                        [NOTE_PACKED_OFFSET + ((phase + 1) * 15) + state_lane];
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

        let first_squeeze_selector = selectors[(NOTE_ABSORB_PERMUTATIONS * P24_ROUNDS) - 1];
        for lane in 0..15 {
            builder.assert_zero(
                first_squeeze_selector
                    * (round_states[P24_ROUNDS - 1][lane].clone() - public_output[lane].clone()),
            );
        }
        let final_squeeze_selector = selectors[NOTE_STEPS - 1];
        builder.assert_zero(
            final_squeeze_selector
                * (round_states[P24_ROUNDS - 1][0].clone() - public_output[15].clone()),
        );
    }
}

impl Poseidon2P24NoteAir {
    fn assert_private_preimage_bytes<AB: AirBuilder>(&self, builder: &mut AB, witness: &[AB::Var]) {
        for byte_index in 0..NOTE_INPUT_BYTES {
            let mut recomposed: AB::Expr = AB::Expr::ZERO;
            for bit_index in 0..NOTE_BITS_PER_BYTE {
                let bit: AB::Expr = witness
                    [NOTE_BITS_OFFSET + (byte_index * NOTE_BITS_PER_BYTE) + bit_index]
                    .into();
                builder.assert_zero(bit.clone() * (bit.clone() - AB::Expr::ONE));
                recomposed += bit * AB::F::from_u32(1_u32 << bit_index);
            }
            builder.assert_eq(witness[NOTE_BYTES_OFFSET + byte_index], recomposed);
        }

        for packed_index in 0..NOTE_INPUT_ELEMENTS {
            let mut recomposed: AB::Expr = AB::Expr::ZERO;
            for byte_offset in 0..3 {
                let byte_index = (packed_index * 3) + byte_offset;
                if byte_index >= NOTE_INPUT_BYTES {
                    break;
                }
                let byte: AB::Expr = witness[NOTE_BYTES_OFFSET + byte_index].into();
                recomposed += byte * AB::F::from_u32(1_u32 << (byte_offset * 8));
            }
            builder.assert_eq(witness[NOTE_PACKED_OFFSET + packed_index], recomposed);
        }
    }
}

/// Produces and independently verifies a hiding-FRI STARK for the frozen
/// `H_NOTE(note_preimage)` candidate. The entire 178-byte preimage is private;
/// the verifier receives only `note_commitment`.
///
/// This does not validate the note fields, bind the recipient field to
/// `H_ADDR`, derive `H_NULLIFIER`, establish Merkle membership, or authorize a
/// spend.
pub fn prove_and_verify_p24_note(
    note_preimage: [u8; NOTE_INPUT_BYTES],
) -> Result<Poseidon2P24NoteExperimentResult, StarkExperimentError> {
    let reference = Poseidon2P24Reference::load_candidate()?;
    let private_reference = Poseidon2P24PrivacyReference::load_candidate()?;
    let note_commitment = private_reference.hash_note(&note_preimage)?;
    let air = Poseidon2P24NoteAir::from_reference(&reference)?;
    let trace = build_p24_note_trace(&air, note_preimage);
    let public_values = note_commitment.map(Val::from_u32);
    let config = make_hiding_config();
    let proof = prove(&config, &air, trace, &public_values);
    verify(&config, &air, &proof, &public_values)
        .map_err(|_| StarkExperimentError::VerificationFailed)?;
    Ok(Poseidon2P24NoteExperimentResult {
        note_commitment,
        trace_rows: NOTE_TRACE_ROWS,
    })
}

/// Command-friendly fixed preimage demonstration for the private `H_NOTE` proof.
pub fn run_p24_note_research_smoke()
-> Result<Poseidon2P24NoteExperimentResult, StarkExperimentError> {
    prove_and_verify_p24_note(core::array::from_fn(|index| index as u8))
}

fn build_p24_note_trace(
    air: &Poseidon2P24NoteAir,
    note_preimage: [u8; NOTE_INPUT_BYTES],
) -> RowMajorMatrix<Val> {
    let packed = byte_pack3le(note_preimage);
    let mut values = Val::zero_vec(NOTE_TRACE_ROWS * NOTE_TRACE_WIDTH);
    let mut raw_state = [Val::ZERO; P24_WIDTH];
    for lane in 0..15 {
        raw_state[lane] = Val::from_u32(packed[lane]);
    }
    for (lane, value) in air.iv.into_iter().enumerate() {
        raw_state[15 + lane] = Val::from_u32(value);
    }
    let mut state = matrix_values(&air.permutation.external_matrix, &raw_state);

    for row in 0..NOTE_TRACE_ROWS {
        let offset = row * NOTE_TRACE_WIDTH;
        values[offset..offset + P24_WIDTH].copy_from_slice(&state);
        write_private_preimage_witness(
            &mut values[offset + NOTE_WITNESS_OFFSET..],
            note_preimage,
            &packed,
        );
        if row < NOTE_STEPS {
            values[offset + NOTE_SELECTOR_OFFSET + row] = Val::ONE;
            let round = row % P24_ROUNDS;
            state = round_values(&air.permutation, state, round);
            if round + 1 == P24_ROUNDS {
                let phase = row / P24_ROUNDS;
                if phase + 1 < NOTE_PERMUTATIONS {
                    if phase + 1 < NOTE_ABSORB_PERMUTATIONS {
                        for lane in 0..15 {
                            state[lane] += Val::from_u32(packed[((phase + 1) * 15) + lane]);
                        }
                    }
                    state = matrix_values(&air.permutation.external_matrix, &state);
                }
            }
        }
    }
    RowMajorMatrix::new(values, NOTE_TRACE_WIDTH)
}

fn write_private_preimage_witness(
    witness: &mut [Val],
    note_preimage: [u8; NOTE_INPUT_BYTES],
    packed: &[u32; NOTE_INPUT_ELEMENTS],
) {
    for (byte_index, byte) in note_preimage.into_iter().enumerate() {
        witness[NOTE_BYTES_OFFSET + byte_index] = Val::from_u8(byte);
        for bit_index in 0..NOTE_BITS_PER_BYTE {
            witness[NOTE_BITS_OFFSET + (byte_index * NOTE_BITS_PER_BYTE) + bit_index] =
                Val::from_u8((byte >> bit_index) & 1);
        }
    }
    for (packed_index, value) in packed.iter().copied().enumerate() {
        witness[NOTE_PACKED_OFFSET + packed_index] = Val::from_u32(value);
    }
}

fn byte_pack3le(input: [u8; NOTE_INPUT_BYTES]) -> [u32; NOTE_INPUT_ELEMENTS] {
    core::array::from_fn(|packed_index| {
        (0..3).fold(0_u32, |packed, byte_offset| {
            let byte_index = (packed_index * 3) + byte_offset;
            if byte_index < NOTE_INPUT_BYTES {
                packed | (u32::from(input[byte_index]) << (byte_offset * 8))
            } else {
                packed
            }
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use noxis_tree_params::P24NoteVectorCorpusV1;

    #[test]
    fn note_stark_matches_the_frozen_reference_for_a_private_178_byte_preimage() {
        let preimage = core::array::from_fn(|index| (index as u8).wrapping_mul(7));
        let result = prove_and_verify_p24_note(preimage).unwrap();
        let reference = Poseidon2P24PrivacyReference::load_candidate().unwrap();

        assert_eq!(
            result.note_commitment,
            reference.hash_note(&preimage).unwrap()
        );
        assert_eq!(result.trace_rows, NOTE_TRACE_ROWS);
    }

    #[test]
    fn note_stark_matches_every_frozen_external_nxnv_vector() {
        let corpus = P24NoteVectorCorpusV1::frozen_external_kat_corpus();
        let note_records: Vec<_> = corpus
            .records()
            .iter()
            .filter(|record| record.domain() == Poseidon2P24NoteDomainV1::Note)
            .collect();
        assert_eq!(
            note_records.len(),
            2,
            "the frozen NXNV profile has two H_NOTE cases"
        );

        for record in note_records {
            let preimage: [u8; NOTE_INPUT_BYTES] = record
                .input()
                .try_into()
                .expect("H_NOTE vectors have a fixed 178-byte preimage");
            let expected = core::array::from_fn(|lane| {
                u32::from_le_bytes(
                    record.digest().as_bytes()[lane * 4..(lane + 1) * 4]
                        .try_into()
                        .expect("each digest lane has four bytes"),
                )
            });

            assert_eq!(byte_pack3le(preimage).as_slice(), record.packed());
            assert_eq!(
                prove_and_verify_p24_note(preimage).unwrap().note_commitment,
                expected
            );
        }
    }

    #[test]
    fn note_air_rejects_changed_commitment_or_noncanonical_private_preimage_witness() {
        let preimage = core::array::from_fn(|index| index as u8 + 1);
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        let private_reference = Poseidon2P24PrivacyReference::load_candidate().unwrap();
        let commitment = private_reference
            .hash_note(&preimage)
            .unwrap()
            .map(Val::from_u32);
        let air = Poseidon2P24NoteAir::from_reference(&reference).unwrap();
        let trace = build_p24_note_trace(&air, preimage);
        p3_air::check_constraints(&air, &trace, &commitment);

        let assert_rejected = |trace: &RowMajorMatrix<Val>, public_values: &[Val; 16]| {
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    p3_air::check_constraints(&air, trace, public_values);
                }))
                .is_err()
            );
        };

        let mut changed_commitment = commitment;
        changed_commitment[0] += Val::ONE;
        assert_rejected(&trace, &changed_commitment);

        let mut non_boolean_bit = trace.clone();
        for row in 0..NOTE_TRACE_ROWS {
            non_boolean_bit.values
                [row * NOTE_TRACE_WIDTH + NOTE_WITNESS_OFFSET + NOTE_BITS_OFFSET] =
                Val::from_u32(2);
        }
        assert_rejected(&non_boolean_bit, &commitment);

        let mut changed_byte = trace.clone();
        for row in 0..NOTE_TRACE_ROWS {
            changed_byte.values
                [row * NOTE_TRACE_WIDTH + NOTE_WITNESS_OFFSET + NOTE_BYTES_OFFSET] += Val::ONE;
        }
        assert_rejected(&changed_byte, &commitment);

        let mut changed_pack = trace;
        for row in 0..NOTE_TRACE_ROWS {
            changed_pack.values
                [row * NOTE_TRACE_WIDTH + NOTE_WITNESS_OFFSET + NOTE_PACKED_OFFSET] += Val::ONE;
        }
        assert_rejected(&changed_pack, &commitment);
    }
}
