//! Private `H_ADDR` STARK relation for the frozen P24 note-domain candidate.
//!
//! The witness is exactly 32 private bytes. The AIR range-checks each byte by
//! an eight-bit decomposition, reconstructs the eleven `BytePack3LE` elements
//! required by `NXPH v1`, and proves the two prescribed P24 permutations. The
//! only public value is the resulting 16-element recipient commitment.
//!
//! This establishes private address-preimage knowledge only. It does not bind
//! the key to a note, a nullifier, a Merkle leaf, a payment address, or a
//! ledger authorization.

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

const ADDR_INPUT_BYTES: usize = 32;
const ADDR_BITS_PER_BYTE: usize = 8;
const ADDR_INPUT_ELEMENTS: usize = 11;
const ADDR_PERMUTATIONS: usize = 2;
const ADDR_STEPS: usize = ADDR_PERMUTATIONS * P24_ROUNDS;
const ADDR_TRACE_ROWS: usize = 64;
const ADDR_SELECTOR_OFFSET: usize = P24_WIDTH;
const ADDR_WITNESS_OFFSET: usize = ADDR_SELECTOR_OFFSET + ADDR_STEPS;
const ADDR_BYTES_OFFSET: usize = 0;
const ADDR_BITS_OFFSET: usize = ADDR_BYTES_OFFSET + ADDR_INPUT_BYTES;
const ADDR_PACKED_OFFSET: usize = ADDR_BITS_OFFSET + (ADDR_INPUT_BYTES * ADDR_BITS_PER_BYTE);
const ADDR_WITNESS_ELEMENTS: usize = ADDR_PACKED_OFFSET + ADDR_INPUT_ELEMENTS;
const ADDR_TRACE_WIDTH: usize = ADDR_WITNESS_OFFSET + ADDR_WITNESS_ELEMENTS;
const ADDR_PUBLIC_VALUES: usize = 16;

/// Public result after an independently verified `H_ADDR` candidate proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Poseidon2P24AddrExperimentResult {
    /// The public 16-element recipient commitment.
    pub recipient_commitment: BabyBearDigestV2,
    /// Number of rows in the fixed private trace.
    pub trace_rows: usize,
}

/// AIR for the exact `NXPH v1` `H_ADDR(nullifier_key)` relation.
#[derive(Clone, Debug)]
struct Poseidon2P24AddrAir {
    permutation: Poseidon2P24Air,
    iv: [u32; 9],
}

impl Poseidon2P24AddrAir {
    fn from_reference(reference: &Poseidon2P24Reference) -> Result<Self, StarkExperimentError> {
        Ok(Self {
            permutation: Poseidon2P24Air::from_reference(reference),
            iv: CandidatePoseidon2P24NoteDomainsManifestV1::new()
                .iv(Poseidon2P24NoteDomainV1::Addr)?,
        })
    }
}

impl<F> BaseAir<F> for Poseidon2P24AddrAir {
    fn width(&self) -> usize {
        ADDR_TRACE_WIDTH
    }

    fn num_public_values(&self) -> usize {
        ADDR_PUBLIC_VALUES
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(8)
    }
}

impl<AB: AirBuilder> Air<AB> for Poseidon2P24AddrAir {
    fn eval(&self, builder: &mut AB) {
        let public_values = builder.public_values().to_vec();
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let local_state = &local[..P24_WIDTH];
        let next_state = &next[..P24_WIDTH];
        let selectors = &local[ADDR_SELECTOR_OFFSET..ADDR_WITNESS_OFFSET];
        let next_selectors = &next[ADDR_SELECTOR_OFFSET..ADDR_WITNESS_OFFSET];
        let witness = &local[ADDR_WITNESS_OFFSET..];
        let next_witness = &next[ADDR_WITNESS_OFFSET..];

        self.assert_private_key_bytes::<AB>(builder, witness);
        for lane in 0..ADDR_WITNESS_ELEMENTS {
            builder
                .when_transition()
                .assert_eq(next_witness[lane], witness[lane]);
        }

        let raw = (0..P24_WIDTH)
            .map(|lane| {
                if lane < ADDR_INPUT_ELEMENTS {
                    witness[ADDR_PACKED_OFFSET + lane].into()
                } else if lane < 15 {
                    AB::Expr::ZERO
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

        for selector in 0..ADDR_STEPS {
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
            for phase in 0..ADDR_PERMUTATIONS {
                for (round, round_state) in round_states.iter().enumerate() {
                    let selector = selectors[(phase * P24_ROUNDS) + round];
                    let target = if round + 1 == P24_ROUNDS && phase + 1 < ADDR_PERMUTATIONS {
                        matrix_expression::<AB>(&self.permutation.external_matrix, round_state)
                            [lane]
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

        let first_squeeze_selector = selectors[P24_ROUNDS - 1];
        for lane in 0..15 {
            builder.assert_zero(
                first_squeeze_selector
                    * (round_states[P24_ROUNDS - 1][lane].clone() - public_output[lane].clone()),
            );
        }
        let final_squeeze_selector = selectors[ADDR_STEPS - 1];
        builder.assert_zero(
            final_squeeze_selector
                * (round_states[P24_ROUNDS - 1][0].clone() - public_output[15].clone()),
        );
    }
}

impl Poseidon2P24AddrAir {
    fn assert_private_key_bytes<AB: AirBuilder>(&self, builder: &mut AB, witness: &[AB::Var]) {
        for byte_index in 0..ADDR_INPUT_BYTES {
            let mut recomposed: AB::Expr = AB::Expr::ZERO;
            for bit_index in 0..ADDR_BITS_PER_BYTE {
                let bit: AB::Expr = witness
                    [ADDR_BITS_OFFSET + (byte_index * ADDR_BITS_PER_BYTE) + bit_index]
                    .into();
                builder.assert_zero(bit.clone() * (bit.clone() - AB::Expr::ONE));
                recomposed += bit * AB::F::from_u32(1_u32 << bit_index);
            }
            builder.assert_eq(witness[ADDR_BYTES_OFFSET + byte_index], recomposed);
        }

        for packed_index in 0..ADDR_INPUT_ELEMENTS {
            let mut recomposed: AB::Expr = AB::Expr::ZERO;
            for byte_offset in 0..3 {
                let byte_index = (packed_index * 3) + byte_offset;
                if byte_index >= ADDR_INPUT_BYTES {
                    break;
                }
                let byte: AB::Expr = witness[ADDR_BYTES_OFFSET + byte_index].into();
                recomposed += byte * AB::F::from_u32(1_u32 << (byte_offset * 8));
            }
            builder.assert_eq(witness[ADDR_PACKED_OFFSET + packed_index], recomposed);
        }
    }
}

/// Produces and independently verifies a hiding-FRI STARK for the frozen
/// `H_ADDR(nullifier_key)` candidate. The 32-byte key is private throughout;
/// the verifier receives only `recipient_commitment`.
///
/// This is not yet a spend authorization: it is not tied to `H_NOTE`,
/// `H_NULLIFIER`, a Merkle path, the hybrid wallet keys, or ledger state.
pub fn prove_and_verify_p24_addr(
    nullifier_key: [u8; ADDR_INPUT_BYTES],
) -> Result<Poseidon2P24AddrExperimentResult, StarkExperimentError> {
    let reference = Poseidon2P24Reference::load_candidate()?;
    let private_reference = Poseidon2P24PrivacyReference::load_candidate()?;
    let recipient_commitment = private_reference.hash_addr(&nullifier_key)?;
    let air = Poseidon2P24AddrAir::from_reference(&reference)?;
    let trace = build_p24_addr_trace(&air, nullifier_key);
    let public_values = recipient_commitment.map(Val::from_u32);
    let config = make_hiding_config();
    let proof = prove(&config, &air, trace, &public_values);
    verify(&config, &air, &proof, &public_values)
        .map_err(|_| StarkExperimentError::VerificationFailed)?;
    Ok(Poseidon2P24AddrExperimentResult {
        recipient_commitment,
        trace_rows: ADDR_TRACE_ROWS,
    })
}

/// Command-friendly fixed key demonstration for the private `H_ADDR` proof.
pub fn run_p24_addr_research_smoke()
-> Result<Poseidon2P24AddrExperimentResult, StarkExperimentError> {
    prove_and_verify_p24_addr(core::array::from_fn(|index| index as u8))
}

fn build_p24_addr_trace(
    air: &Poseidon2P24AddrAir,
    nullifier_key: [u8; ADDR_INPUT_BYTES],
) -> RowMajorMatrix<Val> {
    let packed = byte_pack3le(nullifier_key);
    let mut values = Val::zero_vec(ADDR_TRACE_ROWS * ADDR_TRACE_WIDTH);
    let mut raw_state = [Val::ZERO; P24_WIDTH];
    for (lane, value) in packed.iter().copied().enumerate() {
        raw_state[lane] = Val::from_u32(value);
    }
    for (lane, value) in air.iv.into_iter().enumerate() {
        raw_state[15 + lane] = Val::from_u32(value);
    }
    let mut state = matrix_values(&air.permutation.external_matrix, &raw_state);

    for row in 0..ADDR_TRACE_ROWS {
        let offset = row * ADDR_TRACE_WIDTH;
        values[offset..offset + P24_WIDTH].copy_from_slice(&state);
        write_private_key_witness(
            &mut values[offset + ADDR_WITNESS_OFFSET..],
            nullifier_key,
            &packed,
        );
        if row < ADDR_STEPS {
            values[offset + ADDR_SELECTOR_OFFSET + row] = Val::ONE;
            let round = row % P24_ROUNDS;
            state = round_values(&air.permutation, state, round);
            if round + 1 == P24_ROUNDS && (row / P24_ROUNDS) + 1 < ADDR_PERMUTATIONS {
                state = matrix_values(&air.permutation.external_matrix, &state);
            }
        }
    }
    RowMajorMatrix::new(values, ADDR_TRACE_WIDTH)
}

fn write_private_key_witness(
    witness: &mut [Val],
    nullifier_key: [u8; ADDR_INPUT_BYTES],
    packed: &[u32; ADDR_INPUT_ELEMENTS],
) {
    for (byte_index, byte) in nullifier_key.into_iter().enumerate() {
        witness[ADDR_BYTES_OFFSET + byte_index] = Val::from_u8(byte);
        for bit_index in 0..ADDR_BITS_PER_BYTE {
            witness[ADDR_BITS_OFFSET + (byte_index * ADDR_BITS_PER_BYTE) + bit_index] =
                Val::from_u8((byte >> bit_index) & 1);
        }
    }
    for (packed_index, value) in packed.iter().copied().enumerate() {
        witness[ADDR_PACKED_OFFSET + packed_index] = Val::from_u32(value);
    }
}

fn byte_pack3le(input: [u8; ADDR_INPUT_BYTES]) -> [u32; ADDR_INPUT_ELEMENTS] {
    core::array::from_fn(|packed_index| {
        (0..3).fold(0_u32, |packed, byte_offset| {
            let byte_index = (packed_index * 3) + byte_offset;
            if byte_index < ADDR_INPUT_BYTES {
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
    fn addr_stark_matches_the_frozen_reference_for_a_private_32_byte_key() {
        let key = core::array::from_fn(|index| (index as u8).wrapping_mul(7));
        let result = prove_and_verify_p24_addr(key).unwrap();
        let reference = Poseidon2P24PrivacyReference::load_candidate().unwrap();

        assert_eq!(
            result.recipient_commitment,
            reference.hash_addr(&key).unwrap()
        );
        assert_eq!(result.trace_rows, ADDR_TRACE_ROWS);
    }

    #[test]
    fn addr_stark_matches_every_frozen_external_nxnv_vector() {
        let corpus = P24NoteVectorCorpusV1::frozen_external_kat_corpus();
        let addr_records: Vec<_> = corpus
            .records()
            .iter()
            .filter(|record| record.domain() == Poseidon2P24NoteDomainV1::Addr)
            .collect();
        assert_eq!(
            addr_records.len(),
            2,
            "the frozen NXNV profile has two H_ADDR cases"
        );

        for record in addr_records {
            let key: [u8; ADDR_INPUT_BYTES] = record
                .input()
                .try_into()
                .expect("H_ADDR vectors have a fixed 32-byte preimage");
            let expected = core::array::from_fn(|lane| {
                u32::from_le_bytes(
                    record.digest().as_bytes()[lane * 4..(lane + 1) * 4]
                        .try_into()
                        .expect("each digest lane has four bytes"),
                )
            });

            assert_eq!(byte_pack3le(key).as_slice(), record.packed());
            assert_eq!(
                prove_and_verify_p24_addr(key).unwrap().recipient_commitment,
                expected
            );
        }
    }

    #[test]
    fn addr_air_rejects_changed_commitment_or_noncanonical_private_key_witness() {
        let key = core::array::from_fn(|index| index as u8 + 1);
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        let private_reference = Poseidon2P24PrivacyReference::load_candidate().unwrap();
        let commitment = private_reference
            .hash_addr(&key)
            .unwrap()
            .map(Val::from_u32);
        let air = Poseidon2P24AddrAir::from_reference(&reference).unwrap();
        let trace = build_p24_addr_trace(&air, key);
        assert_eq!(trace.values[ADDR_STEPS * ADDR_TRACE_WIDTH], commitment[15]);
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
        for row in 0..ADDR_TRACE_ROWS {
            non_boolean_bit.values
                [row * ADDR_TRACE_WIDTH + ADDR_WITNESS_OFFSET + ADDR_BITS_OFFSET] =
                Val::from_u32(2);
        }
        assert_rejected(&non_boolean_bit, &commitment);

        let mut changed_byte = trace.clone();
        for row in 0..ADDR_TRACE_ROWS {
            changed_byte.values
                [row * ADDR_TRACE_WIDTH + ADDR_WITNESS_OFFSET + ADDR_BYTES_OFFSET] += Val::ONE;
        }
        assert_rejected(&changed_byte, &commitment);

        let mut changed_pack = trace;
        for row in 0..ADDR_TRACE_ROWS {
            changed_pack.values
                [row * ADDR_TRACE_WIDTH + ADDR_WITNESS_OFFSET + ADDR_PACKED_OFFSET] += Val::ONE;
        }
        assert_rejected(&changed_pack, &commitment);
    }
}
