//! One private 2x2 value-conservation relation bound to four exact `H_NOTE`
//! openings.
//!
//! This is intentionally an intermediate research relation rather than a
//! transfer proof. It proves four private canonical note preimages hash to
//! four public commitments, all four use one public asset, both input values
//! are non-zero, neither two-note sum overflows `u128`, and the two sums are
//! equal. The 16-byte values never appear in the public input.
//!
//! Publishing input commitments would undermine transaction privacy, so this
//! relation is currently used only as a local, opaque proof experiment. A
//! later complete AIR must bind its input notes to membership/nullifier
//! relations and its outputs to the transaction intent and envelopes, while
//! retaining only the protocol-approved public statement.

use noxis_poseidon2_privacy_reference::Poseidon2P24PrivacyReference;
use noxis_poseidon2_reference::{BabyBearDigestV2, P24_WIDTH, Poseidon2P24Reference};
use noxis_tree_params::{CandidatePoseidon2P24NoteDomainsManifestV1, Poseidon2P24NoteDomainV1};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{prove, verify};

use crate::{
    P24_ROUNDS, Poseidon2P24Air, StarkExperimentError, Val, make_hiding_config, matrix_expression,
    matrix_values, round_values,
};

const NOTE_COUNT: usize = 4;
const INPUT_NOTE_COUNT: usize = 2;
const NOTE_INPUT_BYTES: usize = 178;
const NOTE_BITS_PER_BYTE: usize = 8;
const NOTE_INPUT_ELEMENTS: usize = 60;
const NOTE_ABSORB_PERMUTATIONS: usize = 4;
const NOTE_PERMUTATIONS: usize = NOTE_ABSORB_PERMUTATIONS + 1;
const NOTE_STEPS: usize = NOTE_PERMUTATIONS * P24_ROUNDS;
const TRACE_ROWS: usize = 256;
const NOTE_SELECTOR_OFFSET: usize = P24_WIDTH;
const NOTE_WITNESS_OFFSET: usize = NOTE_SELECTOR_OFFSET + NOTE_STEPS;
const NOTE_BYTES_OFFSET: usize = 0;
const NOTE_BITS_OFFSET: usize = NOTE_BYTES_OFFSET + NOTE_INPUT_BYTES;
const NOTE_PACKED_OFFSET: usize = NOTE_BITS_OFFSET + (NOTE_INPUT_BYTES * NOTE_BITS_PER_BYTE);
const NOTE_WITNESS_ELEMENTS: usize = NOTE_PACKED_OFFSET + NOTE_INPUT_ELEMENTS;
const NOTE_TRACE_WIDTH: usize = NOTE_WITNESS_OFFSET + NOTE_WITNESS_ELEMENTS;
const NOTE_COMMITMENT_PUBLIC_VALUES: usize = 16;
const ASSET_BYTES: usize = 32;
const NOTE_VERSION_OFFSET: usize = 0;
const NOTE_ASSET_OFFSET: usize = 2;
const NOTE_VALUE_OFFSET: usize = NOTE_ASSET_OFFSET + ASSET_BYTES;
const VALUE_BYTES: usize = 16;
const ARITHMETIC_SELECTOR_OFFSET: usize = 0;
const ARITHMETIC_INPUT_CARRY_OFFSET: usize = ARITHMETIC_SELECTOR_OFFSET + VALUE_BYTES;
const ARITHMETIC_OUTPUT_CARRY_OFFSET: usize = ARITHMETIC_INPUT_CARRY_OFFSET + 1;
const ARITHMETIC_INPUT_ZERO_INVERSE_OFFSET: usize = ARITHMETIC_OUTPUT_CARRY_OFFSET + 1;
const ARITHMETIC_WIDTH: usize = ARITHMETIC_INPUT_ZERO_INVERSE_OFFSET + INPUT_NOTE_COUNT;
const ARITHMETIC_OFFSET: usize = NOTE_COUNT * NOTE_TRACE_WIDTH;
const TRACE_WIDTH: usize = ARITHMETIC_OFFSET + ARITHMETIC_WIDTH;
const COMMITMENT_PUBLIC_VALUES: usize = NOTE_COUNT * NOTE_COMMITMENT_PUBLIC_VALUES;
const PUBLIC_VALUES: usize = COMMITMENT_PUBLIC_VALUES + ASSET_BYTES;
const OUTPUT_COMMITMENT_PUBLIC_VALUES: usize =
    (NOTE_COUNT - INPUT_NOTE_COUNT) * NOTE_COMMITMENT_PUBLIC_VALUES;
const OUTPUT_COMMITMENT_BINDINGS_OFFSET: usize = PUBLIC_VALUES;
const PUBLIC_VALUES_WITH_OUTPUT_BINDINGS: usize = PUBLIC_VALUES + OUTPUT_COMMITMENT_PUBLIC_VALUES;

/// Public result after one independently verified 2x2 value-conservation
/// experiment. Values and all other note fields remain private.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Poseidon2P24ValueConservationExperimentResult {
    /// Commitments to the two private input notes followed by the two outputs.
    /// They are research-only local public inputs; they are not a Noxis wire
    /// format and must not be published as a transaction statement.
    pub note_commitments: [BabyBearDigestV2; NOTE_COUNT],
    /// The only note semantic field exposed by this relation.
    pub asset_id: [u8; ASSET_BYTES],
    /// Fixed height of the hiding-FRI trace.
    pub trace_rows: usize,
}

#[derive(Clone, Debug)]
struct Poseidon2P24ValueConservationAir {
    permutation: Poseidon2P24Air,
    note_iv: [u32; 9],
    bind_output_commitments: bool,
}

impl Poseidon2P24ValueConservationAir {
    fn from_reference(
        reference: &Poseidon2P24Reference,
        bind_output_commitments: bool,
    ) -> Result<Self, StarkExperimentError> {
        Ok(Self {
            permutation: Poseidon2P24Air::from_reference(reference),
            note_iv: CandidatePoseidon2P24NoteDomainsManifestV1::new()
                .iv(Poseidon2P24NoteDomainV1::Note)?,
            bind_output_commitments,
        })
    }

    fn assert_note_relation<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        local: &[AB::Var],
        next: &[AB::Var],
        public_values: &[AB::PublicVar],
        commitment_offset: usize,
    ) {
        let local_state = &local[..P24_WIDTH];
        let next_state = &next[..P24_WIDTH];
        let selectors = &local[NOTE_SELECTOR_OFFSET..NOTE_WITNESS_OFFSET];
        let next_selectors = &next[NOTE_SELECTOR_OFFSET..NOTE_WITNESS_OFFSET];
        let witness = &local[NOTE_WITNESS_OFFSET..];
        let next_witness = &next[NOTE_WITNESS_OFFSET..];

        self.assert_private_preimage_bytes(builder, witness);
        builder.when_first_row().assert_eq(
            witness[NOTE_BYTES_OFFSET + NOTE_VERSION_OFFSET],
            AB::F::ZERO,
        );
        builder.when_first_row().assert_eq(
            witness[NOTE_BYTES_OFFSET + NOTE_VERSION_OFFSET + 1],
            AB::F::ONE,
        );
        for byte_index in 0..ASSET_BYTES {
            builder.assert_eq(
                witness[NOTE_BYTES_OFFSET + NOTE_ASSET_OFFSET + byte_index],
                public_values[COMMITMENT_PUBLIC_VALUES + byte_index],
            );
        }
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
                    AB::Expr::from_u32(self.note_iv[lane - 15])
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
            [commitment_offset..commitment_offset + NOTE_COMMITMENT_PUBLIC_VALUES]
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

    fn assert_value_relation<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        note_witnesses: [&[AB::Var]; NOTE_COUNT],
        arithmetic: &[AB::Var],
        next_arithmetic: &[AB::Var],
    ) {
        let selectors = &arithmetic[ARITHMETIC_SELECTOR_OFFSET..ARITHMETIC_INPUT_CARRY_OFFSET];
        let next_selectors =
            &next_arithmetic[ARITHMETIC_SELECTOR_OFFSET..ARITHMETIC_INPUT_CARRY_OFFSET];
        let input_carry = arithmetic[ARITHMETIC_INPUT_CARRY_OFFSET];
        let output_carry = arithmetic[ARITHMETIC_OUTPUT_CARRY_OFFSET];
        let next_input_carry = next_arithmetic[ARITHMETIC_INPUT_CARRY_OFFSET];
        let next_output_carry = next_arithmetic[ARITHMETIC_OUTPUT_CARRY_OFFSET];

        for selector in 0..VALUE_BYTES {
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

        builder.when_first_row().assert_eq(input_carry, AB::F::ZERO);
        builder
            .when_first_row()
            .assert_eq(output_carry, AB::F::ZERO);
        for carry in [
            input_carry,
            output_carry,
            next_input_carry,
            next_output_carry,
        ] {
            let carry: AB::Expr = carry.into();
            builder.assert_zero(carry.clone() * (carry - AB::Expr::ONE));
        }

        for input_index in 0..INPUT_NOTE_COUNT {
            let byte_sum = (0..VALUE_BYTES).fold(AB::Expr::ZERO, |sum, byte_index| {
                sum + note_witnesses[input_index]
                    [NOTE_BYTES_OFFSET + NOTE_VALUE_OFFSET + byte_index]
            });
            let inverse: AB::Expr =
                arithmetic[ARITHMETIC_INPUT_ZERO_INVERSE_OFFSET + input_index].into();
            builder
                .when_first_row()
                .assert_eq(byte_sum * inverse, AB::Expr::ONE);
        }

        for (byte_step, selector) in selectors.iter().copied().enumerate() {
            let selector: AB::Expr = selector.into();
            let value_byte_index =
                NOTE_BYTES_OFFSET + NOTE_VALUE_OFFSET + VALUE_BYTES - 1 - byte_step;
            let input_sum: AB::Expr = note_witnesses[0][value_byte_index].into();
            let input_sum = input_sum + note_witnesses[1][value_byte_index] + input_carry;
            let output_sum: AB::Expr = note_witnesses[2][value_byte_index].into();
            let output_sum = output_sum + note_witnesses[3][value_byte_index] + output_carry;
            let carry_difference: AB::Expr = next_input_carry.into();
            let carry_difference = carry_difference - next_output_carry;
            builder.assert_zero(
                selector * (input_sum - output_sum - carry_difference * AB::F::from_u32(256)),
            );
        }

        let last_selector = selectors[VALUE_BYTES - 1];
        builder.assert_zero(last_selector * next_input_carry);
        builder.assert_zero(last_selector * next_output_carry);
    }
}

impl<F> BaseAir<F> for Poseidon2P24ValueConservationAir {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }

    fn num_public_values(&self) -> usize {
        if self.bind_output_commitments {
            PUBLIC_VALUES_WITH_OUTPUT_BINDINGS
        } else {
            PUBLIC_VALUES
        }
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(8)
    }
}

impl<AB: AirBuilder> Air<AB> for Poseidon2P24ValueConservationAir {
    fn eval(&self, builder: &mut AB) {
        let public_values = builder.public_values().to_vec();
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let mut note_witnesses = Vec::with_capacity(NOTE_COUNT);
        for note_index in 0..NOTE_COUNT {
            let start = note_index * NOTE_TRACE_WIDTH;
            self.assert_note_relation(
                builder,
                &local[start..start + NOTE_TRACE_WIDTH],
                &next[start..start + NOTE_TRACE_WIDTH],
                &public_values,
                note_index * NOTE_COMMITMENT_PUBLIC_VALUES,
            );
            note_witnesses.push(&local[start + NOTE_WITNESS_OFFSET..start + NOTE_TRACE_WIDTH]);
        }
        if self.bind_output_commitments {
            for output_index in 0..NOTE_COUNT - INPUT_NOTE_COUNT {
                for lane in 0..NOTE_COMMITMENT_PUBLIC_VALUES {
                    builder.assert_eq(
                        public_values[(INPUT_NOTE_COUNT + output_index)
                            * NOTE_COMMITMENT_PUBLIC_VALUES
                            + lane],
                        public_values[OUTPUT_COMMITMENT_BINDINGS_OFFSET
                            + (output_index * NOTE_COMMITMENT_PUBLIC_VALUES)
                            + lane],
                    );
                }
            }
        }
        let arithmetic = &local[ARITHMETIC_OFFSET..];
        let next_arithmetic = &next[ARITHMETIC_OFFSET..];
        self.assert_value_relation(
            builder,
            [
                note_witnesses[0],
                note_witnesses[1],
                note_witnesses[2],
                note_witnesses[3],
            ],
            arithmetic,
            next_arithmetic,
        );
    }
}

/// Produces and independently verifies one hiding-FRI STARK for four private
/// `H_NOTE` openings and their 2x2 value-conservation relation.
///
/// The supplied order is two inputs followed by two outputs. This API is
/// deliberately in-memory only and returns no portable proof artifact.
pub fn prove_and_verify_p24_value_conservation(
    note_preimages: [[u8; NOTE_INPUT_BYTES]; NOTE_COUNT],
    asset_id: [u8; ASSET_BYTES],
) -> Result<Poseidon2P24ValueConservationExperimentResult, StarkExperimentError> {
    prove_and_verify_value_conservation(note_preimages, asset_id, None)
}

/// Produces and independently verifies the four-note conservation relation
/// while also constraining both output `H_NOTE` commitments to the two public
/// output slots supplied by the caller.
///
/// The slots are public research inputs only. A caller must still prove that
/// they belong to the exact canonical `H_INTENT` statement before treating
/// this as any part of a transfer relation.
pub fn prove_and_verify_p24_value_conservation_bound_outputs(
    note_preimages: [[u8; NOTE_INPUT_BYTES]; NOTE_COUNT],
    asset_id: [u8; ASSET_BYTES],
    output_commitments: [BabyBearDigestV2; NOTE_COUNT - INPUT_NOTE_COUNT],
) -> Result<Poseidon2P24ValueConservationExperimentResult, StarkExperimentError> {
    prove_and_verify_value_conservation(note_preimages, asset_id, Some(output_commitments))
}

fn prove_and_verify_value_conservation(
    note_preimages: [[u8; NOTE_INPUT_BYTES]; NOTE_COUNT],
    asset_id: [u8; ASSET_BYTES],
    output_commitments: Option<[BabyBearDigestV2; NOTE_COUNT - INPUT_NOTE_COUNT]>,
) -> Result<Poseidon2P24ValueConservationExperimentResult, StarkExperimentError> {
    validate_witness_values(&note_preimages, asset_id, output_commitments)?;
    let bind_output_commitments = output_commitments.is_some();
    let reference = Poseidon2P24Reference::load_candidate()?;
    let private_reference = Poseidon2P24PrivacyReference::load_candidate()?;
    let note_commitments: [BabyBearDigestV2; NOTE_COUNT] = note_preimages
        .iter()
        .map(|preimage| private_reference.hash_note(preimage))
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .expect("fixed four-note conservation relation");
    let air =
        Poseidon2P24ValueConservationAir::from_reference(&reference, bind_output_commitments)?;
    let trace = build_trace(&air, note_preimages);
    let mut public_values = Vec::with_capacity(PUBLIC_VALUES);
    for commitment in note_commitments {
        public_values.extend(commitment.map(Val::from_u32));
    }
    public_values.extend(asset_id.map(Val::from_u8));
    if let Some(output_commitments) = output_commitments {
        for commitment in output_commitments {
            public_values.extend(commitment.map(Val::from_u32));
        }
    }
    debug_assert_eq!(
        public_values.len(),
        if bind_output_commitments {
            PUBLIC_VALUES_WITH_OUTPUT_BINDINGS
        } else {
            PUBLIC_VALUES
        }
    );
    let config = make_hiding_config();
    let proof = prove(&config, &air, trace, &public_values);
    verify(&config, &air, &proof, &public_values)
        .map_err(|_| StarkExperimentError::VerificationFailed)?;
    Ok(Poseidon2P24ValueConservationExperimentResult {
        note_commitments,
        asset_id,
        trace_rows: TRACE_ROWS,
    })
}

fn validate_witness_values(
    note_preimages: &[[u8; NOTE_INPUT_BYTES]; NOTE_COUNT],
    asset_id: [u8; ASSET_BYTES],
    output_commitments: Option<[BabyBearDigestV2; NOTE_COUNT - INPUT_NOTE_COUNT]>,
) -> Result<(), StarkExperimentError> {
    for (index, note) in note_preimages.iter().enumerate() {
        if note[NOTE_VERSION_OFFSET..NOTE_VERSION_OFFSET + 2] != 1_u16.to_be_bytes() {
            return Err(StarkExperimentError::UnsupportedValueConservationNoteVersion { index });
        }
        if note[NOTE_ASSET_OFFSET..NOTE_ASSET_OFFSET + ASSET_BYTES] != asset_id {
            return Err(StarkExperimentError::ValueConservationAssetMismatch { index });
        }
        if u128::from_be_bytes(
            note[NOTE_VALUE_OFFSET..NOTE_VALUE_OFFSET + VALUE_BYTES]
                .try_into()
                .expect("fixed value slice"),
        ) == 0
            && index < INPUT_NOTE_COUNT
        {
            return Err(StarkExperimentError::ZeroValueConservationInput { index });
        }
    }
    let input_sum = value(&note_preimages[0])
        .checked_add(value(&note_preimages[1]))
        .ok_or(StarkExperimentError::ValueConservationInputOverflow)?;
    let output_sum = value(&note_preimages[2])
        .checked_add(value(&note_preimages[3]))
        .ok_or(StarkExperimentError::ValueConservationOutputOverflow)?;
    if input_sum != output_sum {
        return Err(StarkExperimentError::ValueConservationMismatch);
    }
    if let Some(output_commitments) = output_commitments {
        let reference = Poseidon2P24PrivacyReference::load_candidate()?;
        for output_index in 0..NOTE_COUNT - INPUT_NOTE_COUNT {
            if reference.hash_note(&note_preimages[INPUT_NOTE_COUNT + output_index])?
                != output_commitments[output_index]
            {
                return Err(
                    StarkExperimentError::ValueConservationOutputCommitmentMismatch {
                        index: output_index,
                    },
                );
            }
        }
    }
    Ok(())
}

fn value(note: &[u8; NOTE_INPUT_BYTES]) -> u128 {
    u128::from_be_bytes(
        note[NOTE_VALUE_OFFSET..NOTE_VALUE_OFFSET + VALUE_BYTES]
            .try_into()
            .expect("fixed value slice"),
    )
}

fn build_trace(
    air: &Poseidon2P24ValueConservationAir,
    note_preimages: [[u8; NOTE_INPUT_BYTES]; NOTE_COUNT],
) -> RowMajorMatrix<Val> {
    let packed = note_preimages.map(byte_pack3le);
    let mut values = Val::zero_vec(TRACE_ROWS * TRACE_WIDTH);
    let mut states: [[Val; P24_WIDTH]; NOTE_COUNT] =
        core::array::from_fn(|note_index| initial_note_state(air, &packed[note_index]));
    let mut input_carry = 0_u16;
    let mut output_carry = 0_u16;
    let input_inverse = input_nonzero_inverse(&note_preimages[0]);
    let second_input_inverse = input_nonzero_inverse(&note_preimages[1]);

    for row in 0..TRACE_ROWS {
        let row_offset = row * TRACE_WIDTH;
        for note_index in 0..NOTE_COUNT {
            let offset = row_offset + (note_index * NOTE_TRACE_WIDTH);
            values[offset..offset + P24_WIDTH].copy_from_slice(&states[note_index]);
            write_private_preimage_witness(
                &mut values[offset + NOTE_WITNESS_OFFSET..offset + NOTE_TRACE_WIDTH],
                note_preimages[note_index],
                &packed[note_index],
            );
            if row < NOTE_STEPS {
                values[offset + NOTE_SELECTOR_OFFSET + row] = Val::ONE;
                let round = row % P24_ROUNDS;
                states[note_index] = round_values(&air.permutation, states[note_index], round);
                if round + 1 == P24_ROUNDS {
                    let phase = row / P24_ROUNDS;
                    if phase + 1 < NOTE_PERMUTATIONS {
                        if phase + 1 < NOTE_ABSORB_PERMUTATIONS {
                            for lane in 0..15 {
                                states[note_index][lane] +=
                                    Val::from_u32(packed[note_index][((phase + 1) * 15) + lane]);
                            }
                        }
                        states[note_index] =
                            matrix_values(&air.permutation.external_matrix, &states[note_index]);
                    }
                }
            }
        }

        let arithmetic_offset = row_offset + ARITHMETIC_OFFSET;
        values[arithmetic_offset + ARITHMETIC_INPUT_CARRY_OFFSET] =
            Val::from_u32(input_carry.into());
        values[arithmetic_offset + ARITHMETIC_OUTPUT_CARRY_OFFSET] =
            Val::from_u32(output_carry.into());
        values[arithmetic_offset + ARITHMETIC_INPUT_ZERO_INVERSE_OFFSET] = input_inverse;
        values[arithmetic_offset + ARITHMETIC_INPUT_ZERO_INVERSE_OFFSET + 1] = second_input_inverse;
        if row < VALUE_BYTES {
            values[arithmetic_offset + ARITHMETIC_SELECTOR_OFFSET + row] = Val::ONE;
            let byte_index = NOTE_VALUE_OFFSET + VALUE_BYTES - 1 - row;
            let next_input = u16::from(note_preimages[0][byte_index])
                + u16::from(note_preimages[1][byte_index])
                + input_carry;
            let next_output = u16::from(note_preimages[2][byte_index])
                + u16::from(note_preimages[3][byte_index])
                + output_carry;
            input_carry = next_input / 256;
            output_carry = next_output / 256;
        }
    }
    RowMajorMatrix::new(values, TRACE_WIDTH)
}

fn initial_note_state(
    air: &Poseidon2P24ValueConservationAir,
    packed: &[u32; NOTE_INPUT_ELEMENTS],
) -> [Val; P24_WIDTH] {
    let mut raw = [Val::ZERO; P24_WIDTH];
    for lane in 0..15 {
        raw[lane] = Val::from_u32(packed[lane]);
    }
    for (lane, value) in air.note_iv.into_iter().enumerate() {
        raw[15 + lane] = Val::from_u32(value);
    }
    matrix_values(&air.permutation.external_matrix, &raw)
}

fn input_nonzero_inverse(note: &[u8; NOTE_INPUT_BYTES]) -> Val {
    let byte_sum = note[NOTE_VALUE_OFFSET..NOTE_VALUE_OFFSET + VALUE_BYTES]
        .iter()
        .fold(0_u32, |sum, byte| sum + u32::from(*byte));
    debug_assert_ne!(byte_sum, 0);
    Val::from_u32(byte_sum).inverse()
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

    fn notes(asset: [u8; ASSET_BYTES]) -> [[u8; NOTE_INPUT_BYTES]; NOTE_COUNT] {
        let values = [40_u128, 60, 45, 55];
        core::array::from_fn(|note_index| {
            let mut note = core::array::from_fn(|index| {
                (index as u8).wrapping_add((note_index as u8).wrapping_mul(37))
            });
            note[NOTE_VERSION_OFFSET..NOTE_VERSION_OFFSET + 2]
                .copy_from_slice(&1_u16.to_be_bytes());
            note[NOTE_ASSET_OFFSET..NOTE_ASSET_OFFSET + ASSET_BYTES].copy_from_slice(&asset);
            note[NOTE_VALUE_OFFSET..NOTE_VALUE_OFFSET + VALUE_BYTES]
                .copy_from_slice(&values[note_index].to_be_bytes());
            note
        })
    }

    #[test]
    fn conservation_stark_binds_four_private_notes_and_private_balanced_values() {
        let asset = [0xA5; ASSET_BYTES];
        let note_preimages = notes(asset);
        let reference = Poseidon2P24PrivacyReference::load_candidate().unwrap();
        let output_commitments = core::array::from_fn(|output_index| {
            reference
                .hash_note(&note_preimages[INPUT_NOTE_COUNT + output_index])
                .unwrap()
        });
        let result = prove_and_verify_p24_value_conservation_bound_outputs(
            note_preimages,
            asset,
            output_commitments,
        )
        .unwrap();

        assert_eq!(
            result.note_commitments,
            note_preimages.map(|note| reference.hash_note(&note).unwrap())
        );
        assert_eq!(result.asset_id, asset);
        assert_eq!(result.trace_rows, TRACE_ROWS);
    }

    #[test]
    fn conservation_rejects_invalid_local_witnesses_before_proving() {
        let asset = [0xA5; ASSET_BYTES];
        let mut unbalanced = notes(asset);
        unbalanced[3][NOTE_VALUE_OFFSET..NOTE_VALUE_OFFSET + VALUE_BYTES]
            .copy_from_slice(&56_u128.to_be_bytes());
        assert!(matches!(
            prove_and_verify_p24_value_conservation(unbalanced, asset),
            Err(StarkExperimentError::ValueConservationMismatch)
        ));

        let mut zero_input = notes(asset);
        zero_input[0][NOTE_VALUE_OFFSET..NOTE_VALUE_OFFSET + VALUE_BYTES]
            .copy_from_slice(&0_u128.to_be_bytes());
        assert!(matches!(
            prove_and_verify_p24_value_conservation(zero_input, asset),
            Err(StarkExperimentError::ZeroValueConservationInput { index: 0 })
        ));

        let mut wrong_asset = notes(asset);
        wrong_asset[2][NOTE_ASSET_OFFSET] ^= 1;
        assert!(matches!(
            prove_and_verify_p24_value_conservation(wrong_asset, asset),
            Err(StarkExperimentError::ValueConservationAssetMismatch { index: 2 })
        ));

        let reference = Poseidon2P24PrivacyReference::load_candidate().unwrap();
        let invalid_notes = notes(asset);
        let mut wrong_output_commitments = core::array::from_fn(|output_index| {
            reference
                .hash_note(&invalid_notes[INPUT_NOTE_COUNT + output_index])
                .unwrap()
        });
        wrong_output_commitments[0][0] += 1;
        assert!(matches!(
            prove_and_verify_p24_value_conservation_bound_outputs(
                notes(asset),
                asset,
                wrong_output_commitments,
            ),
            Err(StarkExperimentError::ValueConservationOutputCommitmentMismatch { index: 0 })
        ));
    }

    #[test]
    fn conservation_air_rejects_tampered_value_or_asset_witness() {
        let asset = [0xA5; ASSET_BYTES];
        let note_preimages = notes(asset);
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        let private_reference = Poseidon2P24PrivacyReference::load_candidate().unwrap();
        let air = Poseidon2P24ValueConservationAir::from_reference(&reference, false).unwrap();
        let trace = build_trace(&air, note_preimages);
        let mut public_values = Vec::with_capacity(PUBLIC_VALUES);
        for note in note_preimages {
            public_values.extend(
                private_reference
                    .hash_note(&note)
                    .unwrap()
                    .map(Val::from_u32),
            );
        }
        public_values.extend(asset.map(Val::from_u8));
        p3_air::check_constraints(&air, &trace, &public_values);

        let assert_rejected = |trace: &RowMajorMatrix<Val>| {
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    p3_air::check_constraints(&air, trace, &public_values);
                }))
                .is_err()
            );
        };

        let mut changed_value = trace.clone();
        for row in 0..TRACE_ROWS {
            changed_value.values[row * TRACE_WIDTH
                + NOTE_WITNESS_OFFSET
                + NOTE_BYTES_OFFSET
                + NOTE_VALUE_OFFSET
                + VALUE_BYTES
                - 1] += Val::ONE;
        }
        assert_rejected(&changed_value);

        let mut changed_asset = trace;
        for row in 0..TRACE_ROWS {
            changed_asset.values[row * TRACE_WIDTH
                + NOTE_WITNESS_OFFSET
                + NOTE_BYTES_OFFSET
                + NOTE_ASSET_OFFSET] += Val::ONE;
        }
        assert_rejected(&changed_asset);
    }

    #[test]
    fn conservation_air_rejects_wrong_public_output_slot_binding() {
        let asset = [0xA5; ASSET_BYTES];
        let note_preimages = notes(asset);
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        let private_reference = Poseidon2P24PrivacyReference::load_candidate().unwrap();
        let air = Poseidon2P24ValueConservationAir::from_reference(&reference, true).unwrap();
        let trace = build_trace(&air, note_preimages);
        let mut public_values = Vec::with_capacity(PUBLIC_VALUES_WITH_OUTPUT_BINDINGS);
        let note_commitments =
            note_preimages.map(|note| private_reference.hash_note(&note).unwrap());
        for commitment in note_commitments {
            public_values.extend(commitment.map(Val::from_u32));
        }
        public_values.extend(asset.map(Val::from_u8));
        for commitment in &note_commitments[INPUT_NOTE_COUNT..] {
            public_values.extend((*commitment).map(Val::from_u32));
        }
        p3_air::check_constraints(&air, &trace, &public_values);

        let mut wrong_output_slot = public_values;
        wrong_output_slot[OUTPUT_COMMITMENT_BINDINGS_OFFSET] += Val::ONE;
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                p3_air::check_constraints(&air, &trace, &wrong_output_slot);
            }))
            .is_err()
        );
    }
}
