//! One private ownership-binding relation for the frozen P24 candidates.
//!
//! This AIR is deliberately narrower than a transfer. It uses one private
//! witness to prove `H_ADDR(key)`, `H_NOTE(note_preimage)` and
//! `H_NULLIFIER(key || rho || note_commitment || position)` together. The
//! note's recipient bytes must encode the `H_ADDR` digest, and the nullifier
//! bytes must encode the same key, the note's `rho`, the exact note digest and
//! a private big-endian leaf position. Only the nullifier is public.

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
const TOTAL_PHASES: usize = ADDR_PHASES + NOTE_PHASES + NULLIFIER_PHASES;
const TOTAL_STEPS: usize = TOTAL_PHASES * P24_ROUNDS;
const TRACE_ROWS: usize = 512;
const SELECTOR_OFFSET: usize = P24_WIDTH;
const WITNESS_OFFSET: usize = SELECTOR_OFFSET + TOTAL_STEPS;

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
const WITNESS_ELEMENTS: usize = NOTE_DIGEST_OFFSET + DIGEST_LANES;
const TRACE_WIDTH: usize = WITNESS_OFFSET + WITNESS_ELEMENTS;

const ADDR_BLOCK_PHASE: usize = 0;
const ADDR_SQUEEZE_PHASE: usize = 1;
const NOTE_FIRST_PHASE: usize = ADDR_PHASES;
const NOTE_LAST_BLOCK_PHASE: usize = NOTE_FIRST_PHASE + 3;
const NOTE_SQUEEZE_PHASE: usize = NOTE_FIRST_PHASE + 4;
const NULLIFIER_FIRST_PHASE: usize = ADDR_PHASES + NOTE_PHASES;
const NULLIFIER_LAST_BLOCK_PHASE: usize = NULLIFIER_FIRST_PHASE + 2;
const NULLIFIER_SQUEEZE_PHASE: usize = NULLIFIER_FIRST_PHASE + 3;

const NOTE_VERSION_OFFSET: usize = 0;
const NOTE_RECIPIENT_OFFSET: usize = 50;
const NOTE_RHO_OFFSET: usize = 114;

/// Public result after an independently verified ownership-binding proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Poseidon2P24OwnershipExperimentResult {
    /// The sole public 16-element value: the deterministic nullifier.
    pub nullifier: BabyBearDigestV2,
    /// Number of rows in the fixed private trace.
    pub trace_rows: usize,
}

/// AIR for one key-to-note-to-nullifier ownership binding.
#[derive(Clone, Debug)]
struct Poseidon2P24OwnershipAir {
    permutation: Poseidon2P24Air,
    addr_iv: [u32; 9],
    note_iv: [u32; 9],
    nullifier_iv: [u32; 9],
}

impl Poseidon2P24OwnershipAir {
    fn from_reference(reference: &Poseidon2P24Reference) -> Result<Self, StarkExperimentError> {
        let manifest = CandidatePoseidon2P24NoteDomainsManifestV1::new();
        Ok(Self {
            permutation: Poseidon2P24Air::from_reference(reference),
            addr_iv: manifest.iv(Poseidon2P24NoteDomainV1::Addr)?,
            note_iv: manifest.iv(Poseidon2P24NoteDomainV1::Note)?,
            nullifier_iv: manifest.iv(Poseidon2P24NoteDomainV1::Nullifier)?,
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
        DIGEST_LANES
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(8)
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
        let selectors = &local[SELECTOR_OFFSET..WITNESS_OFFSET];
        let next_selectors = &next[SELECTOR_OFFSET..WITNESS_OFFSET];
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

        for selector in 0..TOTAL_STEPS {
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
        for lane in 0..P24_WIDTH {
            let mut expected_next: AB::Expr = local_state[lane].into();
            for phase in 0..TOTAL_PHASES {
                for (round, round_state) in round_states.iter().enumerate() {
                    let selector = selectors[(phase * P24_ROUNDS) + round];
                    let target = if round + 1 == P24_ROUNDS {
                        self.phase_transition_target::<AB>(phase, lane, round_state, witness)
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

        let recipient_output = witness
            [RECIPIENT_DIGEST_OFFSET..RECIPIENT_DIGEST_OFFSET + DIGEST_LANES]
            .iter()
            .copied()
            .map(Into::into)
            .collect::<Vec<AB::Expr>>();
        self.assert_digest_at_phase::<AB>(
            builder,
            selectors,
            &round_states,
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
            selectors,
            &round_states,
            NOTE_LAST_BLOCK_PHASE,
            NOTE_SQUEEZE_PHASE,
            &note_output,
        );
        let public_output = public_values
            .iter()
            .copied()
            .map(Into::into)
            .collect::<Vec<AB::Expr>>();
        self.assert_digest_at_phase::<AB>(
            builder,
            selectors,
            &round_states,
            NULLIFIER_LAST_BLOCK_PHASE,
            NULLIFIER_SQUEEZE_PHASE,
            &public_output,
        );
    }
}

impl Poseidon2P24OwnershipAir {
    fn phase_transition_target<AB: AirBuilder>(
        &self,
        phase: usize,
        lane: usize,
        round_state: &[AB::Expr],
        witness: &[AB::Var],
    ) -> AB::Expr {
        match phase {
            ADDR_BLOCK_PHASE | NOTE_LAST_BLOCK_PHASE | NULLIFIER_LAST_BLOCK_PHASE => {
                matrix_expression::<AB>(&self.permutation.external_matrix, round_state)[lane]
                    .clone()
            }
            ADDR_SQUEEZE_PHASE => self
                .initial_state_expression::<AB>(witness, Poseidon2P24NoteDomainV1::Note)[lane]
                .clone(),
            NOTE_SQUEEZE_PHASE => self
                .initial_state_expression::<AB>(witness, Poseidon2P24NoteDomainV1::Nullifier)[lane]
                .clone(),
            NOTE_FIRST_PHASE..=4 => {
                let next_block = phase - NOTE_FIRST_PHASE + 1;
                self.absorb_then_permute_expression::<AB>(
                    round_state,
                    |packed_index| self.note_packed_expression::<AB>(witness, packed_index),
                    next_block,
                    lane,
                )
            }
            NULLIFIER_FIRST_PHASE..=8 => {
                let next_block = phase - NULLIFIER_FIRST_PHASE + 1;
                self.absorb_then_permute_expression::<AB>(
                    round_state,
                    |packed_index| self.nullifier_packed_expression::<AB>(witness, packed_index),
                    next_block,
                    lane,
                )
            }
            NULLIFIER_SQUEEZE_PHASE => round_state[lane].clone(),
            _ => unreachable!("every P24 ownership phase is fixed"),
        }
    }

    fn absorb_then_permute_expression<AB: AirBuilder>(
        &self,
        round_state: &[AB::Expr],
        packed: impl Fn(usize) -> AB::Expr,
        block: usize,
        lane: usize,
    ) -> AB::Expr {
        let absorbed = (0..P24_WIDTH)
            .map(|state_lane| {
                if state_lane < RATE {
                    round_state[state_lane].clone() + packed((block * RATE) + state_lane)
                } else {
                    round_state[state_lane].clone()
                }
            })
            .collect::<Vec<AB::Expr>>();
        matrix_expression::<AB>(&self.permutation.external_matrix, &absorbed)[lane].clone()
    }

    fn assert_digest_at_phase<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        selectors: &[AB::Var],
        round_states: &[Vec<AB::Expr>],
        final_block_phase: usize,
        squeeze_phase: usize,
        digest: &[AB::Expr],
    ) {
        let first_squeeze_selector = selectors[(final_block_phase * P24_ROUNDS) + P24_ROUNDS - 1];
        for lane in 0..RATE {
            builder.assert_zero(
                first_squeeze_selector
                    * (round_states[P24_ROUNDS - 1][lane].clone() - digest[lane].clone()),
            );
        }
        let final_squeeze_selector = selectors[(squeeze_phase * P24_ROUNDS) + P24_ROUNDS - 1];
        builder.assert_zero(
            final_squeeze_selector * (round_states[P24_ROUNDS - 1][0].clone() - digest[15].clone()),
        );
    }
}

/// Produces and independently verifies a hiding-FRI STARK that binds one
/// private key, canonical note preimage and private leaf position to one public
/// nullifier.
///
/// This is not a spend authorization: it does not yet prove Merkle membership,
/// nullifier absence, asset/value rules, state anchoring or ledger acceptance.
pub fn prove_and_verify_p24_note_ownership(
    nullifier_key: [u8; KEY_BYTES],
    note_preimage: [u8; NOTE_BYTES],
    leaf_position: u32,
) -> Result<Poseidon2P24OwnershipExperimentResult, StarkExperimentError> {
    let reference = Poseidon2P24Reference::load_candidate()?;
    let private_reference = Poseidon2P24PrivacyReference::load_candidate()?;
    let recipient_commitment = private_reference.hash_addr(&nullifier_key)?;
    let note_commitment = private_reference.hash_note(&note_preimage)?;
    let nullifier_preimage =
        make_nullifier_preimage(nullifier_key, note_preimage, note_commitment, leaf_position);
    let nullifier = private_reference.hash_nullifier_preimage(&nullifier_preimage)?;
    let air = Poseidon2P24OwnershipAir::from_reference(&reference)?;
    let trace = build_ownership_trace(
        &air,
        nullifier_key,
        note_preimage,
        leaf_position,
        recipient_commitment,
        note_commitment,
    );
    let public_values = nullifier.map(Val::from_u32);
    let config = make_hiding_config();
    let proof = prove(&config, &air, trace, &public_values);
    verify(&config, &air, &proof, &public_values)
        .map_err(|_| StarkExperimentError::VerificationFailed)?;
    Ok(Poseidon2P24OwnershipExperimentResult {
        nullifier,
        trace_rows: TRACE_ROWS,
    })
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
    nullifier_key: [u8; KEY_BYTES],
    note_preimage: [u8; NOTE_BYTES],
    leaf_position: u32,
    recipient_commitment: BabyBearDigestV2,
    note_commitment: BabyBearDigestV2,
) -> RowMajorMatrix<Val> {
    let key_packed = byte_pack3le(&nullifier_key, ADDR_ELEMENTS);
    let note_packed = byte_pack3le(&note_preimage, NOTE_ELEMENTS);
    let nullifier_preimage =
        make_nullifier_preimage(nullifier_key, note_preimage, note_commitment, leaf_position);
    let nullifier_packed = byte_pack3le(&nullifier_preimage, NULLIFIER_ELEMENTS);
    let mut values = Val::zero_vec(TRACE_ROWS * TRACE_WIDTH);
    let mut state = initial_state_values(&air.permutation, air.addr_iv, &key_packed);

    for row in 0..TRACE_ROWS {
        let offset = row * TRACE_WIDTH;
        values[offset..offset + P24_WIDTH].copy_from_slice(&state);
        write_witness(
            &mut values[offset + WITNESS_OFFSET..],
            nullifier_key,
            note_preimage,
            leaf_position,
            recipient_commitment,
            note_commitment,
        );
        if row < TOTAL_STEPS {
            values[offset + SELECTOR_OFFSET + row] = Val::ONE;
            let round = row % P24_ROUNDS;
            state = round_values(&air.permutation, state, round);
            if round + 1 == P24_ROUNDS {
                let phase = row / P24_ROUNDS;
                state = match phase {
                    ADDR_BLOCK_PHASE => matrix_values(&air.permutation.external_matrix, &state),
                    ADDR_SQUEEZE_PHASE => {
                        initial_state_values(&air.permutation, air.note_iv, &note_packed)
                    }
                    NOTE_FIRST_PHASE..=4 => absorb_then_initial_permute(
                        &air.permutation,
                        state,
                        &note_packed,
                        phase - NOTE_FIRST_PHASE + 1,
                    ),
                    NOTE_LAST_BLOCK_PHASE => {
                        matrix_values(&air.permutation.external_matrix, &state)
                    }
                    NOTE_SQUEEZE_PHASE => {
                        initial_state_values(&air.permutation, air.nullifier_iv, &nullifier_packed)
                    }
                    NULLIFIER_FIRST_PHASE..=8 => absorb_then_initial_permute(
                        &air.permutation,
                        state,
                        &nullifier_packed,
                        phase - NULLIFIER_FIRST_PHASE + 1,
                    ),
                    NULLIFIER_LAST_BLOCK_PHASE => {
                        matrix_values(&air.permutation.external_matrix, &state)
                    }
                    NULLIFIER_SQUEEZE_PHASE => state,
                    _ => unreachable!("every P24 ownership phase is fixed"),
                };
            }
        }
    }
    RowMajorMatrix::new(values, TRACE_WIDTH)
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

fn write_witness(
    witness: &mut [Val],
    key: [u8; KEY_BYTES],
    note: [u8; NOTE_BYTES],
    leaf_position: u32,
    recipient: BabyBearDigestV2,
    note_commitment: BabyBearDigestV2,
) {
    write_bytes_and_bits(witness, KEY_BYTES_OFFSET, KEY_BITS_OFFSET, &key);
    write_bytes_and_bits(witness, NOTE_BYTES_OFFSET, NOTE_BITS_OFFSET, &note);
    write_bytes_and_bits(
        witness,
        POSITION_BYTES_OFFSET,
        POSITION_BITS_OFFSET,
        &leaf_position.to_be_bytes(),
    );
    for (lane, value) in recipient.into_iter().enumerate() {
        witness[RECIPIENT_DIGEST_OFFSET + lane] = Val::from_u32(value);
    }
    let note_commitment_bytes = digest_bytes(note_commitment);
    write_bytes_and_bits(
        witness,
        NOTE_COMMITMENT_BYTES_OFFSET,
        NOTE_COMMITMENT_BITS_OFFSET,
        &note_commitment_bytes,
    );
    for (lane, value) in note_commitment.into_iter().enumerate() {
        witness[NOTE_DIGEST_OFFSET + lane] = Val::from_u32(value);
    }
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
    fn ownership_stark_binds_one_private_key_note_and_position_to_the_nullifier() {
        let (key, note, position) = valid_witness();
        let result = prove_and_verify_p24_note_ownership(key, note, position).unwrap();
        let reference = Poseidon2P24PrivacyReference::load_candidate().unwrap();
        let commitment = reference.hash_note(&note).unwrap();
        let expected = reference
            .hash_nullifier_preimage(&make_nullifier_preimage(key, note, commitment, position))
            .unwrap();

        assert_eq!(result.nullifier, expected);
        assert_eq!(result.trace_rows, TRACE_ROWS);
    }

    #[test]
    fn ownership_air_rejects_a_changed_nullifier_or_broken_key_to_recipient_binding() {
        let (key, note, position) = valid_witness();
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        let private_reference = Poseidon2P24PrivacyReference::load_candidate().unwrap();
        let recipient = private_reference.hash_addr(&key).unwrap();
        let commitment = private_reference.hash_note(&note).unwrap();
        let nullifier = private_reference
            .hash_nullifier_preimage(&make_nullifier_preimage(key, note, commitment, position))
            .unwrap()
            .map(Val::from_u32);
        let air = Poseidon2P24OwnershipAir::from_reference(&reference).unwrap();
        let trace = build_ownership_trace(&air, key, note, position, recipient, commitment);
        p3_air::check_constraints(&air, &trace, &nullifier);

        let assert_rejected = |trace: &RowMajorMatrix<Val>, public_values: &[Val; DIGEST_LANES]| {
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    p3_air::check_constraints(&air, trace, public_values);
                }))
                .is_err()
            );
        };

        let mut changed_nullifier = nullifier;
        changed_nullifier[0] += Val::ONE;
        assert_rejected(&trace, &changed_nullifier);

        let mut broken_recipient = trace.clone();
        for row in 0..TRACE_ROWS {
            broken_recipient.values
                [row * TRACE_WIDTH + WITNESS_OFFSET + NOTE_BYTES_OFFSET + NOTE_RECIPIENT_OFFSET] +=
                Val::ONE;
        }
        assert_rejected(&broken_recipient, &nullifier);

        let mut broken_note_commitment = trace;
        for row in 0..TRACE_ROWS {
            broken_note_commitment.values
                [row * TRACE_WIDTH + WITNESS_OFFSET + NOTE_COMMITMENT_BYTES_OFFSET] += Val::ONE;
        }
        assert_rejected(&broken_note_commitment, &nullifier);
    }
}
