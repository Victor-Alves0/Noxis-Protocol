//! Executable Plonky3 STARK integration experiment for Noxis.
//!
//! This crate contains executable Plonky3 STARK experiments with a hiding FRI
//! PCS. Its active smoke proof constrains the exact frozen Poseidon2-P24
//! permutation behind the Noxis candidate privacy primitives. It does **not**
//! yet prove note membership, nullifier absence, ownership, asset
//! conservation, range constraints, recipient binding, or any production
//! privacy property.

use noxis_poseidon2_reference::{
    BabyBearStateP24, P24_WIDTH, Poseidon2P24Reference, Poseidon2P24ReferenceError,
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::PrimeCharacteristicRing;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, HidingFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF, VECTOR_LEN};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::{StarkConfig, prove, verify};
use rand::SeedableRng as _;
use rand_chacha::ChaCha12Rng;

const TRACE_WIDTH: usize = 2;
const TRACE_ROWS: usize = 8;
const P24_ROUNDS: usize = 29;
const P24_TRACE_ROWS: usize = 32;
const P24_SELECTOR_OFFSET: usize = P24_WIDTH;
const P24_TRACE_WIDTH: usize = P24_WIDTH + P24_ROUNDS;
const P24_PUBLIC_VALUES: usize = P24_WIDTH * 2;

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;
type ByteHash = Keccak256Hash;
type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
type FieldHash = SerializingHasher<U64Hash>;
type Compress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
type ValHidingMmcs = MerkleTreeHidingMmcs<
    [Val; VECTOR_LEN],
    [u64; VECTOR_LEN],
    FieldHash,
    Compress,
    ChaCha12Rng,
    2,
    4,
    4,
>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
type ChallengeHidingMmcs = ExtensionMmcs<Val, Challenge, ValHidingMmcs>;
type HidingPcs =
    HidingFriPcs<Val, Radix2DitParallel<Val>, ValHidingMmcs, ChallengeHidingMmcs, ChaCha12Rng>;
type Config = StarkConfig<HidingPcs, Challenge, Challenger>;

/// Public result of a prover run after its proof was independently verified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StarkExperimentResult {
    pub initial_state: u32,
    pub final_state: u32,
    pub trace_rows: usize,
}

/// Public result of a proof for the frozen Poseidon2-P24 candidate
/// permutation. The input and output are public; all intermediate rounds are
/// in the hidden trace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Poseidon2P24ExperimentResult {
    pub input: BabyBearStateP24,
    pub output: BabyBearStateP24,
    pub trace_rows: usize,
}

/// The fixed AIR used only to establish the P3 integration boundary.
#[derive(Clone, Copy, Debug, Default)]
pub struct PrivateAccumulatorAir;

/// AIR for one exact evaluation of the frozen Poseidon2-BabyBear-P24
/// permutation used by the Noxis candidate privacy primitives.
///
/// This is a real permutation constraint system, not a replacement hash. It
/// deliberately proves only this primitive at this stage; note hashing,
/// Merkle-path composition, nullifier derivation and value relations are
/// composed in later AIR work.
#[derive(Clone, Debug)]
pub struct Poseidon2P24Air {
    external_matrix: [[u32; P24_WIDTH]; P24_WIDTH],
    internal_matrix: [[u32; P24_WIDTH]; P24_WIDTH],
    round_constants: [[u32; P24_WIDTH]; P24_ROUNDS],
}

impl Poseidon2P24Air {
    fn from_reference(reference: &Poseidon2P24Reference) -> Self {
        Self {
            external_matrix: *reference.external_matrix(),
            internal_matrix: *reference.internal_matrix(),
            round_constants: *reference.round_constants(),
        }
    }
}

impl<F> BaseAir<F> for PrivateAccumulatorAir {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }

    fn num_public_values(&self) -> usize {
        2
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

impl<F> BaseAir<F> for Poseidon2P24Air {
    fn width(&self) -> usize {
        P24_TRACE_WIDTH
    }

    fn num_public_values(&self) -> usize {
        P24_PUBLIC_VALUES
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(8)
    }
}

impl<AB: AirBuilder> Air<AB> for PrivateAccumulatorAir {
    fn eval(&self, builder: &mut AB) {
        let initial_state = builder.public_values()[0];
        let final_state = builder.public_values()[1];
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();

        builder.when_first_row().assert_eq(local[0], initial_state);
        builder
            .when_transition()
            .assert_eq(local[0] + local[1], next[0]);
        builder.when_last_row().assert_eq(local[0], final_state);
    }
}

impl<AB: AirBuilder> Air<AB> for Poseidon2P24Air {
    fn eval(&self, builder: &mut AB) {
        let public_values = builder.public_values().to_vec();
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let local_state = &local[..P24_WIDTH];
        let next_state = &next[..P24_WIDTH];
        let selectors = &local[P24_SELECTOR_OFFSET..P24_TRACE_WIDTH];
        let next_selectors = &next[P24_SELECTOR_OFFSET..P24_TRACE_WIDTH];

        for output_lane in 0..P24_WIDTH {
            let mut initial_state = AB::Expr::ZERO;
            for (input_lane, public_input) in public_values.iter().take(P24_WIDTH).enumerate() {
                let input: AB::Expr = (*public_input).into();
                initial_state +=
                    input * AB::F::from_u32(self.external_matrix[output_lane][input_lane]);
            }
            builder
                .when_first_row()
                .assert_eq(local_state[output_lane], initial_state);
            builder.when_last_row().assert_eq(
                local_state[output_lane],
                public_values[P24_WIDTH + output_lane],
            );
        }

        for selector in 0..P24_ROUNDS {
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
            .map(|round| self.round_expression::<AB>(local_state, round))
            .collect();
        for lane in 0..P24_WIDTH {
            let mut expected_next: AB::Expr = local_state[lane].into();
            for round in 0..P24_ROUNDS {
                let delta = round_states[round][lane].clone() - local_state[lane];
                expected_next += selectors[round] * delta;
            }
            builder
                .when_transition()
                .assert_eq(next_state[lane], expected_next);
        }
    }
}

impl Poseidon2P24Air {
    fn round_expression<AB: AirBuilder>(&self, state: &[AB::Var], round: usize) -> Vec<AB::Expr> {
        let mut added: Vec<AB::Expr> = state.iter().copied().map(|value| value.into()).collect();
        if is_full_round(round) {
            for (lane, value) in added.iter_mut().enumerate() {
                *value = value.clone() + AB::F::from_u32(self.round_constants[round][lane]);
                *value = seventh_power::<AB>(value.clone());
            }
            matrix_expression::<AB>(&self.external_matrix, &added)
        } else {
            added[0] = added[0].clone() + AB::F::from_u32(self.round_constants[round][0]);
            added[0] = seventh_power::<AB>(added[0].clone());
            matrix_expression::<AB>(&self.internal_matrix, &added)
        }
    }
}

/// Produces and immediately verifies a hiding-FRI STARK for a private sequence
/// of state increments. Only the initial and final accumulator states are
/// public values; the individual increments reside in the private trace.
pub fn prove_and_verify_private_accumulator(
    initial_state: u32,
    increments: [u32; TRACE_ROWS - 1],
) -> Result<StarkExperimentResult, StarkExperimentError> {
    let final_state = increments.iter().fold(initial_state, |state, increment| {
        state.wrapping_add(*increment)
    });
    let trace = build_trace(initial_state, increments);
    let public_values = [Val::from_u32(initial_state), Val::from_u32(final_state)];
    let air = PrivateAccumulatorAir;
    let config = make_hiding_config();
    let proof = prove(&config, &air, trace, &public_values);
    verify(&config, &air, &proof, &public_values)
        .map_err(|_| StarkExperimentError::VerificationFailed)?;
    Ok(StarkExperimentResult {
        initial_state,
        final_state,
        trace_rows: TRACE_ROWS,
    })
}

/// A concrete command-friendly smoke case for local research use.
pub fn run_research_smoke() -> Result<StarkExperimentResult, StarkExperimentError> {
    prove_and_verify_private_accumulator(7, [3, 1, 4, 1, 5, 9, 2])
}

/// Produces and verifies a STARK for the exact frozen P24 permutation. The
/// private trace contains all intermediate states and selector columns; the
/// verifier learns only the supplied public input and output states.
pub fn prove_and_verify_p24_permutation(
    input: BabyBearStateP24,
) -> Result<Poseidon2P24ExperimentResult, StarkExperimentError> {
    let reference = Poseidon2P24Reference::load_candidate()?;
    let output = reference.permutation(input)?;
    let air = Poseidon2P24Air::from_reference(&reference);
    let trace = build_p24_trace(&air, input);
    let public_values = input
        .into_iter()
        .chain(output)
        .map(Val::from_u32)
        .collect::<Vec<_>>();
    let config = make_hiding_config();
    let proof = prove(&config, &air, trace, &public_values);
    verify(&config, &air, &proof, &public_values)
        .map_err(|_| StarkExperimentError::VerificationFailed)?;
    Ok(Poseidon2P24ExperimentResult {
        input,
        output,
        trace_rows: P24_TRACE_ROWS,
    })
}

/// A command-friendly proof of the candidate permutation used by the privacy
/// roadmap. It is the current operational STARK smoke test.
pub fn run_p24_research_smoke() -> Result<Poseidon2P24ExperimentResult, StarkExperimentError> {
    prove_and_verify_p24_permutation(core::array::from_fn(|index| index as u32 + 1))
}

#[derive(Debug)]
pub enum StarkExperimentError {
    CandidateParameters(Poseidon2P24ReferenceError),
    VerificationFailed,
}

impl From<Poseidon2P24ReferenceError> for StarkExperimentError {
    fn from(value: Poseidon2P24ReferenceError) -> Self {
        Self::CandidateParameters(value)
    }
}

impl std::fmt::Display for StarkExperimentError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CandidateParameters(error) => {
                write!(
                    formatter,
                    "could not load frozen P24 candidate parameters: {error}"
                )
            }
            Self::VerificationFailed => {
                formatter.write_str("Plonky3 rejected the research STARK proof")
            }
        }
    }
}

impl std::error::Error for StarkExperimentError {}

fn build_trace(initial_state: u32, increments: [u32; TRACE_ROWS - 1]) -> RowMajorMatrix<Val> {
    let mut values = Val::zero_vec(TRACE_ROWS * TRACE_WIDTH);
    let mut state = Val::from_u32(initial_state);
    for (row, increment) in increments.into_iter().enumerate() {
        let offset = row * TRACE_WIDTH;
        values[offset] = state;
        values[offset + 1] = Val::from_u32(increment);
        state += values[offset + 1];
    }
    let final_offset = (TRACE_ROWS - 1) * TRACE_WIDTH;
    values[final_offset] = state;
    values[final_offset + 1] = Val::ZERO;
    RowMajorMatrix::new(values, TRACE_WIDTH)
}

fn build_p24_trace(air: &Poseidon2P24Air, input: BabyBearStateP24) -> RowMajorMatrix<Val> {
    let mut values = Val::zero_vec(P24_TRACE_ROWS * P24_TRACE_WIDTH);
    let input = input.map(Val::from_u32);
    let mut state = matrix_values(&air.external_matrix, &input);

    for row in 0..P24_TRACE_ROWS {
        let offset = row * P24_TRACE_WIDTH;
        values[offset..offset + P24_WIDTH].copy_from_slice(&state);
        if row < P24_ROUNDS {
            values[offset + P24_SELECTOR_OFFSET + row] = Val::ONE;
            state = round_values(air, state, row);
        }
    }
    RowMajorMatrix::new(values, P24_TRACE_WIDTH)
}

fn round_values(
    air: &Poseidon2P24Air,
    mut state: [Val; P24_WIDTH],
    round: usize,
) -> [Val; P24_WIDTH] {
    if is_full_round(round) {
        for (lane, value) in state.iter_mut().enumerate() {
            *value += Val::from_u32(air.round_constants[round][lane]);
            *value = value.exp_u64(7);
        }
        matrix_values(&air.external_matrix, &state)
    } else {
        state[0] += Val::from_u32(air.round_constants[round][0]);
        state[0] = state[0].exp_u64(7);
        matrix_values(&air.internal_matrix, &state)
    }
}

fn matrix_values(
    matrix: &[[u32; P24_WIDTH]; P24_WIDTH],
    values: &[Val; P24_WIDTH],
) -> [Val; P24_WIDTH] {
    core::array::from_fn(|row| {
        (0..P24_WIDTH).fold(Val::ZERO, |sum, column| {
            sum + values[column] * Val::from_u32(matrix[row][column])
        })
    })
}

fn is_full_round(round: usize) -> bool {
    !(4..P24_ROUNDS - 4).contains(&round)
}

fn seventh_power<AB: AirBuilder>(value: AB::Expr) -> AB::Expr {
    let square = value.clone() * value.clone();
    let fourth = square.clone() * square.clone();
    fourth * square * value
}

fn matrix_expression<AB: AirBuilder>(
    matrix: &[[u32; P24_WIDTH]; P24_WIDTH],
    values: &[AB::Expr],
) -> Vec<AB::Expr> {
    (0..P24_WIDTH)
        .map(|row| {
            (0..P24_WIDTH).fold(AB::Expr::ZERO, |sum, column| {
                sum + values[column].clone() * AB::F::from_u32(matrix[row][column])
            })
        })
        .collect()
}

fn make_hiding_config() -> Config {
    let byte_hash = ByteHash {};
    let u64_hash = U64Hash::new(KeccakF {});
    let field_hash = FieldHash::new(u64_hash);
    let compress = Compress::new(u64_hash);
    let val_mmcs = ValHidingMmcs::new(field_hash, compress, 0, secure_rng());
    let challenge_mmcs = ChallengeHidingMmcs::new(val_mmcs.clone());
    let fri_params = FriParameters {
        log_blowup: 3,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 32,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: challenge_mmcs,
    };
    let pcs = HidingPcs::new(
        Radix2DitParallel::default(),
        val_mmcs,
        fri_params,
        4,
        secure_rng(),
    );
    let challenger = Challenger::from_hasher(vec![], byte_hash);
    Config::new(pcs, challenger)
}

fn secure_rng() -> ChaCha12Rng {
    let mut system_rng = rand::rng();
    ChaCha12Rng::from_rng(&mut system_rng)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hiding_fri_stark_proves_and_verifies_a_private_accumulator_trace() {
        assert_eq!(
            run_research_smoke().unwrap(),
            StarkExperimentResult {
                initial_state: 7,
                final_state: 32,
                trace_rows: TRACE_ROWS,
            }
        );
    }

    #[test]
    fn a_proof_is_rejected_when_its_public_final_state_changes() {
        let increments = [3, 1, 4, 1, 5, 9, 2];
        let trace = build_trace(7, increments);
        let air = PrivateAccumulatorAir;
        let config = make_hiding_config();
        let public_values = [Val::from_u32(7), Val::from_u32(32)];
        let proof = prove(&config, &air, trace, &public_values);
        let wrong_public_values = [Val::from_u32(7), Val::from_u32(33)];

        assert!(verify(&config, &air, &proof, &wrong_public_values).is_err());
    }

    #[test]
    fn p24_stark_matches_the_frozen_candidate_permutation() {
        let input = core::array::from_fn(|index| index as u32 + 1);
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        let air = Poseidon2P24Air::from_reference(&reference);
        let trace = build_p24_trace(&air, input);
        let output = reference.permutation(input).unwrap();
        let public_values = input
            .into_iter()
            .chain(output)
            .map(Val::from_u32)
            .collect::<Vec<_>>();
        p3_air::check_constraints(&air, &trace, &public_values);
        let result = prove_and_verify_p24_permutation(input).unwrap();

        assert_eq!(result.output, output);
        assert_eq!(result.trace_rows, P24_TRACE_ROWS);
    }

    #[test]
    fn p24_proof_rejects_a_changed_public_output() {
        let input = core::array::from_fn(|index| index as u32 + 1);
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        let output = reference.permutation(input).unwrap();
        let air = Poseidon2P24Air::from_reference(&reference);
        let trace = build_p24_trace(&air, input);
        let public_values = input
            .into_iter()
            .chain(output)
            .map(Val::from_u32)
            .collect::<Vec<_>>();
        let config = make_hiding_config();
        let proof = prove(&config, &air, trace, &public_values);
        let mut altered_public_values = public_values;
        altered_public_values[P24_WIDTH] += Val::ONE;

        assert!(verify(&config, &air, &proof, &altered_public_values).is_err());
    }
}
