//! Executable Plonky3 STARK integration experiment for Noxis.
//!
//! This crate contains executable Plonky3 STARK experiments with a hiding FRI
//! PCS. Its active smoke proof constrains the exact frozen Poseidon2-P24
//! permutation behind the Noxis candidate privacy primitives. It does **not**
//! yet prove note membership, nullifier absence, ownership, asset
//! conservation, range constraints, recipient binding, or any production
//! privacy property.

use noxis_poseidon2_reference::{
    BabyBearDigestV2, BabyBearStateP24, P24_WIDTH, Poseidon2P24Reference,
    Poseidon2P24ReferenceError,
};
use noxis_tree_params::{
    CandidatePoseidon2P24ManifestV2, Poseidon2P24CandidateError, Poseidon2P24TreeDomainV1,
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
const P24_HASH16_LEAF_PERMUTATIONS: usize = 3;
const P24_HASH16_LEAF_STEPS: usize = P24_HASH16_LEAF_PERMUTATIONS * P24_ROUNDS;
const P24_HASH16_LEAF_TRACE_ROWS: usize = 128;
const P24_HASH16_LEAF_TRACE_WIDTH: usize = P24_WIDTH + P24_HASH16_LEAF_STEPS;
const P24_HASH16_LEAF_PUBLIC_VALUES: usize = 32;

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

/// Public result of a STARK for the candidate `Hash16(Leaf, commitment)`
/// construction. The commitment and its leaf digest are public; the sponge
/// states across all three permutations remain in the hidden trace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Poseidon2P24LeafExperimentResult {
    pub commitment: BabyBearDigestV2,
    pub leaf: BabyBearDigestV2,
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

/// AIR for the exact `Hash16(Leaf, commitment)` candidate construction.
///
/// It composes three constrained P24 permutations with the frozen leaf IV,
/// the two absorption phases required for sixteen input elements and the
/// prescribed squeeze. This is the first STARK binding between a candidate
/// note commitment and a candidate Merkle leaf; it is not yet a Merkle path
/// or a private-transfer proof.
#[derive(Clone, Debug)]
pub struct Poseidon2P24Hash16LeafAir {
    permutation: Poseidon2P24Air,
    leaf_iv: [u32; 9],
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

impl Poseidon2P24Hash16LeafAir {
    fn from_reference(reference: &Poseidon2P24Reference) -> Result<Self, StarkExperimentError> {
        Ok(Self {
            permutation: Poseidon2P24Air::from_reference(reference),
            leaf_iv: CandidatePoseidon2P24ManifestV2::new().iv(Poseidon2P24TreeDomainV1::Leaf)?,
        })
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

impl<F> BaseAir<F> for Poseidon2P24Hash16LeafAir {
    fn width(&self) -> usize {
        P24_HASH16_LEAF_TRACE_WIDTH
    }

    fn num_public_values(&self) -> usize {
        P24_HASH16_LEAF_PUBLIC_VALUES
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

impl<AB: AirBuilder> Air<AB> for Poseidon2P24Hash16LeafAir {
    fn eval(&self, builder: &mut AB) {
        let public_values = builder.public_values().to_vec();
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let local_state = &local[..P24_WIDTH];
        let next_state = &next[..P24_WIDTH];
        let selectors = &local[P24_SELECTOR_OFFSET..P24_HASH16_LEAF_TRACE_WIDTH];
        let next_selectors = &next[P24_SELECTOR_OFFSET..P24_HASH16_LEAF_TRACE_WIDTH];

        let initial_state = self.initial_state_expression::<AB>(&public_values);
        for lane in 0..P24_WIDTH {
            builder
                .when_first_row()
                .assert_eq(local_state[lane], initial_state[lane].clone());
        }

        for selector in 0..P24_HASH16_LEAF_STEPS {
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
        let phase_completions: Vec<Vec<AB::Expr>> = (0..P24_HASH16_LEAF_PERMUTATIONS)
            .map(|phase| {
                self.phase_completion_expression::<AB>(
                    &round_states[P24_ROUNDS - 1],
                    phase,
                    &public_values,
                )
            })
            .collect();
        for lane in 0..15 {
            let output: AB::Expr = public_values[16 + lane].into();
            builder.assert_zero(
                selectors[(P24_ROUNDS * 2) - 1]
                    * (round_states[P24_ROUNDS - 1][lane].clone() - output),
            );
        }
        let final_output: AB::Expr = public_values[31].into();
        builder.assert_zero(
            selectors[P24_HASH16_LEAF_STEPS - 1]
                * (round_states[P24_ROUNDS - 1][0].clone() - final_output),
        );

        for lane in 0..P24_WIDTH {
            let mut expected_next: AB::Expr = local_state[lane].into();
            for (phase, phase_completion) in phase_completions.iter().enumerate() {
                for (round, round_state) in round_states.iter().enumerate() {
                    let step = (phase * P24_ROUNDS) + round;
                    let target = if round + 1 == P24_ROUNDS {
                        phase_completion[lane].clone()
                    } else {
                        round_state[lane].clone()
                    };
                    expected_next += selectors[step] * (target - local_state[lane]);
                }
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

impl Poseidon2P24Hash16LeafAir {
    fn initial_state_expression<AB: AirBuilder>(
        &self,
        public_values: &[AB::PublicVar],
    ) -> Vec<AB::Expr> {
        let raw = (0..P24_WIDTH)
            .map(|lane| {
                if lane < 15 {
                    public_values[lane].into()
                } else {
                    AB::Expr::from_u32(self.leaf_iv[lane - 15])
                }
            })
            .collect::<Vec<AB::Expr>>();
        matrix_expression::<AB>(&self.permutation.external_matrix, &raw)
    }

    fn phase_completion_expression<AB: AirBuilder>(
        &self,
        final_round_state: &[AB::Expr],
        phase: usize,
        public_values: &[AB::PublicVar],
    ) -> Vec<AB::Expr> {
        let mut absorbed = final_round_state.to_vec();
        match phase {
            0 => {
                let last_input: AB::Expr = public_values[15].into();
                absorbed[0] = absorbed[0].clone() + last_input;
                matrix_expression::<AB>(&self.permutation.external_matrix, &absorbed)
            }
            1 => matrix_expression::<AB>(&self.permutation.external_matrix, &absorbed),
            2 => absorbed,
            _ => unreachable!("fixed leaf hash has exactly three permutations"),
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

/// Produces and verifies a STARK for the exact frozen `Hash16(Leaf, input)`
/// construction. This binds a candidate note commitment to its candidate
/// Merkle-leaf digest without exposing intermediate sponge states.
pub fn prove_and_verify_p24_leaf(
    commitment: BabyBearDigestV2,
) -> Result<Poseidon2P24LeafExperimentResult, StarkExperimentError> {
    let reference = Poseidon2P24Reference::load_candidate()?;
    let leaf = reference.leaf(commitment)?;
    let air = Poseidon2P24Hash16LeafAir::from_reference(&reference)?;
    let trace = build_p24_hash16_leaf_trace(&air, commitment);
    let public_values = commitment
        .into_iter()
        .chain(leaf)
        .map(Val::from_u32)
        .collect::<Vec<_>>();
    let config = make_hiding_config();
    let proof = prove(&config, &air, trace, &public_values);
    verify(&config, &air, &proof, &public_values)
        .map_err(|_| StarkExperimentError::VerificationFailed)?;
    Ok(Poseidon2P24LeafExperimentResult {
        commitment,
        leaf,
        trace_rows: P24_HASH16_LEAF_TRACE_ROWS,
    })
}

/// A command-friendly proof of the first candidate tree operation: hashing a
/// sixteen-element commitment into its `Leaf` digest.
pub fn run_p24_leaf_research_smoke()
-> Result<Poseidon2P24LeafExperimentResult, StarkExperimentError> {
    prove_and_verify_p24_leaf(core::array::from_fn(|index| index as u32 + 1))
}

#[derive(Debug)]
pub enum StarkExperimentError {
    CandidateParameters(Poseidon2P24ReferenceError),
    CandidateTreeParameters(Poseidon2P24CandidateError),
    VerificationFailed,
}

impl From<Poseidon2P24ReferenceError> for StarkExperimentError {
    fn from(value: Poseidon2P24ReferenceError) -> Self {
        Self::CandidateParameters(value)
    }
}

impl From<Poseidon2P24CandidateError> for StarkExperimentError {
    fn from(value: Poseidon2P24CandidateError) -> Self {
        Self::CandidateTreeParameters(value)
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
            Self::CandidateTreeParameters(error) => {
                write!(
                    formatter,
                    "could not load frozen P24 tree parameters: {error}"
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

fn build_p24_hash16_leaf_trace(
    air: &Poseidon2P24Hash16LeafAir,
    commitment: BabyBearDigestV2,
) -> RowMajorMatrix<Val> {
    let mut values = Val::zero_vec(P24_HASH16_LEAF_TRACE_ROWS * P24_HASH16_LEAF_TRACE_WIDTH);
    let mut raw_state = [Val::ZERO; P24_WIDTH];
    for (lane, value) in commitment.into_iter().take(15).enumerate() {
        raw_state[lane] = Val::from_u32(value);
    }
    for (lane, value) in air.leaf_iv.into_iter().enumerate() {
        raw_state[15 + lane] = Val::from_u32(value);
    }
    let mut state = matrix_values(&air.permutation.external_matrix, &raw_state);

    for row in 0..P24_HASH16_LEAF_TRACE_ROWS {
        let offset = row * P24_HASH16_LEAF_TRACE_WIDTH;
        values[offset..offset + P24_WIDTH].copy_from_slice(&state);
        if row < P24_HASH16_LEAF_STEPS {
            values[offset + P24_SELECTOR_OFFSET + row] = Val::ONE;
            let phase = row / P24_ROUNDS;
            let round = row % P24_ROUNDS;
            state = round_values(&air.permutation, state, round);
            if round + 1 == P24_ROUNDS && phase < P24_HASH16_LEAF_PERMUTATIONS - 1 {
                if phase == 0 {
                    state[0] += Val::from_u32(commitment[15]);
                }
                state = matrix_values(&air.permutation.external_matrix, &state);
            }
        }
    }
    RowMajorMatrix::new(values, P24_HASH16_LEAF_TRACE_WIDTH)
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
    use noxis_tree_params::{P24TreeValueV2, P24TreeVectorCorpusV2, P24TreeVectorRecordV2};

    use super::*;

    fn elements(value: P24TreeValueV2) -> BabyBearDigestV2 {
        core::array::from_fn(|index| {
            u32::from_le_bytes(
                value.as_bytes()[index * 4..(index + 1) * 4]
                    .try_into()
                    .expect("fixed P24 tree value bounds"),
            )
        })
    }

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

    #[test]
    fn leaf_hash_stark_matches_the_frozen_candidate_reference() {
        let commitment = core::array::from_fn(|index| index as u32 + 1);
        let result = prove_and_verify_p24_leaf(commitment).unwrap();
        let reference = Poseidon2P24Reference::load_candidate().unwrap();

        assert_eq!(result.leaf, reference.leaf(commitment).unwrap());
        assert_eq!(result.trace_rows, P24_HASH16_LEAF_TRACE_ROWS);
    }

    #[test]
    fn leaf_hash_proof_rejects_a_changed_public_leaf() {
        let commitment = core::array::from_fn(|index| index as u32 + 1);
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        let leaf = reference.leaf(commitment).unwrap();
        let air = Poseidon2P24Hash16LeafAir::from_reference(&reference).unwrap();
        let trace = build_p24_hash16_leaf_trace(&air, commitment);
        let public_values = commitment
            .into_iter()
            .chain(leaf)
            .map(Val::from_u32)
            .collect::<Vec<_>>();
        p3_air::check_constraints(&air, &trace, &public_values);
        let config = make_hiding_config();
        let proof = prove(&config, &air, trace, &public_values);
        let mut altered_public_values = public_values;
        altered_public_values[16] += Val::ONE;

        assert!(verify(&config, &air, &proof, &altered_public_values).is_err());
    }

    #[test]
    fn leaf_hash_stark_matches_every_external_leaf_vector() {
        let corpus = P24TreeVectorCorpusV2::frozen_complete_candidate_corpus();
        for record in corpus.records() {
            let P24TreeVectorRecordV2::Leaf { note, leaf } = record else {
                continue;
            };
            assert_eq!(
                prove_and_verify_p24_leaf(elements(*note)).unwrap().leaf,
                elements(*leaf)
            );
        }
    }
}
