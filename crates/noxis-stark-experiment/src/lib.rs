//! Executable Plonky3 STARK integration experiment for Noxis.
//!
//! This crate proves a deliberately small private accumulator transition with
//! a hiding FRI PCS. It demonstrates the real prover/verifier lifecycle and
//! public-value binding that a future Noxis AIR will need. It does **not**
//! prove note membership, nullifier absence, ownership, asset conservation,
//! range constraints, recipient binding, or any production privacy property.

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

/// The fixed AIR used only to establish the P3 integration boundary.
#[derive(Clone, Copy, Debug, Default)]
pub struct PrivateAccumulatorAir;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StarkExperimentError {
    VerificationFailed,
}

impl std::fmt::Display for StarkExperimentError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Plonky3 rejected the research STARK proof")
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

fn make_hiding_config() -> Config {
    let byte_hash = ByteHash {};
    let u64_hash = U64Hash::new(KeccakF {});
    let field_hash = FieldHash::new(u64_hash);
    let compress = Compress::new(u64_hash);
    let val_mmcs = ValHidingMmcs::new(field_hash, compress, 0, secure_rng());
    let challenge_mmcs = ChallengeHidingMmcs::new(val_mmcs.clone());
    let fri_params = FriParameters {
        log_blowup: 2,
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
}
