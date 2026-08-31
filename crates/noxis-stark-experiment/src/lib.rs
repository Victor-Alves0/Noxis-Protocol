//! Executable Plonky3 STARK integration experiment for Noxis.
//!
//! This crate contains executable Plonky3 STARK experiments with a hiding FRI
//! PCS. Its active smoke proof constrains the exact frozen Poseidon2-P24
//! permutation behind the Noxis candidate privacy primitives. It now also
//! proves standalone private `H_ADDR` and `H_NOTE` preimage relations, plus a
//! composed key-to-note-to-nullifier-to-leaf depth-32 membership relation. It
//! does **not** yet prove nullifier absence, state-anchor acceptance, a
//! complete private transfer, or any production privacy property. The
//! intent-bound value-conservation experiment remains only one local slice.

use noxis_nullifier_tree_reference::NullifierTreeReferenceError;
use noxis_poseidon2_privacy_reference::Poseidon2P24PrivacyReferenceError;
use noxis_poseidon2_reference::{
    BabyBearDigestV2, BabyBearStateP24, P24_WIDTH, Poseidon2P24Reference,
    Poseidon2P24ReferenceError,
};
use noxis_privacy_types::PrivacyTypesError;
use noxis_tree_params::{
    CandidatePoseidon2P24ManifestV2, Poseidon2P24CandidateError,
    Poseidon2P24IntentCommitmentCandidateError, Poseidon2P24NoteDomainsCandidateError,
    Poseidon2P24NullifierSparseCandidateError, Poseidon2P24TreeDomainV1,
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

mod addr;
mod intent;
mod intent_value_conservation;
mod note;
mod nxsm;
mod ownership;
mod profile;
mod value_conservation;

pub use addr::{
    Poseidon2P24AddrExperimentResult, prove_and_verify_p24_addr, run_p24_addr_research_smoke,
};
pub use intent::{
    Poseidon2P24IntentExperimentResult, prove_and_verify_p24_intent, run_p24_intent_research_smoke,
};
pub use intent_value_conservation::{
    Poseidon2P24IntentValueConservationExperimentResult,
    prove_and_verify_p24_intent_value_conservation,
};
pub use note::{
    Poseidon2P24NoteExperimentResult, Poseidon2P24NoteWithAssetExperimentResult,
    prove_and_verify_p24_note, prove_and_verify_p24_note_with_asset, run_p24_note_research_smoke,
};
pub use nxsm::{
    Poseidon2P24NxsmPrefix8ExperimentResult, Poseidon2P24NxsmPrefix8Proof,
    Poseidon2P24NxsmSequentialAbsencePreflightResult, prove_and_verify_p24_nxsm_absence_prefix8,
    prove_p24_nxsm_absence_prefix8, prove_p24_nxsm_absence_segment8,
    run_p24_nxsm_absence_path512_sequential_preflight, verify_p24_nxsm_absence_prefix8_proof,
};
pub use ownership::{
    Poseidon2P24OwnershipExperimentResult, Poseidon2P24OwnershipProof,
    prove_and_verify_p24_note_ownership, prove_and_verify_p24_note_ownership_path2,
    prove_and_verify_p24_note_ownership_path32,
    prove_and_verify_p24_note_ownership_path32_bound_note_commitment,
    prove_p24_note_ownership_path32, prove_p24_note_ownership_path32_bound_note_commitment,
    run_p24_note_ownership_research_smoke, verify_p24_note_ownership_proof,
};
pub use profile::{RESEARCH_STARK_VERIFIER_PROFILE_VERSION, ResearchStarkVerifierProfileV1};
pub use value_conservation::{
    Poseidon2P24ValueConservationExperimentResult, prove_and_verify_p24_value_conservation,
    prove_and_verify_p24_value_conservation_bound_outputs,
};

const TRACE_WIDTH: usize = 2;
const TRACE_ROWS: usize = 8;
pub(crate) const P24_ROUNDS: usize = 29;
const P24_TRACE_ROWS: usize = 32;
const P24_SELECTOR_OFFSET: usize = P24_WIDTH;
const P24_TRACE_WIDTH: usize = P24_WIDTH + P24_ROUNDS;
const P24_PUBLIC_VALUES: usize = P24_WIDTH * 2;
const P24_HASH16_LEAF_PERMUTATIONS: usize = 3;
const P24_HASH16_LEAF_STEPS: usize = P24_HASH16_LEAF_PERMUTATIONS * P24_ROUNDS;
const P24_HASH16_LEAF_TRACE_ROWS: usize = 128;
const P24_HASH16_LEAF_TRACE_WIDTH: usize = P24_WIDTH + P24_HASH16_LEAF_STEPS;
const P24_HASH16_LEAF_PUBLIC_VALUES: usize = 32;
const P24_HASH16_NODE_PERMUTATIONS: usize = 4;
const P24_HASH16_NODE_STEPS: usize = P24_HASH16_NODE_PERMUTATIONS * P24_ROUNDS;
const P24_HASH16_NODE_TRACE_ROWS: usize = 128;
const P24_HASH16_NODE_TRACE_WIDTH: usize = P24_WIDTH + P24_HASH16_NODE_STEPS;
const P24_HASH16_NODE_PUBLIC_VALUES: usize = 48;
const P24_HASH16_DIGEST_ELEMENTS: usize = 16;
const P24_MERKLE_STEP_PRIVATE_WITNESS_ELEMENTS: usize = (P24_HASH16_DIGEST_ELEMENTS * 2) + 1;
const P24_MERKLE_STEP_TRACE_WIDTH: usize =
    P24_HASH16_NODE_TRACE_WIDTH + P24_MERKLE_STEP_PRIVATE_WITNESS_ELEMENTS;
const P24_MERKLE_STEP_PUBLIC_VALUES: usize = P24_HASH16_DIGEST_ELEMENTS;
const P24_MERKLE_PATH2_PERMUTATIONS: usize = P24_HASH16_NODE_PERMUTATIONS * 2;
const P24_MERKLE_PATH2_STEPS: usize = P24_MERKLE_PATH2_PERMUTATIONS * P24_ROUNDS;
const P24_MERKLE_PATH2_TRACE_ROWS: usize = 256;
const P24_MERKLE_PATH2_PRIVATE_WITNESS_ELEMENTS: usize = (P24_HASH16_DIGEST_ELEMENTS * 4) + 2;
const P24_MERKLE_PATH2_TRACE_WIDTH: usize =
    P24_WIDTH + P24_MERKLE_PATH2_STEPS + P24_MERKLE_PATH2_PRIVATE_WITNESS_ELEMENTS;
const P24_MERKLE_PATH2_PUBLIC_VALUES: usize = P24_HASH16_DIGEST_ELEMENTS;
const P24_MERKLE_PATH2_LEAF_OFFSET: usize = 0;
const P24_MERKLE_PATH2_FIRST_SIBLING_OFFSET: usize = P24_HASH16_DIGEST_ELEMENTS;
const P24_MERKLE_PATH2_SECOND_SIBLING_OFFSET: usize = P24_HASH16_DIGEST_ELEMENTS * 2;
const P24_MERKLE_PATH2_FIRST_DIRECTION_OFFSET: usize = P24_HASH16_DIGEST_ELEMENTS * 3;
const P24_MERKLE_PATH2_SECOND_DIRECTION_OFFSET: usize = P24_MERKLE_PATH2_FIRST_DIRECTION_OFFSET + 1;
const P24_MERKLE_PATH2_INTERMEDIATE_OFFSET: usize = P24_MERKLE_PATH2_SECOND_DIRECTION_OFFSET + 1;
const P24_MERKLE_PATH_DEPTH: usize = 32;
const P24_MERKLE_PATH32_PERMUTATIONS: usize = P24_HASH16_NODE_PERMUTATIONS * P24_MERKLE_PATH_DEPTH;
const P24_MERKLE_PATH32_STEPS: usize = P24_MERKLE_PATH32_PERMUTATIONS * P24_ROUNDS;
const P24_MERKLE_PATH32_TRACE_ROWS: usize = 4096;
const P24_MERKLE_PATH32_ROUND_SELECTORS: usize = P24_ROUNDS;
const P24_MERKLE_PATH32_PHASE_SELECTORS: usize = P24_MERKLE_PATH32_PERMUTATIONS;
const P24_MERKLE_PATH32_PHASE_OFFSET: usize =
    P24_SELECTOR_OFFSET + P24_MERKLE_PATH32_ROUND_SELECTORS;
const P24_MERKLE_PATH32_DONE_OFFSET: usize =
    P24_MERKLE_PATH32_PHASE_OFFSET + P24_MERKLE_PATH32_PHASE_SELECTORS;
const P24_MERKLE_PATH32_WITNESS_OFFSET: usize = P24_MERKLE_PATH32_DONE_OFFSET + 1;
const P24_MERKLE_PATH32_PRIVATE_WITNESS_ELEMENTS: usize = P24_HASH16_DIGEST_ELEMENTS
    + (P24_HASH16_DIGEST_ELEMENTS * P24_MERKLE_PATH_DEPTH)
    + P24_MERKLE_PATH_DEPTH
    + (P24_HASH16_DIGEST_ELEMENTS * (P24_MERKLE_PATH_DEPTH - 1));
const P24_MERKLE_PATH32_TRACE_WIDTH: usize = P24_WIDTH
    + P24_MERKLE_PATH32_ROUND_SELECTORS
    + P24_MERKLE_PATH32_PHASE_SELECTORS
    + 1
    + P24_MERKLE_PATH32_PRIVATE_WITNESS_ELEMENTS;
const P24_MERKLE_PATH32_PUBLIC_VALUES: usize = P24_HASH16_DIGEST_ELEMENTS;
const P24_MERKLE_PATH32_LEAF_OFFSET: usize = 0;
const P24_MERKLE_PATH32_SIBLINGS_OFFSET: usize = P24_HASH16_DIGEST_ELEMENTS;
const P24_MERKLE_PATH32_DIRECTIONS_OFFSET: usize =
    P24_MERKLE_PATH32_SIBLINGS_OFFSET + (P24_HASH16_DIGEST_ELEMENTS * P24_MERKLE_PATH_DEPTH);
const P24_MERKLE_PATH32_INTERMEDIATES_OFFSET: usize =
    P24_MERKLE_PATH32_DIRECTIONS_OFFSET + P24_MERKLE_PATH_DEPTH;
const P24_MERKLE_PATH32_PROVER_STACK_BYTES: usize = 64 * 1024 * 1024;

pub(crate) type Val = BabyBear;
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

/// Public result of a STARK for the candidate ordered
/// `Hash16(Node, left || right)` construction. The child and parent digests
/// are public; all sponge states remain in the hidden trace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Poseidon2P24NodeExperimentResult {
    pub left: BabyBearDigestV2,
    pub right: BabyBearDigestV2,
    pub parent: BabyBearDigestV2,
    pub trace_rows: usize,
}

/// Public result of one candidate Merkle-path step. The current digest, its
/// sibling and the left/right direction remain private witness values; only
/// their ordered `Node` parent is public.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Poseidon2P24MerkleStepExperimentResult {
    pub parent: BabyBearDigestV2,
    pub trace_rows: usize,
}

/// Public result of two consecutive candidate Merkle-path steps. The leaf,
/// both siblings, both directions and their intermediate parent are private;
/// only the final root is public.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Poseidon2P24MerklePath2ExperimentResult {
    pub root: BabyBearDigestV2,
    pub trace_rows: usize,
}

/// Public result of a full depth-32 candidate Merkle-path proof. The leaf,
/// siblings, directions and intermediate nodes remain private; only the root
/// is public.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Poseidon2P24MerklePath32ExperimentResult {
    pub root: BabyBearDigestV2,
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
    pub(crate) external_matrix: [[u32; P24_WIDTH]; P24_WIDTH],
    pub(crate) internal_matrix: [[u32; P24_WIDTH]; P24_WIDTH],
    pub(crate) round_constants: [[u32; P24_WIDTH]; P24_ROUNDS],
}

/// The fixed candidate shapes currently supported by the Hash16 AIR.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Poseidon2P24Hash16Shape {
    Leaf,
    Node,
    MerkleStep,
    MerklePath2,
    MerklePath32,
}

impl Poseidon2P24Hash16Shape {
    const fn domain(self) -> Poseidon2P24TreeDomainV1 {
        match self {
            Self::Leaf => Poseidon2P24TreeDomainV1::Leaf,
            Self::Node | Self::MerkleStep | Self::MerklePath2 | Self::MerklePath32 => {
                Poseidon2P24TreeDomainV1::Node
            }
        }
    }

    const fn input_elements(self) -> usize {
        match self {
            Self::Leaf => P24_HASH16_DIGEST_ELEMENTS,
            Self::Node | Self::MerkleStep | Self::MerklePath2 | Self::MerklePath32 => {
                P24_HASH16_DIGEST_ELEMENTS * 2
            }
        }
    }

    const fn permutations(self) -> usize {
        match self {
            Self::Leaf => P24_HASH16_LEAF_PERMUTATIONS,
            Self::Node | Self::MerkleStep => P24_HASH16_NODE_PERMUTATIONS,
            Self::MerklePath2 => P24_MERKLE_PATH2_PERMUTATIONS,
            Self::MerklePath32 => P24_MERKLE_PATH32_PERMUTATIONS,
        }
    }

    const fn steps(self) -> usize {
        self.permutations() * P24_ROUNDS
    }

    const fn trace_rows(self) -> usize {
        match self {
            Self::Leaf => P24_HASH16_LEAF_TRACE_ROWS,
            Self::Node | Self::MerkleStep => P24_HASH16_NODE_TRACE_ROWS,
            Self::MerklePath2 => P24_MERKLE_PATH2_TRACE_ROWS,
            Self::MerklePath32 => P24_MERKLE_PATH32_TRACE_ROWS,
        }
    }

    const fn trace_width(self) -> usize {
        match self {
            Self::Leaf => P24_HASH16_LEAF_TRACE_WIDTH,
            Self::Node => P24_HASH16_NODE_TRACE_WIDTH,
            Self::MerkleStep => P24_MERKLE_STEP_TRACE_WIDTH,
            Self::MerklePath2 => P24_MERKLE_PATH2_TRACE_WIDTH,
            Self::MerklePath32 => P24_MERKLE_PATH32_TRACE_WIDTH,
        }
    }

    const fn public_values(self) -> usize {
        match self {
            Self::Leaf => P24_HASH16_LEAF_PUBLIC_VALUES,
            Self::Node => P24_HASH16_NODE_PUBLIC_VALUES,
            Self::MerkleStep => P24_MERKLE_STEP_PUBLIC_VALUES,
            Self::MerklePath2 => P24_MERKLE_PATH2_PUBLIC_VALUES,
            Self::MerklePath32 => P24_MERKLE_PATH32_PUBLIC_VALUES,
        }
    }

    const fn output_offset(self) -> usize {
        match self {
            Self::Leaf | Self::Node => self.input_elements(),
            Self::MerkleStep | Self::MerklePath2 | Self::MerklePath32 => 0,
        }
    }

    const fn private_witness_offset(self) -> Option<usize> {
        match self {
            Self::MerkleStep | Self::MerklePath2 => Some(P24_SELECTOR_OFFSET + self.steps()),
            Self::MerklePath32 => Some(P24_MERKLE_PATH32_WITNESS_OFFSET),
            Self::Leaf | Self::Node => None,
        }
    }

    const fn private_witness_elements(self) -> usize {
        match self {
            Self::MerkleStep => P24_MERKLE_STEP_PRIVATE_WITNESS_ELEMENTS,
            Self::MerklePath2 => P24_MERKLE_PATH2_PRIVATE_WITNESS_ELEMENTS,
            Self::MerklePath32 => P24_MERKLE_PATH32_PRIVATE_WITNESS_ELEMENTS,
            Self::Leaf | Self::Node => 0,
        }
    }

    const fn hash_count(self) -> usize {
        match self {
            Self::MerklePath2 => 2,
            Self::MerklePath32 => P24_MERKLE_PATH_DEPTH,
            Self::Leaf | Self::Node | Self::MerkleStep => 1,
        }
    }

    const fn permutations_per_hash(self) -> usize {
        match self {
            Self::Leaf => P24_HASH16_LEAF_PERMUTATIONS,
            Self::Node | Self::MerkleStep | Self::MerklePath2 | Self::MerklePath32 => {
                P24_HASH16_NODE_PERMUTATIONS
            }
        }
    }
}

/// AIR for exact fixed-arity candidate `Hash16` constructions.
///
/// It composes constrained P24 permutations with a frozen domain IV, its fixed
/// absorption phases and the prescribed squeeze. The supported `Leaf` and
/// ordered `Node` shapes share the same logic but have distinct arities and
/// public-value layouts. `MerkleStep` adds a private current digest, sibling
/// and boolean direction, but it is only one step and not yet a membership or
/// private-transfer proof.
#[derive(Clone, Debug)]
pub struct Poseidon2P24Hash16Air {
    permutation: Poseidon2P24Air,
    shape: Poseidon2P24Hash16Shape,
    iv: [u32; 9],
}

impl Poseidon2P24Air {
    pub(crate) fn from_reference(reference: &Poseidon2P24Reference) -> Self {
        Self {
            external_matrix: *reference.external_matrix(),
            internal_matrix: *reference.internal_matrix(),
            round_constants: *reference.round_constants(),
        }
    }
}

impl Poseidon2P24Hash16Air {
    fn from_reference(
        reference: &Poseidon2P24Reference,
        shape: Poseidon2P24Hash16Shape,
    ) -> Result<Self, StarkExperimentError> {
        Ok(Self {
            permutation: Poseidon2P24Air::from_reference(reference),
            shape,
            iv: CandidatePoseidon2P24ManifestV2::new().iv(shape.domain())?,
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

impl<F> BaseAir<F> for Poseidon2P24Hash16Air {
    fn width(&self) -> usize {
        self.shape.trace_width()
    }

    fn num_public_values(&self) -> usize {
        self.shape.public_values()
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(match self.shape {
            Poseidon2P24Hash16Shape::MerklePath32 => 10,
            Poseidon2P24Hash16Shape::Leaf
            | Poseidon2P24Hash16Shape::Node
            | Poseidon2P24Hash16Shape::MerkleStep
            | Poseidon2P24Hash16Shape::MerklePath2 => 8,
        })
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

impl<AB: AirBuilder> Air<AB> for Poseidon2P24Hash16Air {
    fn eval(&self, builder: &mut AB) {
        if self.shape == Poseidon2P24Hash16Shape::MerklePath32 {
            self.eval_merkle_path32::<AB>(builder);
            return;
        }

        let public_values = builder.public_values().to_vec();
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let local_state = &local[..P24_WIDTH];
        let next_state = &next[..P24_WIDTH];
        let selector_end = P24_SELECTOR_OFFSET + self.shape.steps();
        let selectors = &local[P24_SELECTOR_OFFSET..selector_end];
        let next_selectors = &next[P24_SELECTOR_OFFSET..selector_end];

        let initial_state = self.initial_state_expression::<AB>(0, local, &public_values);
        for lane in 0..P24_WIDTH {
            builder
                .when_first_row()
                .assert_eq(local_state[lane], initial_state[lane].clone());
        }

        if let Some(witness_offset) = self.shape.private_witness_offset() {
            let witness = &local[witness_offset..];
            let next_witness = &next[witness_offset..];
            for direction_index in 0..self.private_direction_count() {
                let direction: AB::Expr =
                    witness[self.private_direction_offset() + direction_index].into();
                builder.assert_zero(direction.clone() * (direction - AB::Expr::ONE));
            }
            for lane in 0..self.shape.private_witness_elements() {
                builder
                    .when_transition()
                    .assert_eq(next_witness[lane], witness[lane]);
            }
        }

        for selector in 0..self.shape.steps() {
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
        let phase_completions: Vec<Vec<AB::Expr>> = (0..self.shape.permutations())
            .map(|phase| {
                self.phase_completion_expression::<AB>(
                    &round_states[P24_ROUNDS - 1],
                    phase,
                    local,
                    &public_values,
                )
            })
            .collect();
        let public_output = public_values
            .iter()
            .skip(self.shape.output_offset())
            .take(P24_HASH16_DIGEST_ELEMENTS)
            .copied()
            .map(Into::into)
            .collect::<Vec<AB::Expr>>();
        self.assert_hash_output::<AB>(
            builder,
            selectors,
            &round_states[P24_ROUNDS - 1],
            self.shape.hash_count() - 1,
            &public_output,
        );
        if self.shape == Poseidon2P24Hash16Shape::MerklePath2 {
            let witness_offset = self
                .shape
                .private_witness_offset()
                .expect("MerklePath2 always has private witness columns");
            let intermediate_output = local[witness_offset + P24_MERKLE_PATH2_INTERMEDIATE_OFFSET
                ..witness_offset
                    + P24_MERKLE_PATH2_INTERMEDIATE_OFFSET
                    + P24_HASH16_DIGEST_ELEMENTS]
                .iter()
                .copied()
                .map(Into::into)
                .collect::<Vec<AB::Expr>>();
            self.assert_hash_output::<AB>(
                builder,
                selectors,
                &round_states[P24_ROUNDS - 1],
                0,
                &intermediate_output,
            );
        } else if self.shape == Poseidon2P24Hash16Shape::MerklePath32 {
            let witness_offset = self
                .shape
                .private_witness_offset()
                .expect("MerklePath32 always has private witness columns");
            for hash_index in 0..P24_MERKLE_PATH_DEPTH - 1 {
                let intermediate_output = local[witness_offset
                    + P24_MERKLE_PATH32_INTERMEDIATES_OFFSET
                    + (hash_index * P24_HASH16_DIGEST_ELEMENTS)
                    ..witness_offset
                        + P24_MERKLE_PATH32_INTERMEDIATES_OFFSET
                        + ((hash_index + 1) * P24_HASH16_DIGEST_ELEMENTS)]
                    .iter()
                    .copied()
                    .map(Into::into)
                    .collect::<Vec<AB::Expr>>();
                self.assert_hash_output::<AB>(
                    builder,
                    selectors,
                    &round_states[P24_ROUNDS - 1],
                    hash_index,
                    &intermediate_output,
                );
            }
        }

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
    pub(crate) fn round_expression<AB: AirBuilder>(
        &self,
        state: &[AB::Var],
        round: usize,
    ) -> Vec<AB::Expr> {
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

impl Poseidon2P24Hash16Air {
    fn eval_merkle_path32<AB: AirBuilder>(&self, builder: &mut AB) {
        let public_values = builder.public_values().to_vec();
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let local_state = &local[..P24_WIDTH];
        let next_state = &next[..P24_WIDTH];
        let round_selectors =
            &local[P24_SELECTOR_OFFSET..P24_SELECTOR_OFFSET + P24_MERKLE_PATH32_ROUND_SELECTORS];
        let next_round_selectors =
            &next[P24_SELECTOR_OFFSET..P24_SELECTOR_OFFSET + P24_MERKLE_PATH32_ROUND_SELECTORS];
        let phase_selectors = &local[P24_MERKLE_PATH32_PHASE_OFFSET
            ..P24_MERKLE_PATH32_PHASE_OFFSET + P24_MERKLE_PATH32_PHASE_SELECTORS];
        let next_phase_selectors = &next[P24_MERKLE_PATH32_PHASE_OFFSET
            ..P24_MERKLE_PATH32_PHASE_OFFSET + P24_MERKLE_PATH32_PHASE_SELECTORS];
        let done = local[P24_MERKLE_PATH32_DONE_OFFSET];
        let next_done = next[P24_MERKLE_PATH32_DONE_OFFSET];
        let initial_state = self.initial_state_expression::<AB>(0, local, &public_values);

        for lane in 0..P24_WIDTH {
            builder
                .when_first_row()
                .assert_eq(local_state[lane], initial_state[lane].clone());
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

        let terminal: AB::Expr = round_selectors[P24_ROUNDS - 1]
            * phase_selectors[P24_MERKLE_PATH32_PHASE_SELECTORS - 1];
        builder.when_transition().assert_eq(
            next_done,
            done_expr.clone() + terminal.clone() * (AB::Expr::ONE - done_expr.clone()),
        );
        builder.when_transition().assert_eq(
            next_round_selectors[0],
            round_selectors[P24_ROUNDS - 1]
                * (AB::Expr::ONE
                    - AB::Expr::from(phase_selectors[P24_MERKLE_PATH32_PHASE_SELECTORS - 1])),
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
                + (round_selectors[P24_ROUNDS - 1]
                    * phase_selectors[P24_MERKLE_PATH32_PHASE_SELECTORS - 1]),
        );
        for phase in 0..P24_MERKLE_PATH32_PHASE_SELECTORS - 1 {
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
            next_phase_selectors[P24_MERKLE_PATH32_PHASE_SELECTORS - 1],
            phase_selectors[P24_MERKLE_PATH32_PHASE_SELECTORS - 1]
                + (round_selectors[P24_ROUNDS - 1]
                    * phase_selectors[P24_MERKLE_PATH32_PHASE_SELECTORS - 2]),
        );

        let witness_offset = self
            .shape
            .private_witness_offset()
            .expect("MerklePath32 always has private witness columns");
        for direction_index in 0..P24_MERKLE_PATH_DEPTH {
            let direction: AB::Expr = local
                [witness_offset + P24_MERKLE_PATH32_DIRECTIONS_OFFSET + direction_index]
                .into();
            builder.assert_zero(direction.clone() * (direction - AB::Expr::ONE));
        }
        for lane in 0..P24_MERKLE_PATH32_PRIVATE_WITNESS_ELEMENTS {
            builder
                .when_transition()
                .assert_eq(next[witness_offset + lane], local[witness_offset + lane]);
        }

        let round_states: Vec<Vec<AB::Expr>> = (0..P24_ROUNDS)
            .map(|round| self.permutation.round_expression::<AB>(local_state, round))
            .collect();
        let phase_completions: Vec<Vec<AB::Expr>> = (0..P24_MERKLE_PATH32_PHASE_SELECTORS)
            .map(|phase| {
                self.phase_completion_expression::<AB>(
                    &round_states[P24_ROUNDS - 1],
                    phase,
                    local,
                    &public_values,
                )
            })
            .collect();
        for lane in 0..P24_WIDTH {
            let mut final_round_target: AB::Expr = local_state[lane].into();
            for phase in 0..P24_MERKLE_PATH32_PHASE_SELECTORS {
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

        self.assert_merkle_path32_outputs::<AB>(
            builder,
            &round_states[P24_ROUNDS - 1],
            round_selectors[P24_ROUNDS - 1],
            phase_selectors,
            done,
            local,
            &public_values,
        );
    }

    #[allow(clippy::too_many_arguments)] // AIR evaluation context is intentionally explicit.
    fn assert_merkle_path32_outputs<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        final_round_state: &[AB::Expr],
        final_round_selector: AB::Var,
        phase_selectors: &[AB::Var],
        done: AB::Var,
        local: &[AB::Var],
        public_values: &[AB::PublicVar],
    ) {
        let active: AB::Expr = AB::Expr::ONE - AB::Expr::from(done);
        let witness_offset = P24_MERKLE_PATH32_WITNESS_OFFSET;
        for hash_index in 0..P24_MERKLE_PATH_DEPTH {
            let output = if hash_index + 1 == P24_MERKLE_PATH_DEPTH {
                public_values
                    .iter()
                    .copied()
                    .map(Into::into)
                    .collect::<Vec<AB::Expr>>()
            } else {
                let start = witness_offset
                    + P24_MERKLE_PATH32_INTERMEDIATES_OFFSET
                    + (hash_index * P24_HASH16_DIGEST_ELEMENTS);
                local[start..start + P24_HASH16_DIGEST_ELEMENTS]
                    .iter()
                    .copied()
                    .map(Into::into)
                    .collect::<Vec<AB::Expr>>()
            };
            let first_squeeze_phase = (hash_index * P24_HASH16_NODE_PERMUTATIONS) + 2;
            let final_squeeze_phase = first_squeeze_phase + 1;
            let first_gate: AB::Expr =
                active.clone() * final_round_selector * phase_selectors[first_squeeze_phase];
            for lane in 0..15 {
                builder.assert_zero(
                    first_gate.clone() * (final_round_state[lane].clone() - output[lane].clone()),
                );
            }
            let final_gate: AB::Expr =
                active.clone() * final_round_selector * phase_selectors[final_squeeze_phase];
            builder.assert_zero(final_gate * (final_round_state[0].clone() - output[15].clone()));
        }
    }

    const fn private_direction_offset(&self) -> usize {
        match self.shape {
            Poseidon2P24Hash16Shape::MerkleStep => P24_MERKLE_STEP_PRIVATE_WITNESS_ELEMENTS - 1,
            Poseidon2P24Hash16Shape::MerklePath2 => P24_MERKLE_PATH2_FIRST_DIRECTION_OFFSET,
            Poseidon2P24Hash16Shape::MerklePath32 => P24_MERKLE_PATH32_DIRECTIONS_OFFSET,
            Poseidon2P24Hash16Shape::Leaf | Poseidon2P24Hash16Shape::Node => 0,
        }
    }

    const fn private_direction_count(&self) -> usize {
        match self.shape {
            Poseidon2P24Hash16Shape::MerkleStep => 1,
            Poseidon2P24Hash16Shape::MerklePath2 => 2,
            Poseidon2P24Hash16Shape::MerklePath32 => P24_MERKLE_PATH_DEPTH,
            Poseidon2P24Hash16Shape::Leaf | Poseidon2P24Hash16Shape::Node => 0,
        }
    }

    fn initial_state_expression<AB: AirBuilder>(
        &self,
        hash_index: usize,
        local: &[AB::Var],
        public_values: &[AB::PublicVar],
    ) -> Vec<AB::Expr> {
        let raw = (0..P24_WIDTH)
            .map(|lane| {
                if lane < 15 && lane < self.shape.input_elements() {
                    self.input_expression::<AB>(hash_index, lane, local, public_values)
                } else {
                    AB::Expr::from_u32(self.iv[lane - 15])
                }
            })
            .collect::<Vec<AB::Expr>>();
        matrix_expression::<AB>(&self.permutation.external_matrix, &raw)
    }

    fn phase_completion_expression<AB: AirBuilder>(
        &self,
        final_round_state: &[AB::Expr],
        phase: usize,
        local: &[AB::Var],
        public_values: &[AB::PublicVar],
    ) -> Vec<AB::Expr> {
        let mut absorbed = final_round_state.to_vec();
        let permutations_per_hash = self.shape.permutations_per_hash();
        let hash_index = phase / permutations_per_hash;
        let phase_in_hash = phase % permutations_per_hash;
        match phase_in_hash {
            phase_in_hash if phase_in_hash + 1 < permutations_per_hash => {
                let input_start = (phase_in_hash + 1) * 15;
                for (lane, absorbed_lane) in absorbed.iter_mut().enumerate().take(15) {
                    if input_start + lane < self.shape.input_elements() {
                        let input = self.input_expression::<AB>(
                            hash_index,
                            input_start + lane,
                            local,
                            public_values,
                        );
                        *absorbed_lane = absorbed_lane.clone() + input;
                    }
                }
                matrix_expression::<AB>(&self.permutation.external_matrix, &absorbed)
            }
            _ if hash_index + 1 < self.shape.hash_count() => {
                self.initial_state_expression::<AB>(hash_index + 1, local, public_values)
            }
            _ => absorbed,
        }
    }

    fn input_expression<AB: AirBuilder>(
        &self,
        hash_index: usize,
        input_index: usize,
        local: &[AB::Var],
        public_values: &[AB::PublicVar],
    ) -> AB::Expr {
        match self.shape {
            Poseidon2P24Hash16Shape::Leaf | Poseidon2P24Hash16Shape::Node => {
                public_values[input_index].into()
            }
            Poseidon2P24Hash16Shape::MerkleStep => {
                let witness_offset = self
                    .shape
                    .private_witness_offset()
                    .expect("MerkleStep always has private witness columns");
                let lane = input_index % P24_HASH16_DIGEST_ELEMENTS;
                let current: AB::Expr = local[witness_offset + lane].into();
                let sibling: AB::Expr =
                    local[witness_offset + P24_HASH16_DIGEST_ELEMENTS + lane].into();
                let direction: AB::Expr =
                    local[witness_offset + (P24_HASH16_DIGEST_ELEMENTS * 2)].into();

                if input_index < P24_HASH16_DIGEST_ELEMENTS {
                    current.clone() + direction.clone() * (sibling.clone() - current)
                } else {
                    sibling.clone() + direction * (current - sibling)
                }
            }
            Poseidon2P24Hash16Shape::MerklePath2 => {
                let witness_offset = self
                    .shape
                    .private_witness_offset()
                    .expect("MerklePath2 always has private witness columns");
                let lane = input_index % P24_HASH16_DIGEST_ELEMENTS;
                let (current_offset, sibling_offset, direction_offset) = match hash_index {
                    0 => (
                        P24_MERKLE_PATH2_LEAF_OFFSET,
                        P24_MERKLE_PATH2_FIRST_SIBLING_OFFSET,
                        P24_MERKLE_PATH2_FIRST_DIRECTION_OFFSET,
                    ),
                    1 => (
                        P24_MERKLE_PATH2_INTERMEDIATE_OFFSET,
                        P24_MERKLE_PATH2_SECOND_SIBLING_OFFSET,
                        P24_MERKLE_PATH2_SECOND_DIRECTION_OFFSET,
                    ),
                    _ => unreachable!("MerklePath2 has exactly two hashes"),
                };
                let current: AB::Expr = local[witness_offset + current_offset + lane].into();
                let sibling: AB::Expr = local[witness_offset + sibling_offset + lane].into();
                let direction: AB::Expr = local[witness_offset + direction_offset].into();

                if input_index < P24_HASH16_DIGEST_ELEMENTS {
                    current.clone() + direction.clone() * (sibling.clone() - current)
                } else {
                    sibling.clone() + direction * (current - sibling)
                }
            }
            Poseidon2P24Hash16Shape::MerklePath32 => {
                let witness_offset = self
                    .shape
                    .private_witness_offset()
                    .expect("MerklePath32 always has private witness columns");
                let lane = input_index % P24_HASH16_DIGEST_ELEMENTS;
                let current_offset = if hash_index == 0 {
                    P24_MERKLE_PATH32_LEAF_OFFSET
                } else {
                    P24_MERKLE_PATH32_INTERMEDIATES_OFFSET
                        + ((hash_index - 1) * P24_HASH16_DIGEST_ELEMENTS)
                };
                let sibling_offset =
                    P24_MERKLE_PATH32_SIBLINGS_OFFSET + (hash_index * P24_HASH16_DIGEST_ELEMENTS);
                let direction_offset = P24_MERKLE_PATH32_DIRECTIONS_OFFSET + hash_index;
                let current: AB::Expr = local[witness_offset + current_offset + lane].into();
                let sibling: AB::Expr = local[witness_offset + sibling_offset + lane].into();
                let direction: AB::Expr = local[witness_offset + direction_offset].into();

                if input_index < P24_HASH16_DIGEST_ELEMENTS {
                    current.clone() + direction.clone() * (sibling.clone() - current)
                } else {
                    sibling.clone() + direction * (current - sibling)
                }
            }
        }
    }

    fn assert_hash_output<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        selectors: &[AB::Var],
        final_round_state: &[AB::Expr],
        hash_index: usize,
        output: &[AB::Expr],
    ) {
        let permutations_per_hash = self.shape.permutations_per_hash();
        let final_absorption_phase =
            (hash_index * permutations_per_hash) + ((self.shape.input_elements() - 1) / 15);
        for (lane, output_lane) in output.iter().take(15).enumerate() {
            builder.assert_zero(
                selectors[(P24_ROUNDS * (final_absorption_phase + 1)) - 1]
                    * (final_round_state[lane].clone() - output_lane.clone()),
            );
        }
        builder.assert_zero(
            selectors[(P24_ROUNDS * ((hash_index + 1) * permutations_per_hash)) - 1]
                * (final_round_state[0].clone() - output[15].clone()),
        );
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
    let leaf = prove_and_verify_p24_hash16(Poseidon2P24Hash16Shape::Leaf, &commitment)?;
    Ok(Poseidon2P24LeafExperimentResult {
        commitment,
        leaf,
        trace_rows: P24_HASH16_LEAF_TRACE_ROWS,
    })
}

/// Produces and verifies a STARK for the exact frozen ordered
/// `Hash16(Node, left || right)` construction. This binds both public child
/// digests, in their prescribed order, to the public parent digest without
/// exposing intermediate sponge states.
pub fn prove_and_verify_p24_node(
    left: BabyBearDigestV2,
    right: BabyBearDigestV2,
) -> Result<Poseidon2P24NodeExperimentResult, StarkExperimentError> {
    let mut input = [0_u32; P24_HASH16_DIGEST_ELEMENTS * 2];
    input[..P24_HASH16_DIGEST_ELEMENTS].copy_from_slice(&left);
    input[P24_HASH16_DIGEST_ELEMENTS..].copy_from_slice(&right);
    let parent = prove_and_verify_p24_hash16(Poseidon2P24Hash16Shape::Node, &input)?;
    Ok(Poseidon2P24NodeExperimentResult {
        left,
        right,
        parent,
        trace_rows: P24_HASH16_NODE_TRACE_ROWS,
    })
}

/// Produces and verifies a hiding-FRI STARK for one candidate Merkle-path
/// step. `current_is_right` is a private Boolean witness: it selects either
/// `Node(current, sibling)` or `Node(sibling, current)`, while the verifier
/// learns only the resulting public parent digest.
///
/// This proves a single ordered hash relation, not membership in a committed
/// tree. A later path AIR must bind consecutive steps to a public root.
pub fn prove_and_verify_p24_merkle_step(
    current: BabyBearDigestV2,
    sibling: BabyBearDigestV2,
    current_is_right: bool,
) -> Result<Poseidon2P24MerkleStepExperimentResult, StarkExperimentError> {
    let reference = Poseidon2P24Reference::load_candidate()?;
    let (left, right) = if current_is_right {
        (sibling, current)
    } else {
        (current, sibling)
    };
    let parent = reference.node(left, right)?;
    let air =
        Poseidon2P24Hash16Air::from_reference(&reference, Poseidon2P24Hash16Shape::MerkleStep)?;
    let trace = build_p24_merkle_step_trace(&air, current, sibling, current_is_right);
    let public_values = parent.map(Val::from_u32);
    let config = make_hiding_config();
    let proof = prove(&config, &air, trace, &public_values);
    verify(&config, &air, &proof, &public_values)
        .map_err(|_| StarkExperimentError::VerificationFailed)?;
    Ok(Poseidon2P24MerkleStepExperimentResult {
        parent,
        trace_rows: P24_HASH16_NODE_TRACE_ROWS,
    })
}

/// Produces and verifies a hiding-FRI STARK for two consecutive candidate
/// Merkle-path steps. The leaf, siblings, direction bits and the intermediate
/// parent are private witness values; only the final root is public.
///
/// This establishes the first compositional membership building block. It is
/// intentionally limited to two levels and does not yet bind the leaf to a
/// note opening or the root to a ledger state anchor.
pub fn prove_and_verify_p24_merkle_path2(
    leaf: BabyBearDigestV2,
    siblings: [BabyBearDigestV2; 2],
    current_is_right: [bool; 2],
) -> Result<Poseidon2P24MerklePath2ExperimentResult, StarkExperimentError> {
    let reference = Poseidon2P24Reference::load_candidate()?;
    let intermediate = candidate_node(&reference, leaf, siblings[0], current_is_right[0])?;
    let root = candidate_node(&reference, intermediate, siblings[1], current_is_right[1])?;
    let air =
        Poseidon2P24Hash16Air::from_reference(&reference, Poseidon2P24Hash16Shape::MerklePath2)?;
    let trace = build_p24_merkle_path2_trace(&air, leaf, siblings, current_is_right, intermediate);
    let public_values = root.map(Val::from_u32);
    let config = make_hiding_config();
    let proof = prove(&config, &air, trace, &public_values);
    verify(&config, &air, &proof, &public_values)
        .map_err(|_| StarkExperimentError::VerificationFailed)?;
    Ok(Poseidon2P24MerklePath2ExperimentResult {
        root,
        trace_rows: P24_MERKLE_PATH2_TRACE_ROWS,
    })
}

/// Produces and verifies a hiding-FRI STARK for the full fixed depth-32 P24
/// candidate Merkle path. The `leaf_index` supplies private direction bits in
/// least-significant-bit-first order; the verifier receives only `root`.
///
/// This proves candidate tree membership relative to the supplied public root.
/// It still does not prove ownership, bind the leaf to a note opening, or bind
/// the root to a Noxis state anchor.
pub fn prove_and_verify_p24_merkle_path32(
    leaf: BabyBearDigestV2,
    leaf_index: u32,
    siblings: [BabyBearDigestV2; P24_MERKLE_PATH_DEPTH],
) -> Result<Poseidon2P24MerklePath32ExperimentResult, StarkExperimentError> {
    let reference = Poseidon2P24Reference::load_candidate()?;
    let directions = core::array::from_fn(|level| ((leaf_index >> level) & 1) == 1);
    let mut current = leaf;
    let mut intermediates = [[0_u32; P24_HASH16_DIGEST_ELEMENTS]; P24_MERKLE_PATH_DEPTH - 1];
    for level in 0..P24_MERKLE_PATH_DEPTH {
        current = candidate_node(&reference, current, siblings[level], directions[level])?;
        if level + 1 < P24_MERKLE_PATH_DEPTH {
            intermediates[level] = current;
        }
    }
    let root = current;
    let air =
        Poseidon2P24Hash16Air::from_reference(&reference, Poseidon2P24Hash16Shape::MerklePath32)?;
    let trace = build_p24_merkle_path32_trace(&air, leaf, siblings, directions, intermediates);
    let public_values = root.map(Val::from_u32);
    prove_and_verify_with_large_stack(air, trace, public_values)?;
    Ok(Poseidon2P24MerklePath32ExperimentResult {
        root,
        trace_rows: P24_MERKLE_PATH32_TRACE_ROWS,
    })
}

fn prove_and_verify_p24_hash16(
    shape: Poseidon2P24Hash16Shape,
    input: &[u32],
) -> Result<BabyBearDigestV2, StarkExperimentError> {
    let reference = Poseidon2P24Reference::load_candidate()?;
    let output = reference.hash16(shape.domain(), input)?;
    let air = Poseidon2P24Hash16Air::from_reference(&reference, shape)?;
    let trace = build_p24_hash16_trace(&air, input);
    let public_values = input
        .iter()
        .copied()
        .chain(output)
        .map(Val::from_u32)
        .collect::<Vec<_>>();
    let config = make_hiding_config();
    let proof = prove(&config, &air, trace, &public_values);
    verify(&config, &air, &proof, &public_values)
        .map_err(|_| StarkExperimentError::VerificationFailed)?;
    Ok(output)
}

fn candidate_node(
    reference: &Poseidon2P24Reference,
    current: BabyBearDigestV2,
    sibling: BabyBearDigestV2,
    current_is_right: bool,
) -> Result<BabyBearDigestV2, Poseidon2P24ReferenceError> {
    if current_is_right {
        reference.node(sibling, current)
    } else {
        reference.node(current, sibling)
    }
}

/// A command-friendly proof of the first candidate tree operation: hashing a
/// sixteen-element commitment into its `Leaf` digest.
pub fn run_p24_leaf_research_smoke()
-> Result<Poseidon2P24LeafExperimentResult, StarkExperimentError> {
    prove_and_verify_p24_leaf(core::array::from_fn(|index| index as u32 + 1))
}

/// A command-friendly proof that the candidate ordered parent transformation
/// binds distinct left and right child digests.
pub fn run_p24_node_research_smoke()
-> Result<Poseidon2P24NodeExperimentResult, StarkExperimentError> {
    prove_and_verify_p24_node(
        core::array::from_fn(|index| index as u32 + 1),
        core::array::from_fn(|index| index as u32 + 17),
    )
}

/// A command-friendly one-step candidate Merkle proof with a private right
/// direction bit.
pub fn run_p24_merkle_step_research_smoke()
-> Result<Poseidon2P24MerkleStepExperimentResult, StarkExperimentError> {
    prove_and_verify_p24_merkle_step(
        core::array::from_fn(|index| index as u32 + 1),
        core::array::from_fn(|index| index as u32 + 17),
        true,
    )
}

/// A command-friendly candidate two-level Merkle path whose directions remain
/// private in the STARK trace.
pub fn run_p24_merkle_path2_research_smoke()
-> Result<Poseidon2P24MerklePath2ExperimentResult, StarkExperimentError> {
    prove_and_verify_p24_merkle_path2(
        core::array::from_fn(|index| index as u32 + 1),
        [
            core::array::from_fn(|index| index as u32 + 17),
            core::array::from_fn(|index| index as u32 + 33),
        ],
        [true, false],
    )
}

/// A command-friendly proof of one full fixed-depth candidate Merkle path.
pub fn run_p24_merkle_path32_research_smoke()
-> Result<Poseidon2P24MerklePath32ExperimentResult, StarkExperimentError> {
    let reference = Poseidon2P24Reference::load_candidate()?;
    let commitments = [
        core::array::from_fn(|index| index as u32 + 1),
        core::array::from_fn(|index| index as u32 + 17),
        core::array::from_fn(|index| index as u32 + 33),
    ];
    let (leaf, siblings, expected_root) = reference.small_tree_path(&commitments, 2)?;
    let result = prove_and_verify_p24_merkle_path32(leaf, 2, siblings)?;
    debug_assert_eq!(result.root, expected_root);
    Ok(result)
}

#[derive(Debug)]
pub enum StarkExperimentError {
    CandidateParameters(Poseidon2P24ReferenceError),
    CandidateTreeParameters(Poseidon2P24CandidateError),
    CandidatePrivateDomains(Poseidon2P24NoteDomainsCandidateError),
    CandidateIntentCommitment(Poseidon2P24IntentCommitmentCandidateError),
    CandidatePrivateReference(Poseidon2P24PrivacyReferenceError),
    PrivacyTypes(PrivacyTypesError),
    CandidateNullifierSparseDomains(Poseidon2P24NullifierSparseCandidateError),
    CandidateNullifierSparseReference(NullifierTreeReferenceError),
    InvalidNxsmSegmentByteIndex { actual: usize },
    NxsmSequentialRootMismatch,
    ZeroValueConservationInput { index: usize },
    UnsupportedValueConservationNoteVersion { index: usize },
    ValueConservationAssetMismatch { index: usize },
    ValueConservationOutputCommitmentMismatch { index: usize },
    ValueConservationInputOverflow,
    ValueConservationOutputOverflow,
    ValueConservationMismatch,
    OwnershipNoteCommitmentMismatch,
    VerificationFailed,
    ProverThreadFailed,
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

impl From<Poseidon2P24NoteDomainsCandidateError> for StarkExperimentError {
    fn from(value: Poseidon2P24NoteDomainsCandidateError) -> Self {
        Self::CandidatePrivateDomains(value)
    }
}

impl From<Poseidon2P24IntentCommitmentCandidateError> for StarkExperimentError {
    fn from(value: Poseidon2P24IntentCommitmentCandidateError) -> Self {
        Self::CandidateIntentCommitment(value)
    }
}

impl From<Poseidon2P24PrivacyReferenceError> for StarkExperimentError {
    fn from(value: Poseidon2P24PrivacyReferenceError) -> Self {
        Self::CandidatePrivateReference(value)
    }
}

impl From<PrivacyTypesError> for StarkExperimentError {
    fn from(value: PrivacyTypesError) -> Self {
        Self::PrivacyTypes(value)
    }
}

impl From<Poseidon2P24NullifierSparseCandidateError> for StarkExperimentError {
    fn from(value: Poseidon2P24NullifierSparseCandidateError) -> Self {
        Self::CandidateNullifierSparseDomains(value)
    }
}

impl From<NullifierTreeReferenceError> for StarkExperimentError {
    fn from(value: NullifierTreeReferenceError) -> Self {
        Self::CandidateNullifierSparseReference(value)
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
            Self::CandidatePrivateDomains(error) => {
                write!(
                    formatter,
                    "could not load frozen P24 private-domain parameters: {error}"
                )
            }
            Self::CandidateIntentCommitment(error) => {
                write!(
                    formatter,
                    "could not load frozen P24 intent-commitment parameters: {error}"
                )
            }
            Self::CandidatePrivateReference(error) => {
                write!(
                    formatter,
                    "could not evaluate the frozen P24 private-domain reference: {error}"
                )
            }
            Self::PrivacyTypes(error) => {
                write!(
                    formatter,
                    "invalid candidate private-transfer value: {error}"
                )
            }
            Self::CandidateNullifierSparseDomains(error) => {
                write!(
                    formatter,
                    "could not load frozen P24 sparse-nullifier parameters: {error}"
                )
            }
            Self::CandidateNullifierSparseReference(error) => {
                write!(
                    formatter,
                    "could not evaluate the frozen P24 sparse-nullifier reference: {error}"
                )
            }
            Self::InvalidNxsmSegmentByteIndex { actual } => {
                write!(
                    formatter,
                    "NXSM segment byte index {actual} exceeds the 64-byte nullifier"
                )
            }
            Self::NxsmSequentialRootMismatch => {
                formatter.write_str("verified NXSM segments did not reach the expected root")
            }
            Self::ZeroValueConservationInput { index } => {
                write!(
                    formatter,
                    "value-conservation input note {index} has zero value"
                )
            }
            Self::UnsupportedValueConservationNoteVersion { index } => {
                write!(
                    formatter,
                    "value-conservation note {index} has unsupported version"
                )
            }
            Self::ValueConservationAssetMismatch { index } => {
                write!(
                    formatter,
                    "value-conservation note {index} does not use the public asset"
                )
            }
            Self::ValueConservationOutputCommitmentMismatch { index } => {
                write!(
                    formatter,
                    "value-conservation output note {index} does not match its public commitment"
                )
            }
            Self::ValueConservationInputOverflow => {
                formatter.write_str("value-conservation input sum overflows u128")
            }
            Self::ValueConservationOutputOverflow => {
                formatter.write_str("value-conservation output sum overflows u128")
            }
            Self::ValueConservationMismatch => {
                formatter.write_str("value-conservation input and output sums differ")
            }
            Self::OwnershipNoteCommitmentMismatch => formatter
                .write_str("ownership note does not match its supplied research commitment"),
            Self::VerificationFailed => {
                formatter.write_str("Plonky3 rejected the research STARK proof")
            }
            Self::ProverThreadFailed => {
                formatter.write_str("the dedicated depth-32 STARK prover thread could not complete")
            }
        }
    }
}

impl std::error::Error for StarkExperimentError {}

fn prove_and_verify_with_large_stack(
    air: Poseidon2P24Hash16Air,
    trace: RowMajorMatrix<Val>,
    public_values: [Val; P24_HASH16_DIGEST_ELEMENTS],
) -> Result<(), StarkExperimentError> {
    let prover = std::thread::Builder::new()
        .name("noxis-p24-path32-prover".to_owned())
        .stack_size(P24_MERKLE_PATH32_PROVER_STACK_BYTES)
        .spawn(move || {
            let config = make_high_degree_hiding_config();
            let proof = prove(&config, &air, trace, &public_values);
            verify(&config, &air, &proof, &public_values)
                .map_err(|_| StarkExperimentError::VerificationFailed)
        })
        .map_err(|_| StarkExperimentError::ProverThreadFailed)?;
    prover
        .join()
        .map_err(|_| StarkExperimentError::ProverThreadFailed)?
}

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

fn build_p24_hash16_trace(air: &Poseidon2P24Hash16Air, input: &[u32]) -> RowMajorMatrix<Val> {
    debug_assert_eq!(input.len(), air.shape.input_elements());
    let mut values = Val::zero_vec(air.shape.trace_rows() * air.shape.trace_width());
    let mut raw_state = [Val::ZERO; P24_WIDTH];
    for (lane, value) in input.iter().copied().take(15).enumerate() {
        raw_state[lane] = Val::from_u32(value);
    }
    for (lane, value) in air.iv.into_iter().enumerate() {
        raw_state[15 + lane] = Val::from_u32(value);
    }
    let mut state = matrix_values(&air.permutation.external_matrix, &raw_state);

    for row in 0..air.shape.trace_rows() {
        let offset = row * air.shape.trace_width();
        values[offset..offset + P24_WIDTH].copy_from_slice(&state);
        if row < air.shape.steps() {
            values[offset + P24_SELECTOR_OFFSET + row] = Val::ONE;
            let phase = row / P24_ROUNDS;
            let round = row % P24_ROUNDS;
            state = round_values(&air.permutation, state, round);
            if round + 1 == P24_ROUNDS && phase + 1 < air.shape.permutations() {
                let input_start = (phase + 1) * 15;
                for lane in 0..15 {
                    if input_start + lane < input.len() {
                        state[lane] += Val::from_u32(input[input_start + lane]);
                    }
                }
                state = matrix_values(&air.permutation.external_matrix, &state);
            }
        }
    }
    RowMajorMatrix::new(values, air.shape.trace_width())
}

fn build_p24_merkle_step_trace(
    air: &Poseidon2P24Hash16Air,
    current: BabyBearDigestV2,
    sibling: BabyBearDigestV2,
    current_is_right: bool,
) -> RowMajorMatrix<Val> {
    debug_assert_eq!(air.shape, Poseidon2P24Hash16Shape::MerkleStep);

    let (left, right) = if current_is_right {
        (sibling, current)
    } else {
        (current, sibling)
    };
    let mut input = [0_u32; P24_HASH16_DIGEST_ELEMENTS * 2];
    input[..P24_HASH16_DIGEST_ELEMENTS].copy_from_slice(&left);
    input[P24_HASH16_DIGEST_ELEMENTS..].copy_from_slice(&right);

    let mut trace = build_p24_hash16_trace(air, &input);
    let witness_offset = air
        .shape
        .private_witness_offset()
        .expect("MerkleStep always has private witness columns");
    for row in 0..air.shape.trace_rows() {
        let witness = &mut trace.values[row * air.shape.trace_width() + witness_offset
            ..(row * air.shape.trace_width())
                + witness_offset
                + P24_MERKLE_STEP_PRIVATE_WITNESS_ELEMENTS];
        witness[..P24_HASH16_DIGEST_ELEMENTS].copy_from_slice(&current.map(Val::from_u32));
        witness[P24_HASH16_DIGEST_ELEMENTS..P24_HASH16_DIGEST_ELEMENTS * 2]
            .copy_from_slice(&sibling.map(Val::from_u32));
        witness[P24_MERKLE_STEP_PRIVATE_WITNESS_ELEMENTS - 1] = if current_is_right {
            Val::ONE
        } else {
            Val::ZERO
        };
    }
    trace
}

fn build_p24_merkle_path2_trace(
    air: &Poseidon2P24Hash16Air,
    leaf: BabyBearDigestV2,
    siblings: [BabyBearDigestV2; 2],
    current_is_right: [bool; 2],
    intermediate: BabyBearDigestV2,
) -> RowMajorMatrix<Val> {
    debug_assert_eq!(air.shape, Poseidon2P24Hash16Shape::MerklePath2);

    let inputs = [
        p24_node_input(leaf, siblings[0], current_is_right[0]),
        p24_node_input(intermediate, siblings[1], current_is_right[1]),
    ];
    let mut values = Val::zero_vec(air.shape.trace_rows() * air.shape.trace_width());
    let mut raw_state = [Val::ZERO; P24_WIDTH];
    for (lane, value) in inputs[0].iter().copied().take(15).enumerate() {
        raw_state[lane] = Val::from_u32(value);
    }
    for (lane, value) in air.iv.into_iter().enumerate() {
        raw_state[15 + lane] = Val::from_u32(value);
    }
    let mut state = matrix_values(&air.permutation.external_matrix, &raw_state);
    let witness_offset = air
        .shape
        .private_witness_offset()
        .expect("MerklePath2 always has private witness columns");

    for row in 0..air.shape.trace_rows() {
        let offset = row * air.shape.trace_width();
        values[offset..offset + P24_WIDTH].copy_from_slice(&state);
        let witness = &mut values[offset + witness_offset
            ..offset + witness_offset + P24_MERKLE_PATH2_PRIVATE_WITNESS_ELEMENTS];
        witness[P24_MERKLE_PATH2_LEAF_OFFSET
            ..P24_MERKLE_PATH2_LEAF_OFFSET + P24_HASH16_DIGEST_ELEMENTS]
            .copy_from_slice(&leaf.map(Val::from_u32));
        witness[P24_MERKLE_PATH2_FIRST_SIBLING_OFFSET
            ..P24_MERKLE_PATH2_FIRST_SIBLING_OFFSET + P24_HASH16_DIGEST_ELEMENTS]
            .copy_from_slice(&siblings[0].map(Val::from_u32));
        witness[P24_MERKLE_PATH2_SECOND_SIBLING_OFFSET
            ..P24_MERKLE_PATH2_SECOND_SIBLING_OFFSET + P24_HASH16_DIGEST_ELEMENTS]
            .copy_from_slice(&siblings[1].map(Val::from_u32));
        witness[P24_MERKLE_PATH2_FIRST_DIRECTION_OFFSET] = if current_is_right[0] {
            Val::ONE
        } else {
            Val::ZERO
        };
        witness[P24_MERKLE_PATH2_SECOND_DIRECTION_OFFSET] = if current_is_right[1] {
            Val::ONE
        } else {
            Val::ZERO
        };
        witness[P24_MERKLE_PATH2_INTERMEDIATE_OFFSET
            ..P24_MERKLE_PATH2_INTERMEDIATE_OFFSET + P24_HASH16_DIGEST_ELEMENTS]
            .copy_from_slice(&intermediate.map(Val::from_u32));

        if row < air.shape.steps() {
            values[offset + P24_SELECTOR_OFFSET + row] = Val::ONE;
            let phase = row / P24_ROUNDS;
            let round = row % P24_ROUNDS;
            let hash_index = phase / P24_HASH16_NODE_PERMUTATIONS;
            let phase_in_hash = phase % P24_HASH16_NODE_PERMUTATIONS;
            state = round_values(&air.permutation, state, round);
            if round + 1 == P24_ROUNDS {
                if phase_in_hash + 1 < P24_HASH16_NODE_PERMUTATIONS {
                    let input_start = (phase_in_hash + 1) * 15;
                    for lane in 0..15 {
                        if input_start + lane < inputs[hash_index].len() {
                            state[lane] += Val::from_u32(inputs[hash_index][input_start + lane]);
                        }
                    }
                    state = matrix_values(&air.permutation.external_matrix, &state);
                } else if hash_index == 0 {
                    let mut next_raw = [Val::ZERO; P24_WIDTH];
                    for (lane, value) in inputs[1].iter().copied().take(15).enumerate() {
                        next_raw[lane] = Val::from_u32(value);
                    }
                    for (lane, value) in air.iv.into_iter().enumerate() {
                        next_raw[15 + lane] = Val::from_u32(value);
                    }
                    state = matrix_values(&air.permutation.external_matrix, &next_raw);
                }
            }
        }
    }
    RowMajorMatrix::new(values, air.shape.trace_width())
}

fn build_p24_merkle_path32_trace(
    air: &Poseidon2P24Hash16Air,
    leaf: BabyBearDigestV2,
    siblings: [BabyBearDigestV2; P24_MERKLE_PATH_DEPTH],
    directions: [bool; P24_MERKLE_PATH_DEPTH],
    intermediates: [BabyBearDigestV2; P24_MERKLE_PATH_DEPTH - 1],
) -> RowMajorMatrix<Val> {
    debug_assert_eq!(air.shape, Poseidon2P24Hash16Shape::MerklePath32);

    let mut inputs = Vec::with_capacity(P24_MERKLE_PATH_DEPTH);
    let mut current = leaf;
    for level in 0..P24_MERKLE_PATH_DEPTH {
        inputs.push(p24_node_input(current, siblings[level], directions[level]));
        if level + 1 < P24_MERKLE_PATH_DEPTH {
            current = intermediates[level];
        }
    }

    let mut values = Val::zero_vec(air.shape.trace_rows() * air.shape.trace_width());
    let mut raw_state = [Val::ZERO; P24_WIDTH];
    for (lane, value) in inputs[0].iter().copied().take(15).enumerate() {
        raw_state[lane] = Val::from_u32(value);
    }
    for (lane, value) in air.iv.into_iter().enumerate() {
        raw_state[15 + lane] = Val::from_u32(value);
    }
    let mut state = matrix_values(&air.permutation.external_matrix, &raw_state);
    let witness_offset = air
        .shape
        .private_witness_offset()
        .expect("MerklePath32 always has private witness columns");

    for row in 0..air.shape.trace_rows() {
        let offset = row * air.shape.trace_width();
        values[offset..offset + P24_WIDTH].copy_from_slice(&state);
        let witness = &mut values[offset + witness_offset
            ..offset + witness_offset + P24_MERKLE_PATH32_PRIVATE_WITNESS_ELEMENTS];
        witness[P24_MERKLE_PATH32_LEAF_OFFSET
            ..P24_MERKLE_PATH32_LEAF_OFFSET + P24_HASH16_DIGEST_ELEMENTS]
            .copy_from_slice(&leaf.map(Val::from_u32));
        for (level, sibling) in siblings.iter().enumerate() {
            let start = P24_MERKLE_PATH32_SIBLINGS_OFFSET + (level * P24_HASH16_DIGEST_ELEMENTS);
            witness[start..start + P24_HASH16_DIGEST_ELEMENTS]
                .copy_from_slice(&sibling.map(Val::from_u32));
            witness[P24_MERKLE_PATH32_DIRECTIONS_OFFSET + level] = if directions[level] {
                Val::ONE
            } else {
                Val::ZERO
            };
        }
        for (level, intermediate) in intermediates.iter().enumerate() {
            let start =
                P24_MERKLE_PATH32_INTERMEDIATES_OFFSET + (level * P24_HASH16_DIGEST_ELEMENTS);
            witness[start..start + P24_HASH16_DIGEST_ELEMENTS]
                .copy_from_slice(&intermediate.map(Val::from_u32));
        }

        if row < P24_MERKLE_PATH32_STEPS {
            let phase = row / P24_ROUNDS;
            let round = row % P24_ROUNDS;
            values[offset + P24_SELECTOR_OFFSET + round] = Val::ONE;
            values[offset + P24_MERKLE_PATH32_PHASE_OFFSET + phase] = Val::ONE;
            let hash_index = phase / P24_HASH16_NODE_PERMUTATIONS;
            let phase_in_hash = phase % P24_HASH16_NODE_PERMUTATIONS;
            state = round_values(&air.permutation, state, round);
            if round + 1 == P24_ROUNDS {
                if phase_in_hash + 1 < P24_HASH16_NODE_PERMUTATIONS {
                    let input_start = (phase_in_hash + 1) * 15;
                    for lane in 0..15 {
                        if input_start + lane < inputs[hash_index].len() {
                            state[lane] += Val::from_u32(inputs[hash_index][input_start + lane]);
                        }
                    }
                    state = matrix_values(&air.permutation.external_matrix, &state);
                } else if hash_index + 1 < P24_MERKLE_PATH_DEPTH {
                    let mut next_raw = [Val::ZERO; P24_WIDTH];
                    for (lane, value) in inputs[hash_index + 1].iter().copied().take(15).enumerate()
                    {
                        next_raw[lane] = Val::from_u32(value);
                    }
                    for (lane, value) in air.iv.into_iter().enumerate() {
                        next_raw[15 + lane] = Val::from_u32(value);
                    }
                    state = matrix_values(&air.permutation.external_matrix, &next_raw);
                }
            }
        } else {
            values[offset + P24_SELECTOR_OFFSET + P24_ROUNDS - 1] = Val::ONE;
            values
                [offset + P24_MERKLE_PATH32_PHASE_OFFSET + P24_MERKLE_PATH32_PHASE_SELECTORS - 1] =
                Val::ONE;
            values[offset + P24_MERKLE_PATH32_DONE_OFFSET] = Val::ONE;
        }
    }
    RowMajorMatrix::new(values, air.shape.trace_width())
}

fn p24_node_input(
    current: BabyBearDigestV2,
    sibling: BabyBearDigestV2,
    current_is_right: bool,
) -> [u32; P24_HASH16_DIGEST_ELEMENTS * 2] {
    let (left, right) = if current_is_right {
        (sibling, current)
    } else {
        (current, sibling)
    };
    let mut input = [0_u32; P24_HASH16_DIGEST_ELEMENTS * 2];
    input[..P24_HASH16_DIGEST_ELEMENTS].copy_from_slice(&left);
    input[P24_HASH16_DIGEST_ELEMENTS..].copy_from_slice(&right);
    input
}

pub(crate) fn round_values(
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

pub(crate) fn matrix_values(
    matrix: &[[u32; P24_WIDTH]; P24_WIDTH],
    values: &[Val; P24_WIDTH],
) -> [Val; P24_WIDTH] {
    core::array::from_fn(|row| {
        (0..P24_WIDTH).fold(Val::ZERO, |sum, column| {
            sum + values[column] * Val::from_u32(matrix[row][column])
        })
    })
}

pub(crate) fn is_full_round(round: usize) -> bool {
    !(4..P24_ROUNDS - 4).contains(&round)
}

fn seventh_power<AB: AirBuilder>(value: AB::Expr) -> AB::Expr {
    let square = value.clone() * value.clone();
    let fourth = square.clone() * square.clone();
    fourth * square * value
}

pub(crate) fn matrix_expression<AB: AirBuilder>(
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

pub(crate) fn make_hiding_config() -> Config {
    make_hiding_config_for_profile(ResearchStarkVerifierProfileV1::STANDARD_P24)
}

pub(crate) fn make_high_degree_hiding_config() -> Config {
    make_hiding_config_for_profile(ResearchStarkVerifierProfileV1::HIGH_DEGREE_P24)
}

fn make_hiding_config_for_profile(profile: ResearchStarkVerifierProfileV1) -> Config {
    let byte_hash = ByteHash {};
    let u64_hash = U64Hash::new(KeccakF {});
    let field_hash = FieldHash::new(u64_hash);
    let compress = Compress::new(u64_hash);
    let val_mmcs = ValHidingMmcs::new(field_hash, compress, 0, secure_rng());
    let challenge_mmcs = ChallengeHidingMmcs::new(val_mmcs.clone());
    let fri_params = FriParameters {
        log_blowup: profile.fri_log_blowup(),
        log_final_poly_len: profile.fri_log_final_poly_len(),
        max_log_arity: profile.fri_max_log_arity(),
        num_queries: profile.fri_num_queries(),
        commit_proof_of_work_bits: profile.fri_commit_proof_of_work_bits(),
        query_proof_of_work_bits: profile.fri_query_proof_of_work_bits(),
        mmcs: challenge_mmcs,
    };
    let pcs = HidingPcs::new(
        Radix2DitParallel::default(),
        val_mmcs,
        fri_params,
        profile.num_random_codewords(),
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
    fn high_degree_profile_constructs_and_verifies_a_p24_proof() {
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
        let config = make_high_degree_hiding_config();
        let proof = prove(&config, &air, trace, &public_values);

        verify(&config, &air, &proof, &public_values)
            .expect("the explicit high-degree profile should verify a P24 proof");
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
    fn p24_research_proof_round_trips_to_a_fresh_local_verifier_config() {
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
        let encoded = postcard::to_allocvec(&proof)
            .expect("the experimental Plonky3 proof should serialize for this local test");
        let decoded = postcard::from_bytes(&encoded)
            .expect("the locally serialized experimental proof should deserialize");

        let verifier_config = make_hiding_config();
        verify(&verifier_config, &air, &decoded, &public_values).expect(
            "a proof decoded under a fresh configuration with the same profile should verify",
        );
    }

    #[test]
    fn p24_research_proof_verifies_in_a_child_process() {
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
        let encoded = postcard::to_allocvec(&proof)
            .expect("the experimental Plonky3 proof should serialize for this local test");
        let path = std::env::temp_dir().join(format!(
            "noxis-stark-research-proof-{}-{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("the system clock should be after the Unix epoch")
                .as_nanos()
        ));
        std::fs::write(&path, encoded).expect("the child-process test proof should be writable");

        let child = std::process::Command::new(
            std::env::current_exe().expect("the current test executable should be discoverable"),
        )
        .arg("--exact")
        .arg("tests::p24_research_proof_child_process_verifier")
        .arg("--nocapture")
        .env("NOXIS_STARK_RESEARCH_PROOF_PATH", &path)
        .output()
        .expect("the child-process verifier should start");
        let _ = std::fs::remove_file(&path);

        assert!(
            child.status.success(),
            "the child-process verifier failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        );
    }

    #[test]
    fn p24_research_proof_child_process_verifier() {
        let Ok(path) = std::env::var("NOXIS_STARK_RESEARCH_PROOF_PATH") else {
            return;
        };
        let encoded = std::fs::read(path).expect("the parent test should provide proof bytes");
        let decoded = postcard::from_bytes(&encoded)
            .expect("the child process should deserialize the supplied proof bytes");
        let input = core::array::from_fn(|index| index as u32 + 1);
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        let output = reference.permutation(input).unwrap();
        let air = Poseidon2P24Air::from_reference(&reference);
        let public_values = input
            .into_iter()
            .chain(output)
            .map(Val::from_u32)
            .collect::<Vec<_>>();
        let verifier_config = make_hiding_config();

        verify(&verifier_config, &air, &decoded, &public_values).expect(
            "the child process should verify the supplied proof with a fresh configuration",
        );
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
        let air = Poseidon2P24Hash16Air::from_reference(&reference, Poseidon2P24Hash16Shape::Leaf)
            .unwrap();
        let trace = build_p24_hash16_trace(&air, &commitment);
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

    #[test]
    fn node_hash_stark_matches_the_frozen_candidate_reference() {
        let left = core::array::from_fn(|index| index as u32 + 1);
        let right = core::array::from_fn(|index| index as u32 + 17);
        let result = prove_and_verify_p24_node(left, right).unwrap();
        let reference = Poseidon2P24Reference::load_candidate().unwrap();

        assert_eq!(result.parent, reference.node(left, right).unwrap());
        assert_eq!(result.trace_rows, P24_HASH16_NODE_TRACE_ROWS);
    }

    #[test]
    fn node_hash_proof_rejects_a_changed_public_parent_or_child_order() {
        let left = core::array::from_fn(|index| index as u32 + 1);
        let right = core::array::from_fn(|index| index as u32 + 17);
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        let parent = reference.node(left, right).unwrap();
        let air = Poseidon2P24Hash16Air::from_reference(&reference, Poseidon2P24Hash16Shape::Node)
            .unwrap();
        let input = left.into_iter().chain(right).collect::<Vec<_>>();
        let trace = build_p24_hash16_trace(&air, &input);
        let public_values = input
            .iter()
            .copied()
            .chain(parent)
            .map(Val::from_u32)
            .collect::<Vec<_>>();
        p3_air::check_constraints(&air, &trace, &public_values);

        let mut changed_parent = public_values.clone();
        changed_parent[32] += Val::ONE;

        let mut reversed_children = public_values.clone();
        let original_right = reversed_children[16..32].to_vec();
        reversed_children[..16].copy_from_slice(&original_right);
        reversed_children[16..32].copy_from_slice(&left.map(Val::from_u32));

        // These direct checks exercise the AIR boundary constraints rather than
        // merely relying on Fiat-Shamir binding during proof verification.
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                p3_air::check_constraints(&air, &trace, &changed_parent);
            }))
            .is_err()
        );
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                p3_air::check_constraints(&air, &trace, &reversed_children);
            }))
            .is_err()
        );

        let config = make_hiding_config();
        let proof = prove(&config, &air, trace, &public_values);
        assert!(verify(&config, &air, &proof, &changed_parent).is_err());
        assert!(verify(&config, &air, &proof, &reversed_children).is_err());
    }

    #[test]
    fn private_merkle_step_stark_matches_both_candidate_child_orders() {
        let current = core::array::from_fn(|index| index as u32 + 1);
        let sibling = core::array::from_fn(|index| index as u32 + 17);
        let reference = Poseidon2P24Reference::load_candidate().unwrap();

        let current_left = prove_and_verify_p24_merkle_step(current, sibling, false).unwrap();
        let current_right = prove_and_verify_p24_merkle_step(current, sibling, true).unwrap();

        assert_eq!(
            current_left.parent,
            reference.node(current, sibling).unwrap()
        );
        assert_eq!(
            current_right.parent,
            reference.node(sibling, current).unwrap()
        );
        assert_ne!(current_left.parent, current_right.parent);
        assert_eq!(current_left.trace_rows, P24_HASH16_NODE_TRACE_ROWS);
    }

    #[test]
    fn private_merkle_step_air_rejects_a_changed_parent_or_invalid_direction() {
        let current = core::array::from_fn(|index| index as u32 + 1);
        let sibling = core::array::from_fn(|index| index as u32 + 17);
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        let parent = reference.node(current, sibling).unwrap();
        let air =
            Poseidon2P24Hash16Air::from_reference(&reference, Poseidon2P24Hash16Shape::MerkleStep)
                .unwrap();
        let trace = build_p24_merkle_step_trace(&air, current, sibling, false);
        let public_values = parent.map(Val::from_u32);
        p3_air::check_constraints(&air, &trace, &public_values);

        let mut changed_parent = public_values;
        changed_parent[0] += Val::ONE;
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                p3_air::check_constraints(&air, &trace, &changed_parent);
            }))
            .is_err()
        );

        let mut non_boolean_direction = trace.clone();
        let direction_offset =
            P24_HASH16_NODE_TRACE_WIDTH + P24_MERKLE_STEP_PRIVATE_WITNESS_ELEMENTS - 1;
        for row in 0..P24_HASH16_NODE_TRACE_ROWS {
            non_boolean_direction.values[row * P24_MERKLE_STEP_TRACE_WIDTH + direction_offset] =
                Val::from_u32(2);
        }
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                p3_air::check_constraints(&air, &non_boolean_direction, &public_values);
            }))
            .is_err()
        );

        let mut reversed_direction = trace.clone();
        for row in 0..P24_HASH16_NODE_TRACE_ROWS {
            reversed_direction.values[row * P24_MERKLE_STEP_TRACE_WIDTH + direction_offset] =
                Val::ONE;
        }
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                p3_air::check_constraints(&air, &reversed_direction, &public_values);
            }))
            .is_err()
        );

        let mut changed_sibling = trace.clone();
        let sibling_offset = P24_HASH16_NODE_TRACE_WIDTH + P24_HASH16_DIGEST_ELEMENTS;
        for row in 0..P24_HASH16_NODE_TRACE_ROWS {
            changed_sibling.values[row * P24_MERKLE_STEP_TRACE_WIDTH + sibling_offset] += Val::ONE;
        }
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                p3_air::check_constraints(&air, &changed_sibling, &public_values);
            }))
            .is_err()
        );

        let mut changed_direction = trace;
        changed_direction.values[P24_MERKLE_STEP_TRACE_WIDTH + direction_offset] = Val::ONE;
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                p3_air::check_constraints(&air, &changed_direction, &public_values);
            }))
            .is_err()
        );
    }

    #[test]
    fn private_merkle_path2_stark_binds_two_ordered_hashes_to_one_public_root() {
        let leaf = core::array::from_fn(|index| index as u32 + 1);
        let siblings = [
            core::array::from_fn(|index| index as u32 + 17),
            core::array::from_fn(|index| index as u32 + 33),
        ];
        let directions = [true, false];
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        let intermediate = candidate_node(&reference, leaf, siblings[0], directions[0]).unwrap();
        let root = candidate_node(&reference, intermediate, siblings[1], directions[1]).unwrap();

        let result = prove_and_verify_p24_merkle_path2(leaf, siblings, directions).unwrap();

        assert_eq!(result.root, root);
        assert_eq!(result.trace_rows, P24_MERKLE_PATH2_TRACE_ROWS);
    }

    #[test]
    fn private_merkle_path2_stark_matches_the_first_two_levels_of_external_paths() {
        let corpus = P24TreeVectorCorpusV2::frozen_complete_candidate_corpus();
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        let paths = corpus
            .records()
            .iter()
            .filter_map(|record| match record {
                P24TreeVectorRecordV2::Path {
                    leaf_index,
                    leaf,
                    siblings,
                    ..
                } => Some((
                    *leaf_index,
                    elements(*leaf),
                    elements(siblings[0]),
                    elements(siblings[1]),
                )),
                _ => None,
            })
            .collect::<Vec<_>>();

        assert_eq!(
            paths.len(),
            4,
            "complete P24 corpus fixes four path orientations"
        );
        for (leaf_index, leaf, first_sibling, second_sibling) in paths {
            let directions = [(leaf_index & 1) != 0, (leaf_index & 2) != 0];
            let intermediate =
                candidate_node(&reference, leaf, first_sibling, directions[0]).unwrap();
            let expected_root =
                candidate_node(&reference, intermediate, second_sibling, directions[1]).unwrap();

            assert_eq!(
                prove_and_verify_p24_merkle_path2(
                    leaf,
                    [first_sibling, second_sibling],
                    directions,
                )
                .unwrap()
                .root,
                expected_root
            );
        }
    }

    #[test]
    fn private_merkle_path2_air_rejects_a_changed_root_or_intermediate_link() {
        let leaf = core::array::from_fn(|index| index as u32 + 1);
        let siblings = [
            core::array::from_fn(|index| index as u32 + 17),
            core::array::from_fn(|index| index as u32 + 33),
        ];
        let directions = [true, false];
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        let intermediate = candidate_node(&reference, leaf, siblings[0], directions[0]).unwrap();
        let root = candidate_node(&reference, intermediate, siblings[1], directions[1]).unwrap();
        let air =
            Poseidon2P24Hash16Air::from_reference(&reference, Poseidon2P24Hash16Shape::MerklePath2)
                .unwrap();
        let trace = build_p24_merkle_path2_trace(&air, leaf, siblings, directions, intermediate);
        let public_values = root.map(Val::from_u32);
        p3_air::check_constraints(&air, &trace, &public_values);

        let mut changed_root = public_values;
        changed_root[0] += Val::ONE;
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                p3_air::check_constraints(&air, &trace, &changed_root);
            }))
            .is_err()
        );

        let mut changed_intermediate = trace.clone();
        let witness_offset = P24_SELECTOR_OFFSET + P24_MERKLE_PATH2_STEPS;
        for row in 0..P24_MERKLE_PATH2_TRACE_ROWS {
            changed_intermediate.values[row * P24_MERKLE_PATH2_TRACE_WIDTH
                + witness_offset
                + P24_MERKLE_PATH2_INTERMEDIATE_OFFSET] += Val::ONE;
        }
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                p3_air::check_constraints(&air, &changed_intermediate, &public_values);
            }))
            .is_err()
        );

        let mut reversed_first_direction = trace.clone();
        for row in 0..P24_MERKLE_PATH2_TRACE_ROWS {
            reversed_first_direction.values[row * P24_MERKLE_PATH2_TRACE_WIDTH
                + witness_offset
                + P24_MERKLE_PATH2_FIRST_DIRECTION_OFFSET] = Val::ZERO;
        }
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                p3_air::check_constraints(&air, &reversed_first_direction, &public_values);
            }))
            .is_err()
        );

        let mut non_boolean_second_direction = trace.clone();
        for row in 0..P24_MERKLE_PATH2_TRACE_ROWS {
            non_boolean_second_direction.values[row * P24_MERKLE_PATH2_TRACE_WIDTH
                + witness_offset
                + P24_MERKLE_PATH2_SECOND_DIRECTION_OFFSET] = Val::from_u32(2);
        }
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                p3_air::check_constraints(&air, &non_boolean_second_direction, &public_values);
            }))
            .is_err()
        );

        let mut reversed_second_direction = trace;
        for row in 0..P24_MERKLE_PATH2_TRACE_ROWS {
            reversed_second_direction.values[row * P24_MERKLE_PATH2_TRACE_WIDTH
                + witness_offset
                + P24_MERKLE_PATH2_SECOND_DIRECTION_OFFSET] = Val::ONE;
        }
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                p3_air::check_constraints(&air, &reversed_second_direction, &public_values);
            }))
            .is_err()
        );
    }

    #[test]
    fn private_merkle_path32_air_accepts_a_complete_external_path_trace() {
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        let commitments = [
            core::array::from_fn(|index| index as u32 + 1),
            core::array::from_fn(|index| index as u32 + 17),
            core::array::from_fn(|index| index as u32 + 33),
        ];
        let (leaf, siblings, root) = reference.small_tree_path(&commitments, 2).unwrap();
        let directions = core::array::from_fn(|level| ((2_u32 >> level) & 1) == 1);
        let mut current = leaf;
        let mut intermediates = [[0_u32; P24_HASH16_DIGEST_ELEMENTS]; P24_MERKLE_PATH_DEPTH - 1];
        for level in 0..P24_MERKLE_PATH_DEPTH {
            current =
                candidate_node(&reference, current, siblings[level], directions[level]).unwrap();
            if level + 1 < P24_MERKLE_PATH_DEPTH {
                intermediates[level] = current;
            }
        }
        assert_eq!(current, root);
        let air = Poseidon2P24Hash16Air::from_reference(
            &reference,
            Poseidon2P24Hash16Shape::MerklePath32,
        )
        .unwrap();
        let trace = build_p24_merkle_path32_trace(&air, leaf, siblings, directions, intermediates);

        p3_air::check_constraints(&air, &trace, &root.map(Val::from_u32));
    }

    #[test]
    fn node_hash_stark_matches_ordered_external_node_vectors() {
        let corpus = P24TreeVectorCorpusV2::frozen_complete_candidate_corpus();
        let nodes = corpus
            .records()
            .iter()
            .filter_map(|record| match record {
                P24TreeVectorRecordV2::Node {
                    left,
                    right,
                    parent,
                } => Some((elements(*left), elements(*right), elements(*parent))),
                _ => None,
            })
            .collect::<Vec<_>>();

        assert_eq!(nodes.len(), 2, "complete corpus fixes both node orders");
        assert_eq!(nodes[0].0, nodes[1].1);
        assert_eq!(nodes[0].1, nodes[1].0);
        assert_ne!(nodes[0].2, nodes[1].2);
        for (left, right, parent) in nodes {
            assert_eq!(
                prove_and_verify_p24_node(left, right).unwrap().parent,
                parent
            );
        }
    }
}
