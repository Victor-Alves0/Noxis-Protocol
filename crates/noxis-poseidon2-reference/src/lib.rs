//! Auditable, deliberately unoptimized Poseidon2-BabyBear-P24 reference.
//!
//! This crate is isolated from the ledger, Merkle state and consensus. It is
//! an independent, dense-matrix reading of the frozen candidate artifact so
//! that future optimized/AIR implementations have a small correctness oracle.

use std::fmt;

use noxis_tree_params::{
    CandidatePoseidon2P24ManifestV2, Poseidon2P24CandidateError, Poseidon2P24TreeDomainV1,
};

/// Width of the frozen Poseidon2-BabyBear candidate state.
pub const P24_WIDTH: usize = 24;
/// Number of full rounds in the candidate permutation.
pub const P24_FULL_ROUNDS: usize = 8;
/// Number of partial rounds in the candidate permutation.
pub const P24_PARTIAL_ROUNDS: usize = 21;
/// Prime modulus of the BabyBear field.
pub const BABYBEAR_MODULUS: u32 = 2_013_265_921;
/// Number of state elements exposed by each fixed tree digest.
pub const P24_TREE_DIGEST_ELEMENTS: usize = 16;

const P24_HALF_FULL_ROUNDS: usize = P24_FULL_ROUNDS / 2;
const P24_TOTAL_ROUNDS: usize = P24_FULL_ROUNDS + P24_PARTIAL_ROUNDS;
const P24_DIAGONAL_OFFSET: usize = 0;
const P24_EXTERNAL_OFFSET: usize = P24_DIAGONAL_OFFSET + P24_WIDTH;
const P24_INTERNAL_OFFSET: usize = P24_EXTERNAL_OFFSET + (P24_WIDTH * P24_WIDTH);
const P24_ROUND_CONSTANT_OFFSET: usize = P24_INTERNAL_OFFSET + (P24_WIDTH * P24_WIDTH);

/// A fixed-width semantic state of canonical BabyBear elements.
pub type BabyBearStateP24 = [u32; P24_WIDTH];
/// A canonical 16-element public Noxis v2 tree value.
pub type BabyBearDigestV2 = [u32; P24_TREE_DIGEST_ELEMENTS];

/// Dense reference evaluator for the frozen P24 candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Poseidon2P24Reference {
    external_matrix: [[u32; P24_WIDTH]; P24_WIDTH],
    internal_matrix: [[u32; P24_WIDTH]; P24_WIDTH],
    round_constants: [[u32; P24_WIDTH]; P24_TOTAL_ROUNDS],
}

impl Poseidon2P24Reference {
    /// Loads only the currently frozen, unselected P24 candidate artifact.
    pub fn load_candidate() -> Result<Self, Poseidon2P24ReferenceError> {
        let payload = CandidatePoseidon2P24ManifestV2::new().parameter_payload()?;
        let values = decode_elements(&payload)?;
        let diagonal = values[P24_DIAGONAL_OFFSET..P24_EXTERNAL_OFFSET]
            .try_into()
            .expect("fixed P24 diagonal bounds");
        let external_matrix = matrix_from(&values[P24_EXTERNAL_OFFSET..P24_INTERNAL_OFFSET]);
        let internal_matrix = matrix_from(&values[P24_INTERNAL_OFFSET..P24_ROUND_CONSTANT_OFFSET]);
        let round_constants = matrix_from(
            &values[P24_ROUND_CONSTANT_OFFSET
                ..P24_ROUND_CONSTANT_OFFSET + (P24_TOTAL_ROUNDS * P24_WIDTH)],
        );
        validate_internal_matrix(&diagonal, &internal_matrix)?;
        Ok(Self {
            external_matrix,
            internal_matrix,
            round_constants,
        })
    }

    /// Applies the candidate permutation to one complete canonical state.
    pub fn permutation(
        &self,
        input: BabyBearStateP24,
    ) -> Result<BabyBearStateP24, Poseidon2P24ReferenceError> {
        validate_state(&input)?;
        let mut state = matmul(&self.external_matrix, &input);

        for round in 0..P24_HALF_FULL_ROUNDS {
            add_round_constants(&mut state, &self.round_constants[round]);
            apply_sbox_to_all(&mut state);
            state = matmul(&self.external_matrix, &state);
        }

        for round in P24_HALF_FULL_ROUNDS..(P24_HALF_FULL_ROUNDS + P24_PARTIAL_ROUNDS) {
            state[0] = add(state[0], self.round_constants[round][0]);
            state[0] = sbox_seven(state[0]);
            state = matmul(&self.internal_matrix, &state);
        }

        for round in (P24_HALF_FULL_ROUNDS + P24_PARTIAL_ROUNDS)..P24_TOTAL_ROUNDS {
            add_round_constants(&mut state, &self.round_constants[round]);
            apply_sbox_to_all(&mut state);
            state = matmul(&self.external_matrix, &state);
        }
        Ok(state)
    }

    /// Applies the fixed-arity candidate `Hash16` construction.
    ///
    /// This supports only the three documented tree roles. It is not a
    /// general variable-length hash API and remains a reference evaluator,
    /// not a selected ledger primitive.
    pub fn hash16(
        &self,
        domain: Poseidon2P24TreeDomainV1,
        input: &[u32],
    ) -> Result<BabyBearDigestV2, Poseidon2P24ReferenceError> {
        let expected = match domain {
            Poseidon2P24TreeDomainV1::Leaf => P24_TREE_DIGEST_ELEMENTS,
            Poseidon2P24TreeDomainV1::Node => P24_TREE_DIGEST_ELEMENTS * 2,
            Poseidon2P24TreeDomainV1::EmptyBase => 0,
        };
        if input.len() != expected {
            return Err(Poseidon2P24ReferenceError::InvalidDomainArity {
                domain,
                actual: input.len(),
                expected,
            });
        }
        for (index, value) in input.iter().copied().enumerate() {
            if value >= BABYBEAR_MODULUS {
                return Err(Poseidon2P24ReferenceError::NonCanonicalHashInput { index, value });
            }
        }

        let iv = CandidatePoseidon2P24ManifestV2::new().iv(domain)?;
        let mut state = [0_u32; P24_WIDTH];
        state[15..].copy_from_slice(&iv);
        if input.is_empty() {
            state = self.permutation(state)?;
        } else {
            for block in input.chunks(15) {
                for (lane, value) in state[..15].iter_mut().zip(block) {
                    *lane = add(*lane, *value);
                }
                state = self.permutation(state)?;
            }
        }

        let mut output = [0_u32; P24_TREE_DIGEST_ELEMENTS];
        output[..15].copy_from_slice(&state[..15]);
        state = self.permutation(state)?;
        output[15] = state[0];
        Ok(output)
    }

    /// Computes the candidate leaf transformation for one canonical note value.
    pub fn leaf(
        &self,
        note: BabyBearDigestV2,
    ) -> Result<BabyBearDigestV2, Poseidon2P24ReferenceError> {
        self.hash16(Poseidon2P24TreeDomainV1::Leaf, &note)
    }

    /// Computes the ordered candidate parent transformation.
    pub fn node(
        &self,
        left: BabyBearDigestV2,
        right: BabyBearDigestV2,
    ) -> Result<BabyBearDigestV2, Poseidon2P24ReferenceError> {
        let mut input = [0_u32; P24_TREE_DIGEST_ELEMENTS * 2];
        input[..P24_TREE_DIGEST_ELEMENTS].copy_from_slice(&left);
        input[P24_TREE_DIGEST_ELEMENTS..].copy_from_slice(&right);
        self.hash16(Poseidon2P24TreeDomainV1::Node, &input)
    }

    /// Derives all empty values from level zero through the depth-32 root.
    pub fn empty_values(&self) -> Result<[BabyBearDigestV2; 33], Poseidon2P24ReferenceError> {
        let mut empty = [[0_u32; P24_TREE_DIGEST_ELEMENTS]; 33];
        empty[0] = self.hash16(Poseidon2P24TreeDomainV1::EmptyBase, &[])?;
        let mut previous = empty[0];
        for next in &mut empty[1..] {
            *next = self.node(previous, previous)?;
            previous = *next;
        }
        Ok(empty)
    }

    /// Computes the depth-32 root for zero to four notes appended from index 0.
    pub fn small_tree_root(
        &self,
        notes: &[BabyBearDigestV2],
    ) -> Result<BabyBearDigestV2, Poseidon2P24ReferenceError> {
        const MAX_SMALL_TREE_NOTES: usize = 4;
        if notes.len() > MAX_SMALL_TREE_NOTES {
            return Err(Poseidon2P24ReferenceError::TooManySmallTreeNotes {
                actual: notes.len(),
                limit: MAX_SMALL_TREE_NOTES,
            });
        }
        let empty = self.empty_values()?;
        if notes.is_empty() {
            return Ok(empty[32]);
        }
        let mut nodes = Vec::with_capacity(notes.len());
        for note in notes {
            nodes.push(self.leaf(*note)?);
        }
        for empty_value in empty.iter().take(32).copied() {
            if nodes.len() % 2 == 1 {
                nodes.push(empty_value);
            }
            let mut parents = Vec::with_capacity(nodes.len() / 2);
            for pair in nodes.chunks_exact(2) {
                parents.push(self.node(pair[0], pair[1])?);
            }
            nodes = parents;
        }
        Ok(nodes[0])
    }
}

fn decode_elements(payload: &[u8]) -> Result<Vec<u32>, Poseidon2P24ReferenceError> {
    if payload.len() % 4 != 0 {
        return Err(Poseidon2P24ReferenceError::InvalidPayloadLength(
            payload.len(),
        ));
    }
    let mut values = Vec::with_capacity(payload.len() / 4);
    for (index, bytes) in payload.chunks_exact(4).enumerate() {
        let value = u32::from_le_bytes(bytes.try_into().expect("chunks are exactly four bytes"));
        if value >= BABYBEAR_MODULUS {
            return Err(Poseidon2P24ReferenceError::NonCanonicalParameter { index, value });
        }
        values.push(value);
    }
    Ok(values)
}

fn matrix_from<const ROWS: usize>(values: &[u32]) -> [[u32; P24_WIDTH]; ROWS] {
    let mut matrix = [[0_u32; P24_WIDTH]; ROWS];
    for (row, matrix_row) in matrix.iter_mut().enumerate() {
        matrix_row.copy_from_slice(&values[row * P24_WIDTH..(row + 1) * P24_WIDTH]);
    }
    matrix
}

fn validate_internal_matrix(
    diagonal: &[u32; P24_WIDTH],
    matrix: &[[u32; P24_WIDTH]; P24_WIDTH],
) -> Result<(), Poseidon2P24ReferenceError> {
    for (row, matrix_row) in matrix.iter().enumerate() {
        for (column, value) in matrix_row.iter().copied().enumerate() {
            let expected = if row == column {
                add(diagonal[row], 1)
            } else {
                1
            };
            if value != expected {
                return Err(Poseidon2P24ReferenceError::InvalidInternalMatrix { row, column });
            }
        }
    }
    Ok(())
}

fn validate_state(state: &BabyBearStateP24) -> Result<(), Poseidon2P24ReferenceError> {
    for (index, value) in state.iter().copied().enumerate() {
        if value >= BABYBEAR_MODULUS {
            return Err(Poseidon2P24ReferenceError::NonCanonicalInput { index, value });
        }
    }
    Ok(())
}

fn add(left: u32, right: u32) -> u32 {
    ((u64::from(left) + u64::from(right)) % u64::from(BABYBEAR_MODULUS)) as u32
}

fn multiply(left: u32, right: u32) -> u32 {
    ((u64::from(left) * u64::from(right)) % u64::from(BABYBEAR_MODULUS)) as u32
}

fn matmul(matrix: &[[u32; P24_WIDTH]; P24_WIDTH], state: &BabyBearStateP24) -> BabyBearStateP24 {
    let mut output = [0_u32; P24_WIDTH];
    for (row, result) in output.iter_mut().enumerate() {
        let mut accumulated = 0_u32;
        for column in 0..P24_WIDTH {
            accumulated = add(accumulated, multiply(matrix[row][column], state[column]));
        }
        *result = accumulated;
    }
    output
}

fn add_round_constants(state: &mut BabyBearStateP24, constants: &BabyBearStateP24) {
    for (value, constant) in state.iter_mut().zip(constants) {
        *value = add(*value, *constant);
    }
}

fn apply_sbox_to_all(state: &mut BabyBearStateP24) {
    for value in state {
        *value = sbox_seven(*value);
    }
}

fn sbox_seven(value: u32) -> u32 {
    let square = multiply(value, value);
    let fourth = multiply(square, square);
    multiply(multiply(fourth, square), value)
}

/// Errors produced while loading or evaluating the reference candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Poseidon2P24ReferenceError {
    Candidate(Poseidon2P24CandidateError),
    InvalidPayloadLength(usize),
    NonCanonicalParameter {
        index: usize,
        value: u32,
    },
    InvalidInternalMatrix {
        row: usize,
        column: usize,
    },
    NonCanonicalInput {
        index: usize,
        value: u32,
    },
    InvalidDomainArity {
        domain: Poseidon2P24TreeDomainV1,
        actual: usize,
        expected: usize,
    },
    NonCanonicalHashInput {
        index: usize,
        value: u32,
    },
    TooManySmallTreeNotes {
        actual: usize,
        limit: usize,
    },
}

impl From<Poseidon2P24CandidateError> for Poseidon2P24ReferenceError {
    fn from(value: Poseidon2P24CandidateError) -> Self {
        Self::Candidate(value)
    }
}

impl fmt::Display for Poseidon2P24ReferenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Candidate(error) => write!(formatter, "invalid frozen P24 candidate: {error}"),
            Self::InvalidPayloadLength(length) => {
                write!(formatter, "P24 payload has invalid length {length}")
            }
            Self::NonCanonicalParameter { index, value } => {
                write!(formatter, "P24 parameter {index} is non-canonical: {value}")
            }
            Self::InvalidInternalMatrix { row, column } => write!(
                formatter,
                "P24 internal matrix differs at row {row}, column {column}"
            ),
            Self::NonCanonicalInput { index, value } => {
                write!(formatter, "P24 input {index} is non-canonical: {value}")
            }
            Self::InvalidDomainArity {
                domain,
                actual,
                expected,
            } => write!(
                formatter,
                "P24 {domain:?} input has arity {actual}, expected {expected}"
            ),
            Self::NonCanonicalHashInput { index, value } => {
                write!(
                    formatter,
                    "P24 Hash16 input {index} is non-canonical: {value}"
                )
            }
            Self::TooManySmallTreeNotes { actual, limit } => {
                write!(
                    formatter,
                    "small P24 tree has {actual} notes, limit is {limit}"
                )
            }
        }
    }
}

impl std::error::Error for Poseidon2P24ReferenceError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_a_noncanonical_input_before_permutation() {
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        let mut invalid = [0_u32; P24_WIDTH];
        invalid[7] = BABYBEAR_MODULUS;
        assert_eq!(
            reference.permutation(invalid),
            Err(Poseidon2P24ReferenceError::NonCanonicalInput {
                index: 7,
                value: BABYBEAR_MODULUS,
            })
        );
    }

    #[test]
    fn candidate_permutation_is_deterministic_and_canonical() {
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        let input = core::array::from_fn(|index| index as u32);
        let first = reference.permutation(input).unwrap();
        let second = reference.permutation(input).unwrap();
        assert_eq!(first, second);
        assert!(first.into_iter().all(|value| value < BABYBEAR_MODULUS));
        assert_ne!(first, [0_u32; P24_WIDTH]);
    }

    #[test]
    fn matches_independently_executed_horizen_p24_vectors() {
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        assert_eq!(
            reference.permutation([0_u32; P24_WIDTH]).unwrap(),
            [
                972_705_262,
                946_791_486,
                1_172_739_502,
                607_725_896,
                1_443_562_977,
                10_371_933,
                1_256_364_390,
                832_646_779,
                324_608_513,
                1_218_088_384,
                1_927_362_941,
                1_316_083_208,
                1_247_749_003,
                494_661_501,
                219_252_024,
                979_706_958,
                417_250_331,
                1_789_792_672,
                422_984_860,
                1_807_101_920,
                1_567_038_995,
                1_949_574_701,
                1_240_162_431,
                1_775_282_439,
            ]
        );
        assert_eq!(
            reference
                .permutation(core::array::from_fn(|index| index as u32))
                .unwrap(),
            [
                785_637_949,
                311_566_256,
                241_540_729,
                1_641_553_353,
                851_108_667,
                1_648_913_123,
                510_139_232,
                616_108_837,
                707_720_633,
                1_357_404_478,
                1_539_840_236,
                275_323_287,
                899_761_440,
                732_341_189,
                664_618_988,
                1_426_148_993,
                1_498_654_335,
                792_736_017,
                1_804_085_503,
                402_731_039,
                659_103_866,
                1_036_635_937,
                1_016_617_890,
                1_470_732_388,
            ]
        );
    }

    #[test]
    fn hash16_rejects_wrong_arity_and_noncanonical_input() {
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        assert_eq!(
            reference.hash16(Poseidon2P24TreeDomainV1::Leaf, &[]),
            Err(Poseidon2P24ReferenceError::InvalidDomainArity {
                domain: Poseidon2P24TreeDomainV1::Leaf,
                actual: 0,
                expected: 16,
            })
        );
        assert_eq!(
            reference.hash16(Poseidon2P24TreeDomainV1::EmptyBase, &[BABYBEAR_MODULUS]),
            Err(Poseidon2P24ReferenceError::InvalidDomainArity {
                domain: Poseidon2P24TreeDomainV1::EmptyBase,
                actual: 1,
                expected: 0,
            })
        );
        let mut invalid_note = [0_u32; 16];
        invalid_note[3] = BABYBEAR_MODULUS;
        assert_eq!(
            reference.leaf(invalid_note),
            Err(Poseidon2P24ReferenceError::NonCanonicalHashInput {
                index: 3,
                value: BABYBEAR_MODULUS,
            })
        );
    }

    #[test]
    fn candidate_tree_construction_preserves_order_and_depth() {
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        let note = core::array::from_fn(|index| index as u32);
        let left = reference.leaf(note).unwrap();
        let right = reference.leaf([42; 16]).unwrap();
        assert_ne!(
            reference.node(left, right).unwrap(),
            reference.node(right, left).unwrap()
        );
        assert_eq!(
            reference.small_tree_root(&[]).unwrap(),
            reference.empty_values().unwrap()[32]
        );
        assert_eq!(
            reference.small_tree_root(&[[0; 16]; 5]),
            Err(Poseidon2P24ReferenceError::TooManySmallTreeNotes {
                actual: 5,
                limit: 4,
            })
        );
    }

    #[test]
    fn matches_independently_executed_horizen_candidate_tree_vectors() {
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        let ascending = core::array::from_fn(|index| index as u32);
        assert_eq!(
            reference.leaf(ascending).unwrap(),
            [
                1_885_520_353,
                817_880_247,
                179_016_861,
                1_670_698_945,
                1_003_043_622,
                1_660_823_950,
                418_310_182,
                145_631_727,
                1_931_043_094,
                552_715_547,
                217_320_907,
                336_527_988,
                950_393_991,
                29_613_778,
                1_342_823_976,
                594_627_989,
            ]
        );
        assert_eq!(
            reference.empty_values().unwrap()[0],
            [
                1_512_554_497,
                689_510_411,
                298_804_240,
                226_781_819,
                1_699_451_698,
                1_897_505_306,
                494_919_784,
                91_749_885,
                525_457_148,
                1_975_785_775,
                1_454_528_822,
                1_425_803_620,
                1_638_267_585,
                196_224_467,
                1_850_954_458,
                742_553_555,
            ]
        );
        assert_eq!(
            reference.small_tree_root(&[]).unwrap(),
            [
                421_415_291,
                1_439_096_942,
                1_801_418_607,
                791_648_458,
                923_180_062,
                336_216_405,
                1_548_328_837,
                276_941_737,
                1_646_407_031,
                1_355_632_884,
                1_840_068_405,
                1_655_848_893,
                1_322_611_759,
                1_198_810_312,
                1_439_237_937,
                217_027_717,
            ]
        );
        assert_eq!(
            reference.small_tree_root(&[ascending]).unwrap(),
            [
                373_411_015,
                446_667_222,
                1_283_249_050,
                1_030_415_401,
                1_153_863_167,
                863_056_528,
                1_182_887_606,
                1_734_020_832,
                976_592_531,
                1_273_310_725,
                52_195_675,
                1_618_911_086,
                636_297_535,
                40_446_655,
                578_434_053,
                7_846_796,
            ]
        );
        assert_eq!(
            reference.small_tree_root(&[ascending, [42; 16]]).unwrap(),
            [
                947_471_769,
                1_312_214_486,
                1_702_539_332,
                1_169_609_440,
                1_835_023_530,
                50_898_665,
                1_106_025_759,
                1_856_856_533,
                409_234_260,
                1_172_338_941,
                592_960_369,
                1_793_134_602,
                1_319_057_675,
                671_860_240,
                311_526_041,
                511_993_212,
            ]
        );
    }
}
