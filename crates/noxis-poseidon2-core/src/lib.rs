//! Allocation-free, `no_std` Poseidon2-BabyBear-P24 evaluator.
//!
//! This crate is deliberately limited to the frozen **candidate** tree
//! parameters. It contains no manifest parser, storage codec, or consensus
//! authorization. The build step reads the canonical checked-in parameter
//! fixture and rejects a changed length, checksum, or non-canonical element
//! before emitting the fixed parameter array consumed by this kernel.

#![no_std]

/// Width of the frozen Poseidon2-BabyBear candidate state.
pub const P24_WIDTH: usize = 24;
/// Number of full rounds in the candidate permutation.
pub const P24_FULL_ROUNDS: usize = 8;
/// Number of partial rounds in the candidate permutation.
pub const P24_PARTIAL_ROUNDS: usize = 21;
/// Prime modulus of the BabyBear field.
pub const BABYBEAR_MODULUS: u32 = 2_013_265_921;
/// Number of field elements in a Noxis tree digest.
pub const P24_TREE_DIGEST_ELEMENTS: usize = 16;
/// Required Noxis candidate membership-path depth.
pub const P24_TREE_DEPTH: usize = 32;

const P24_HALF_FULL_ROUNDS: usize = P24_FULL_ROUNDS / 2;
const P24_TOTAL_ROUNDS: usize = P24_FULL_ROUNDS + P24_PARTIAL_ROUNDS;
const P24_DIAGONAL_OFFSET: usize = 0;
const P24_EXTERNAL_OFFSET: usize = P24_DIAGONAL_OFFSET + P24_WIDTH;
const P24_INTERNAL_OFFSET: usize = P24_EXTERNAL_OFFSET + (P24_WIDTH * P24_WIDTH);
const P24_ROUND_CONSTANT_OFFSET: usize = P24_INTERNAL_OFFSET + (P24_WIDTH * P24_WIDTH);
const P24_IV_OFFSET: usize = P24_ROUND_CONSTANT_OFFSET + (P24_TOTAL_ROUNDS * P24_WIDTH);

include!(concat!(env!("OUT_DIR"), "/parameters.rs"));

/// A fixed-width canonical BabyBear state.
pub type BabyBearStateP24 = [u32; P24_WIDTH];
/// A canonical Noxis candidate tree digest.
pub type BabyBearDigestV2 = [u32; P24_TREE_DIGEST_ELEMENTS];

/// The three fixed tree roles supported by the candidate construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum P24TreeDomain {
    Leaf,
    Node,
    EmptyBase,
}

impl P24TreeDomain {
    const fn input_elements(self) -> usize {
        match self {
            Self::Leaf => P24_TREE_DIGEST_ELEMENTS,
            Self::Node => P24_TREE_DIGEST_ELEMENTS * 2,
            Self::EmptyBase => 0,
        }
    }

    const fn iv_offset(self) -> usize {
        let domain = match self {
            Self::Leaf => 0,
            Self::Node => 1,
            Self::EmptyBase => 2,
        };
        P24_IV_OFFSET + (domain * 9)
    }
}

/// Errors produced by the allocation-free candidate evaluator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum P24CoreError {
    NonCanonicalInput {
        index: usize,
        value: u32,
    },
    InvalidDomainArity {
        domain: P24TreeDomain,
        actual: usize,
        expected: usize,
    },
}

/// Applies the frozen candidate permutation to a canonical state.
pub fn permutation(input: BabyBearStateP24) -> Result<BabyBearStateP24, P24CoreError> {
    validate_elements(&input)?;
    let external = external_matrix();
    let internal = internal_matrix();
    let constants = round_constants();
    let mut state = matmul(&external, &input);

    for constants in constants.iter().take(P24_HALF_FULL_ROUNDS) {
        add_round_constants(&mut state, constants);
        apply_sbox_to_all(&mut state);
        state = matmul(&external, &state);
    }
    for constants in constants
        .iter()
        .skip(P24_HALF_FULL_ROUNDS)
        .take(P24_PARTIAL_ROUNDS)
    {
        state[0] = add(state[0], constants[0]);
        state[0] = sbox_seven(state[0]);
        state = matmul(&internal, &state);
    }
    for constants in constants
        .iter()
        .skip(P24_HALF_FULL_ROUNDS + P24_PARTIAL_ROUNDS)
    {
        add_round_constants(&mut state, constants);
        apply_sbox_to_all(&mut state);
        state = matmul(&external, &state);
    }
    Ok(state)
}

/// Applies Noxis's fixed `Hash16` construction for one tree role.
pub fn hash16(domain: P24TreeDomain, input: &[u32]) -> Result<BabyBearDigestV2, P24CoreError> {
    let expected = domain.input_elements();
    if input.len() != expected {
        return Err(P24CoreError::InvalidDomainArity {
            domain,
            actual: input.len(),
            expected,
        });
    }
    validate_elements(input)?;

    let mut state = [0_u32; P24_WIDTH];
    state[15..].copy_from_slice(&P24_PARAMETERS[domain.iv_offset()..domain.iv_offset() + 9]);
    if input.is_empty() {
        state = permutation(state)?;
    } else {
        for block in input.chunks(15) {
            for (lane, value) in state[..15].iter_mut().zip(block) {
                *lane = add(*lane, *value);
            }
            state = permutation(state)?;
        }
    }

    let mut output = [0_u32; P24_TREE_DIGEST_ELEMENTS];
    output[..15].copy_from_slice(&state[..15]);
    state = permutation(state)?;
    output[15] = state[0];
    Ok(output)
}

/// Applies the candidate leaf transformation to a private note commitment.
pub fn leaf(note: BabyBearDigestV2) -> Result<BabyBearDigestV2, P24CoreError> {
    hash16(P24TreeDomain::Leaf, &note)
}

/// Applies the ordered candidate parent transformation.
pub fn node(
    left: BabyBearDigestV2,
    right: BabyBearDigestV2,
) -> Result<BabyBearDigestV2, P24CoreError> {
    let mut input = [0_u32; P24_TREE_DIGEST_ELEMENTS * 2];
    input[..P24_TREE_DIGEST_ELEMENTS].copy_from_slice(&left);
    input[P24_TREE_DIGEST_ELEMENTS..].copy_from_slice(&right);
    hash16(P24TreeDomain::Node, &input)
}

/// Reconstructs a depth-32 candidate root from one private note commitment.
pub fn root_from_note_path(
    note: BabyBearDigestV2,
    leaf_index: u32,
    siblings: [BabyBearDigestV2; P24_TREE_DEPTH],
) -> Result<BabyBearDigestV2, P24CoreError> {
    let mut current = leaf(note)?;
    for (level, sibling) in siblings.into_iter().enumerate() {
        current = if (leaf_index >> level) & 1 == 0 {
            node(current, sibling)?
        } else {
            node(sibling, current)?
        };
    }
    Ok(current)
}

fn external_matrix() -> [[u32; P24_WIDTH]; P24_WIDTH] {
    matrix_from(P24_EXTERNAL_OFFSET)
}

fn internal_matrix() -> [[u32; P24_WIDTH]; P24_WIDTH] {
    matrix_from(P24_INTERNAL_OFFSET)
}

fn round_constants() -> [[u32; P24_WIDTH]; P24_TOTAL_ROUNDS] {
    let mut constants = [[0_u32; P24_WIDTH]; P24_TOTAL_ROUNDS];
    for (row, values) in constants.iter_mut().enumerate() {
        let offset = P24_ROUND_CONSTANT_OFFSET + (row * P24_WIDTH);
        values.copy_from_slice(&P24_PARAMETERS[offset..offset + P24_WIDTH]);
    }
    constants
}

fn matrix_from(offset: usize) -> [[u32; P24_WIDTH]; P24_WIDTH] {
    let mut matrix = [[0_u32; P24_WIDTH]; P24_WIDTH];
    for (row, values) in matrix.iter_mut().enumerate() {
        let row_offset = offset + (row * P24_WIDTH);
        values.copy_from_slice(&P24_PARAMETERS[row_offset..row_offset + P24_WIDTH]);
    }
    matrix
}

fn validate_elements(input: &[u32]) -> Result<(), P24CoreError> {
    for (index, value) in input.iter().copied().enumerate() {
        if value >= BABYBEAR_MODULUS {
            return Err(P24CoreError::NonCanonicalInput { index, value });
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_frozen_zero_state_permutation_vector() {
        assert_eq!(
            permutation([0_u32; P24_WIDTH]).unwrap(),
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
    }

    #[test]
    fn rejects_noncanonical_note_element() {
        let mut note = [0_u32; P24_TREE_DIGEST_ELEMENTS];
        note[3] = BABYBEAR_MODULUS;
        assert_eq!(
            leaf(note),
            Err(P24CoreError::NonCanonicalInput {
                index: 3,
                value: BABYBEAR_MODULUS
            })
        );
    }
}
