//! Isolated reference evaluator for the unselected P24 private-note domains.
//!
//! It intentionally exposes only the three fixed-arity byte interfaces frozen
//! by `NXPH v1`. It is neither a wallet API nor a selected hash backend.

use std::fmt;

use noxis_poseidon2_reference::{
    BABYBEAR_MODULUS, BabyBearDigestV2, Poseidon2P24Reference, Poseidon2P24ReferenceError,
};
use noxis_tree_params::{
    CandidatePoseidon2P24NoteDomainsManifestV1, P24_BYTE_PACK_WIDTH, Poseidon2P24NoteDomainV1,
    Poseidon2P24NoteDomainsCandidateError,
};

const RATE: usize = 15;
const WIDTH: usize = 24;
const DIGEST_ELEMENTS: usize = 16;

/// Dense reference evaluator for the three fixed private-note candidate domains.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Poseidon2P24PrivacyReference {
    permutation: Poseidon2P24Reference,
}

impl Poseidon2P24PrivacyReference {
    /// Loads the frozen tree and private-domain candidates before evaluation.
    pub fn load_candidate() -> Result<Self, Poseidon2P24PrivacyReferenceError> {
        CandidatePoseidon2P24NoteDomainsManifestV1::new().encode()?;
        Ok(Self {
            permutation: Poseidon2P24Reference::load_candidate()?,
        })
    }

    /// Evaluates the fixed 32-byte address-domain input.
    pub fn hash_addr(
        &self,
        nullifier_key: [u8; 32],
    ) -> Result<BabyBearDigestV2, Poseidon2P24PrivacyReferenceError> {
        self.hash_bytes(Poseidon2P24NoteDomainV1::Addr, &nullifier_key)
    }

    /// Evaluates the fixed 178-byte canonical note preimage.
    pub fn hash_note(
        &self,
        note_preimage: [u8; 178],
    ) -> Result<BabyBearDigestV2, Poseidon2P24PrivacyReferenceError> {
        self.hash_bytes(Poseidon2P24NoteDomainV1::Note, &note_preimage)
    }

    /// Evaluates the fixed canonical 132-byte nullifier preimage.
    ///
    /// The caller must assemble `key || rho || commitment-u32le || position-u32be`
    /// exactly as frozen by the candidate. A later local witness type will own
    /// that assembly so secrets never become a generic byte-hash API.
    pub fn hash_nullifier_preimage(
        &self,
        nullifier_preimage: [u8; 132],
    ) -> Result<BabyBearDigestV2, Poseidon2P24PrivacyReferenceError> {
        self.hash_bytes(Poseidon2P24NoteDomainV1::Nullifier, &nullifier_preimage)
    }

    /// Shows the only candidate bytes-to-field conversion for one fixed domain.
    pub fn byte_pack3le(
        domain: Poseidon2P24NoteDomainV1,
        input: &[u8],
    ) -> Result<Vec<u32>, Poseidon2P24PrivacyReferenceError> {
        if input.len() != domain.input_bytes() {
            return Err(Poseidon2P24PrivacyReferenceError::InvalidInputLength {
                domain,
                actual: input.len(),
                expected: domain.input_bytes(),
            });
        }
        let packed: Vec<u32> = input
            .chunks(P24_BYTE_PACK_WIDTH)
            .map(|chunk| {
                chunk
                    .iter()
                    .enumerate()
                    .fold(0_u32, |value, (offset, byte)| {
                        value | (u32::from(*byte) << (offset * 8))
                    })
            })
            .collect();
        debug_assert_eq!(packed.len(), domain.input_elements());
        debug_assert!(packed.iter().all(|element| *element < BABYBEAR_MODULUS));
        Ok(packed)
    }

    fn hash_bytes(
        &self,
        domain: Poseidon2P24NoteDomainV1,
        input: &[u8],
    ) -> Result<BabyBearDigestV2, Poseidon2P24PrivacyReferenceError> {
        let elements = Self::byte_pack3le(domain, input)?;
        let iv = CandidatePoseidon2P24NoteDomainsManifestV1::new().iv(domain)?;
        let mut state = [0_u32; WIDTH];
        state[RATE..].copy_from_slice(&iv);
        for block in elements.chunks(RATE) {
            for (lane, value) in state[..RATE].iter_mut().zip(block) {
                *lane = add(*lane, *value);
            }
            state = self.permutation.permutation(state)?;
        }
        let mut output = [0_u32; DIGEST_ELEMENTS];
        output[..RATE].copy_from_slice(&state[..RATE]);
        state = self.permutation.permutation(state)?;
        output[RATE] = state[0];
        Ok(output)
    }
}

fn add(left: u32, right: u32) -> u32 {
    ((u64::from(left) + u64::from(right)) % u64::from(BABYBEAR_MODULUS)) as u32
}

/// Fail-closed errors from the private-domain reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Poseidon2P24PrivacyReferenceError {
    TreeReference(Poseidon2P24ReferenceError),
    Candidate(Poseidon2P24NoteDomainsCandidateError),
    InvalidInputLength {
        domain: Poseidon2P24NoteDomainV1,
        actual: usize,
        expected: usize,
    },
}

impl From<Poseidon2P24ReferenceError> for Poseidon2P24PrivacyReferenceError {
    fn from(value: Poseidon2P24ReferenceError) -> Self {
        Self::TreeReference(value)
    }
}

impl From<Poseidon2P24NoteDomainsCandidateError> for Poseidon2P24PrivacyReferenceError {
    fn from(value: Poseidon2P24NoteDomainsCandidateError) -> Self {
        Self::Candidate(value)
    }
}

impl fmt::Display for Poseidon2P24PrivacyReferenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TreeReference(error) => write!(formatter, "invalid P24 reference: {error}"),
            Self::Candidate(error) => write!(formatter, "invalid NXPH candidate: {error}"),
            Self::InvalidInputLength {
                domain,
                actual,
                expected,
            } => write!(
                formatter,
                "P24 private {domain:?} input has {actual} bytes, expected {expected}"
            ),
        }
    }
}

impl std::error::Error for Poseidon2P24PrivacyReferenceError {}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn ascending<const N: usize>(start: u8) -> [u8; N] {
        core::array::from_fn(|index| start.wrapping_add(index as u8))
    }

    #[test]
    fn byte_pack_is_fixed_length_and_little_endian() {
        assert_eq!(
            Poseidon2P24PrivacyReference::byte_pack3le(
                Poseidon2P24NoteDomainV1::Addr,
                &ascending::<32>(0),
            )
            .unwrap(),
            vec![
                131_328, 328_707, 526_086, 723_465, 920_844, 1_118_223, 1_315_602, 1_512_981,
                1_710_360, 1_907_739, 7_966,
            ]
        );
        assert_eq!(
            Poseidon2P24PrivacyReference::byte_pack3le(Poseidon2P24NoteDomainV1::Note, &[]),
            Err(Poseidon2P24PrivacyReferenceError::InvalidInputLength {
                domain: Poseidon2P24NoteDomainV1::Note,
                actual: 0,
                expected: 178,
            })
        );
    }

    #[test]
    fn frozen_external_kat_artifact_is_present_and_stable() {
        let bytes = include_bytes!("../fixtures/p24-private-domain-kats-v1.json");
        assert_eq!(bytes.len(), 6_693);
        assert_eq!(
            format!("{:x}", Sha256::digest(bytes)),
            "c99521ac2c154de6e1212a617c5bbcd6c2f20523acf97631fed2ad3ed099cf30"
        );
    }

    #[test]
    fn matches_externally_executed_addr_and_note_kats() {
        let reference = Poseidon2P24PrivacyReference::load_candidate().unwrap();
        assert_eq!(
            reference.hash_addr(ascending::<32>(0)).unwrap(),
            [
                115_780_848,
                1_488_678_630,
                1_399_912_284,
                1_219_509_420,
                1_345_882_329,
                1_837_465_190,
                1_967_171_304,
                738_411_337,
                1_437_527_031,
                1_923_884_581,
                1_024_490_489,
                923_711_499,
                1_254_496_708,
                1_249_780_469,
                1_985_204_366,
                771_190_060,
            ]
        );
        let descending = core::array::from_fn(|index| 255_u8 - index as u8);
        assert_eq!(
            reference.hash_addr(descending).unwrap(),
            [
                2_002_739_025,
                113_032_689,
                1_421_794_099,
                964_418_646,
                1_964_345_787,
                1_551_781_171,
                338_563_576,
                133_538_835,
                745_313_621,
                1_973_481_606,
                478_566_289,
                1_141_262_648,
                529_582_569,
                6_046_958,
                312_207_571,
                948_951_208,
            ]
        );
        let affine =
            core::array::from_fn(|index| 17_u8.wrapping_add(31_u8.wrapping_mul(index as u8)));
        assert_eq!(
            reference.hash_note(ascending::<178>(0)).unwrap(),
            [
                1_727_817_926,
                750_994_629,
                697_453_727,
                566_577_232,
                973_445_008,
                1_906_707_017,
                881_196_045,
                1_222_807_235,
                181_143_227,
                959_402_732,
                1_792_526_077,
                418_591_644,
                1_278_989_523,
                207_744_150,
                1_940_240_553,
                1_515_884_781,
            ]
        );
        assert_eq!(
            reference.hash_note(affine).unwrap(),
            [
                562_739_465,
                1_798_714_523,
                1_611_819_938,
                507_084_372,
                645_641_553,
                1_524_421_508,
                528_505_987,
                20_854_891,
                1_388_027_201,
                883_420_654,
                950_708_463,
                668_466_233,
                178_111_559,
                106_289_656,
                1_730_719_700,
                997_768_926,
            ]
        );
    }

    #[test]
    fn matches_externally_executed_nullifier_kats_and_rejects_mutation() {
        let reference = Poseidon2P24PrivacyReference::load_candidate().unwrap();
        let mut first = ascending::<132>(0);
        first[128..].copy_from_slice(&0_u32.to_be_bytes());
        assert_eq!(
            reference.hash_nullifier_preimage(first).unwrap(),
            [
                2_003_527_154,
                1_745_920_045,
                113_276_676,
                721_087_644,
                1_558_321_923,
                1_928_665_047,
                141_168_681,
                253_411_039,
                1_170_925_763,
                387_439_201,
                491_313_824,
                1_071_531_158,
                939_053_051,
                145_290_746,
                1_291_080_194,
                1_095_323_589,
            ]
        );
        let mut second = [0_u8; 132];
        second[..32].copy_from_slice(&ascending::<32>(160));
        second[32..64].copy_from_slice(&ascending::<32>(96));
        for (index, byte) in second[64..128].iter_mut().enumerate() {
            *byte = 255 - index as u8;
        }
        second[128..].copy_from_slice(&u32::MAX.to_be_bytes());
        let expected = [
            287_356_015,
            960_027_868,
            1_517_262_014,
            1_316_939_758,
            1_327_369_726,
            1_850_628_752,
            1_309_840_036,
            1_273_441_266,
            1_912_785_637,
            35_654_405,
            735_052_960,
            494_615_289,
            441_950_369,
            502_904_033,
            1_535_097_886,
            1_170_294_996,
        ];
        assert_eq!(reference.hash_nullifier_preimage(second).unwrap(), expected);
        second[100] ^= 1;
        assert_ne!(reference.hash_nullifier_preimage(second).unwrap(), expected);
    }
}
