//! Frozen, unselected Poseidon2-BabyBear-P24 tree-parameter candidate.
//!
//! The constants in this module are a verification artifact, not an active
//! hash implementation or a recognized tree-parameter selection. In
//! particular, this module cannot produce a Merkle root or proof and its
//! candidate ID intentionally has a different type from a future allowlisted
//! `TreeParametersId`.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use noxis_privacy_types::BABYBEAR_MODULUS;
use sha2::{Digest, Sha256};

use crate::DRAFT_TREE_MANIFEST_MAGIC;

/// SHA-256 domain for this unselected P24 parameter-candidate identity.
pub const P24_CANDIDATE_MANIFEST_ID_DOMAIN: &[u8] = b"NOXIS/TREE-P24-PARAMETERS-CANDIDATE-ID/V1\0";
/// Fixed byte length of the P24 parameter payload, excluding its header.
pub const P24_PARAMETER_PAYLOAD_LENGTH: usize = 7_596;
/// Fixed byte length of the canonical P24 candidate manifest.
pub const P24_CANDIDATE_MANIFEST_LENGTH: usize = 64 + P24_PARAMETER_PAYLOAD_LENGTH;

const P24_CANDIDATE_MANIFEST_VERSION: u16 = 2;
const P24_CANDIDATE_KIND: u8 = 1;
const P24_PROFILE_ID: u16 = 1;
const P24_TREE_DEPTH: u8 = 32;
const P24_TREE_ARITY: u8 = 2;
const BABYBEAR_FIELD_ID: u8 = 1;
const BABYBEAR_LE32_ENCODING: u8 = 1;
const P24_DIGEST_ELEMENTS: u8 = 16;
const P24_STATE_WIDTH: u8 = 24;
const P24_ALPHA: u8 = 7;
const P24_FULL_ROUNDS: u8 = 8;
const P24_PARTIAL_ROUNDS: u8 = 21;
const P24_RATE: u8 = 15;
const P24_CAPACITY: u8 = 9;
const DENSE_ROW_MAJOR_LAYOUT: u8 = 1;
const INTERNAL_J_PLUS_DIAG_LAYOUT: u8 = 1;
const P24_DIAGONAL_ELEMENTS: u16 = 24;
const P24_MATRIX_DIMENSION: u8 = 24;
const P24_ROUND_CONSTANT_ROWS: u8 = 29;
const P24_IV_DOMAIN_COUNT: u8 = 3;
const P24_IV_ELEMENTS_PER_DOMAIN: u8 = 9;
const P24_HEADER_RESERVED_BYTES: usize = 22;
const P24_PARAMETER_ELEMENTS: usize = P24_PARAMETER_PAYLOAD_LENGTH / 4;
const P24_IV_OFFSET_ELEMENTS: usize = 24 + (24 * 24) + (24 * 24) + (29 * 24);
const P24_IV_KDF_PREFIX: &[u8] = b"NOXIS/POSEIDON2-TREE-IV/V2\0";
const EXPECTED_PAYLOAD_SHA256: [u8; 32] = [
    0x48, 0xf6, 0xc2, 0x5b, 0x02, 0xa6, 0x40, 0xc0, 0x6e, 0x3b, 0xbc, 0x8f, 0xc4, 0x97, 0x04, 0x63,
    0x4f, 0x25, 0x4c, 0xd0, 0xa7, 0x71, 0x61, 0xa5, 0x9b, 0x28, 0x3e, 0x53, 0x02, 0xa3, 0x90, 0xb0,
];
#[cfg(test)]
const EXPECTED_CANDIDATE_ID: [u8; 32] = [
    0x96, 0xd8, 0xc3, 0x94, 0xfc, 0x3e, 0xca, 0x45, 0x6b, 0x91, 0x8b, 0x96, 0xbc, 0x53, 0x2a, 0x33,
    0x95, 0xd5, 0x3b, 0x67, 0x7d, 0x79, 0x89, 0xe7, 0x79, 0x14, 0x31, 0x4c, 0x07, 0x7d, 0xfa, 0x3b,
];

const P24_PARAMETER_PAYLOAD_BASE64: &str =
    include_str!("../fixtures/poseidon2_babybear_p24_candidate_v1.base64");

/// The tree role for which a capacity IV is derived.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Poseidon2P24TreeDomainV1 {
    Leaf,
    Node,
    EmptyBase,
}

impl Poseidon2P24TreeDomainV1 {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::Leaf => b"NOXIS/POSEIDON2-TREE/V2/LEAF\0",
            Self::Node => b"NOXIS/POSEIDON2-TREE/V2/NODE\0",
            Self::EmptyBase => b"NOXIS/POSEIDON2-TREE/V2/EMPTY-BASE\0",
        }
    }

    const fn payload_index(self) -> usize {
        match self {
            Self::Leaf => 0,
            Self::Node => 1,
            Self::EmptyBase => 2,
        }
    }
}

/// The sole canonical P24 candidate manifest.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CandidatePoseidon2P24ManifestV2;

impl CandidatePoseidon2P24ManifestV2 {
    /// Returns the fixed, unselected candidate.
    pub const fn new() -> Self {
        Self
    }

    /// Returns the full canonical manifest bytes after validating its payload.
    pub fn encode(self) -> Result<Vec<u8>, Poseidon2P24CandidateError> {
        let payload = self.parameter_payload()?;
        let mut manifest = Vec::with_capacity(P24_CANDIDATE_MANIFEST_LENGTH);
        manifest.extend_from_slice(&DRAFT_TREE_MANIFEST_MAGIC);
        manifest.extend_from_slice(&P24_CANDIDATE_MANIFEST_VERSION.to_be_bytes());
        manifest.extend_from_slice(&[P24_CANDIDATE_KIND, 0]);
        manifest.extend_from_slice(&P24_PROFILE_ID.to_be_bytes());
        manifest.extend_from_slice(&[
            P24_TREE_DEPTH,
            P24_TREE_ARITY,
            BABYBEAR_FIELD_ID,
            BABYBEAR_LE32_ENCODING,
            P24_DIGEST_ELEMENTS,
            P24_STATE_WIDTH,
            P24_ALPHA,
            P24_FULL_ROUNDS,
            P24_PARTIAL_ROUNDS,
            P24_RATE,
            P24_CAPACITY,
            DENSE_ROW_MAJOR_LAYOUT,
            INTERNAL_J_PLUS_DIAG_LAYOUT,
            0,
        ]);
        manifest.extend_from_slice(&BABYBEAR_MODULUS.to_be_bytes());
        manifest.extend_from_slice(&P24_DIAGONAL_ELEMENTS.to_be_bytes());
        manifest.extend_from_slice(&[
            P24_MATRIX_DIMENSION,
            P24_MATRIX_DIMENSION,
            P24_MATRIX_DIMENSION,
            P24_MATRIX_DIMENSION,
            P24_ROUND_CONSTANT_ROWS,
            P24_MATRIX_DIMENSION,
            P24_IV_DOMAIN_COUNT,
            P24_IV_ELEMENTS_PER_DOMAIN,
        ]);
        manifest.extend_from_slice(&(P24_PARAMETER_PAYLOAD_LENGTH as u32).to_be_bytes());
        manifest.extend_from_slice(&[0; P24_HEADER_RESERVED_BYTES]);
        debug_assert_eq!(manifest.len(), 64);
        manifest.extend_from_slice(&payload);
        debug_assert_eq!(manifest.len(), P24_CANDIDATE_MANIFEST_LENGTH);
        Ok(manifest)
    }

    /// Decodes only the exact canonical candidate byte sequence.
    pub fn decode(bytes: &[u8]) -> Result<Self, Poseidon2P24CandidateError> {
        if bytes.len() != P24_CANDIDATE_MANIFEST_LENGTH {
            return Err(Poseidon2P24CandidateError::InvalidManifestLength {
                actual: bytes.len(),
                expected: P24_CANDIDATE_MANIFEST_LENGTH,
            });
        }
        if bytes[..4] != DRAFT_TREE_MANIFEST_MAGIC {
            return Err(Poseidon2P24CandidateError::InvalidManifestMagic);
        }
        if bytes[4..6] != P24_CANDIDATE_MANIFEST_VERSION.to_be_bytes() {
            return Err(Poseidon2P24CandidateError::UnsupportedManifestVersion);
        }
        if bytes[6] != P24_CANDIDATE_KIND {
            return Err(Poseidon2P24CandidateError::UnsupportedManifestKind);
        }
        if bytes != self_or_canonical_bytes()? {
            return Err(Poseidon2P24CandidateError::NonCanonicalManifest);
        }
        Ok(Self)
    }

    /// Returns the separately typed, non-allowlisted candidate identity.
    pub fn candidate_id(
        self,
    ) -> Result<CandidatePoseidon2P24ManifestIdV2, Poseidon2P24CandidateError> {
        let manifest = self.encode()?;
        let mut hasher = Sha256::new();
        hasher.update(P24_CANDIDATE_MANIFEST_ID_DOMAIN);
        hasher.update(manifest);
        Ok(CandidatePoseidon2P24ManifestIdV2(hasher.finalize().into()))
    }

    /// Decodes and validates the canonical literal parameter payload.
    pub fn parameter_payload(self) -> Result<Vec<u8>, Poseidon2P24CandidateError> {
        let compact: String = P24_PARAMETER_PAYLOAD_BASE64
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect();
        let payload = STANDARD
            .decode(compact)
            .map_err(|_| Poseidon2P24CandidateError::InvalidEmbeddedBase64)?;
        validate_payload(&payload)?;
        Ok(payload)
    }

    /// Re-derives and cross-checks one domain IV from the candidate payload.
    pub fn iv(
        self,
        domain: Poseidon2P24TreeDomainV1,
    ) -> Result<[u32; 9], Poseidon2P24CandidateError> {
        let payload = self.parameter_payload()?;
        let offset = (P24_IV_OFFSET_ELEMENTS + (domain.payload_index() * 9)) * 4;
        let mut stored = [0_u32; 9];
        for (index, value) in stored.iter_mut().enumerate() {
            *value = u32::from_le_bytes(
                payload[offset + (index * 4)..offset + (index * 4) + 4]
                    .try_into()
                    .expect("fixed payload bounds"),
            );
        }
        let derived = derive_iv(domain);
        if stored != derived {
            return Err(Poseidon2P24CandidateError::InvalidDerivedIv { domain });
        }
        Ok(stored)
    }
}

fn self_or_canonical_bytes() -> Result<Vec<u8>, Poseidon2P24CandidateError> {
    CandidatePoseidon2P24ManifestV2::new().encode()
}

fn validate_payload(payload: &[u8]) -> Result<(), Poseidon2P24CandidateError> {
    if payload.len() != P24_PARAMETER_PAYLOAD_LENGTH {
        return Err(Poseidon2P24CandidateError::InvalidPayloadLength {
            actual: payload.len(),
            expected: P24_PARAMETER_PAYLOAD_LENGTH,
        });
    }
    let digest: [u8; 32] = Sha256::digest(payload).into();
    if digest != EXPECTED_PAYLOAD_SHA256 {
        return Err(Poseidon2P24CandidateError::PayloadChecksumMismatch);
    }
    for index in 0..P24_PARAMETER_ELEMENTS {
        let offset = index * 4;
        let value = u32::from_le_bytes(
            payload[offset..offset + 4]
                .try_into()
                .expect("fixed payload bounds"),
        );
        if value >= BABYBEAR_MODULUS {
            return Err(Poseidon2P24CandidateError::NonCanonicalFieldElement { index, value });
        }
    }
    for domain in [
        Poseidon2P24TreeDomainV1::Leaf,
        Poseidon2P24TreeDomainV1::Node,
        Poseidon2P24TreeDomainV1::EmptyBase,
    ] {
        let offset = (P24_IV_OFFSET_ELEMENTS + (domain.payload_index() * 9)) * 4;
        let mut stored = [0_u32; 9];
        for (index, value) in stored.iter_mut().enumerate() {
            *value = u32::from_le_bytes(
                payload[offset + (index * 4)..offset + (index * 4) + 4]
                    .try_into()
                    .expect("fixed payload bounds"),
            );
        }
        if stored != derive_iv(domain) {
            return Err(Poseidon2P24CandidateError::InvalidDerivedIv { domain });
        }
    }
    Ok(())
}

fn derive_iv(domain: Poseidon2P24TreeDomainV1) -> [u32; 9] {
    let mut output = [0_u32; 9];
    let mut accepted = 0;
    let mut counter = 0_u32;
    while accepted < output.len() {
        let mut hasher = Sha256::new();
        hasher.update(P24_IV_KDF_PREFIX);
        hasher.update(domain.label());
        hasher.update(counter.to_be_bytes());
        let digest = hasher.finalize();
        for chunk in digest.chunks_exact(4) {
            let candidate = u32::from_be_bytes(
                chunk
                    .try_into()
                    .expect("sha256 output is divisible by four"),
            );
            if candidate < BABYBEAR_MODULUS {
                output[accepted] = candidate;
                accepted += 1;
                if accepted == output.len() {
                    break;
                }
            }
        }
        counter = counter
            .checked_add(1)
            .expect("IV rejection sampler exhausted u32 counter");
    }
    output
}

/// A candidate identity that deliberately cannot be confused with an approved
/// parameter identity or used to authorize consensus behavior.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CandidatePoseidon2P24ManifestIdV2([u8; 32]);

impl CandidatePoseidon2P24ManifestIdV2 {
    /// Returns the SHA-256 digest bytes in canonical order.
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Display for CandidatePoseidon2P24ManifestIdV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Errors while reading or checking the P24 candidate artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Poseidon2P24CandidateError {
    InvalidEmbeddedBase64,
    InvalidPayloadLength { actual: usize, expected: usize },
    PayloadChecksumMismatch,
    NonCanonicalFieldElement { index: usize, value: u32 },
    InvalidDerivedIv { domain: Poseidon2P24TreeDomainV1 },
    InvalidManifestLength { actual: usize, expected: usize },
    InvalidManifestMagic,
    UnsupportedManifestVersion,
    UnsupportedManifestKind,
    NonCanonicalManifest,
}

impl fmt::Display for Poseidon2P24CandidateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEmbeddedBase64 => {
                formatter.write_str("embedded P24 candidate payload is not base64")
            }
            Self::InvalidPayloadLength { actual, expected } => write!(
                formatter,
                "P24 candidate payload length is {actual}, expected {expected}"
            ),
            Self::PayloadChecksumMismatch => {
                formatter.write_str("P24 candidate payload checksum does not match")
            }
            Self::NonCanonicalFieldElement { index, value } => write!(
                formatter,
                "P24 candidate field element {index} is non-canonical: {value}"
            ),
            Self::InvalidDerivedIv { domain } => write!(
                formatter,
                "P24 candidate IV for {domain:?} differs from its prescribed derivation"
            ),
            Self::InvalidManifestLength { actual, expected } => write!(
                formatter,
                "P24 candidate manifest length is {actual}, expected {expected}"
            ),
            Self::InvalidManifestMagic => {
                formatter.write_str("invalid P24 candidate manifest magic")
            }
            Self::UnsupportedManifestVersion => {
                formatter.write_str("unsupported P24 candidate manifest version")
            }
            Self::UnsupportedManifestKind => {
                formatter.write_str("unsupported P24 candidate manifest kind")
            }
            Self::NonCanonicalManifest => {
                formatter.write_str("P24 candidate manifest differs from canonical bytes")
            }
        }
    }
}

impl std::error::Error for Poseidon2P24CandidateError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_shape_checksum_and_field_encoding_are_frozen() {
        let payload = CandidatePoseidon2P24ManifestV2::new()
            .parameter_payload()
            .unwrap();
        assert_eq!(payload.len(), P24_PARAMETER_PAYLOAD_LENGTH);
        assert_eq!(Sha256::digest(payload).as_slice(), EXPECTED_PAYLOAD_SHA256);
        assert_eq!(P24_PARAMETER_ELEMENTS, 1_899);
    }

    #[test]
    fn manifest_bytes_and_candidate_identity_are_frozen() {
        let manifest = CandidatePoseidon2P24ManifestV2::new();
        let bytes = manifest.encode().unwrap();
        assert_eq!(bytes.len(), P24_CANDIDATE_MANIFEST_LENGTH);
        assert_eq!(&bytes[..4], b"NXTM");
        assert_eq!(&bytes[4..6], &[0, 2]);
        assert_eq!(bytes[6], P24_CANDIDATE_KIND);
        assert_eq!(
            manifest.candidate_id().unwrap().as_bytes(),
            EXPECTED_CANDIDATE_ID
        );
    }

    #[test]
    fn each_domain_iv_is_frozen_and_rederived() {
        let manifest = CandidatePoseidon2P24ManifestV2::new();
        assert_eq!(
            manifest.iv(Poseidon2P24TreeDomainV1::Leaf).unwrap(),
            [
                1_715_759_230,
                249_999_687,
                1_330_481_756,
                332_819_014,
                858_899_600,
                1_629_379_922,
                798_936_327,
                1_891_598_621,
                1_138_906_242
            ]
        );
        assert_eq!(
            manifest.iv(Poseidon2P24TreeDomainV1::Node).unwrap(),
            [
                1_083_254_345,
                979_775_538,
                39_404_930,
                747_249_100,
                754_301_869,
                1_796_627_618,
                536_507_185,
                1_559_761_034,
                980_659_263
            ]
        );
        assert_eq!(
            manifest.iv(Poseidon2P24TreeDomainV1::EmptyBase).unwrap(),
            [
                1_123_440_458,
                1_059_224_467,
                343_664_718,
                1_070_154_018,
                1_064_192_615,
                460_784_134,
                1_802_221_789,
                29_930_173,
                691_548_159
            ]
        );
    }

    #[test]
    fn decoder_rejects_every_noncanonical_mutation() {
        let canonical = CandidatePoseidon2P24ManifestV2::new().encode().unwrap();
        assert_eq!(
            CandidatePoseidon2P24ManifestV2::decode(&canonical),
            Ok(CandidatePoseidon2P24ManifestV2)
        );
        for index in [0, 4, 6, 16, 41, 63, 64, canonical.len() - 1] {
            let mut changed = canonical.clone();
            changed[index] ^= 1;
            assert!(CandidatePoseidon2P24ManifestV2::decode(&changed).is_err());
        }
        assert!(
            CandidatePoseidon2P24ManifestV2::decode(&canonical[..canonical.len() - 1]).is_err()
        );
    }
}
