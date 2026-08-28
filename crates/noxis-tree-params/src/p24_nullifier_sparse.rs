//! Frozen candidate domains for the private sparse nullifier tree.
//!
//! `NXSM` is an unselected child of `NXPH`. Its three IVs are deliberately
//! distinct from note, intent and public-tree functions, so a future proof
//! cannot confuse an unspent-nullifier path with a note-membership path.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use noxis_privacy_types::BABYBEAR_MODULUS;
use sha2::{Digest, Sha256};

use crate::{
    CandidatePoseidon2P24NoteDomainsManifestV1, P24_BYTE_PACK_WIDTH,
    P24_NOTE_DOMAINS_MANIFEST_LENGTH, Poseidon2P24NoteDomainsCandidateError,
};

/// SHA-256 domain for the isolated `NXSM` candidate identity.
pub const P24_NULLIFIER_SPARSE_CANDIDATE_ID_DOMAIN: &[u8] =
    b"NOXIS/POSEIDON2-NULLIFIER-SPARSE-MERKLE-CANDIDATE-ID/V1\0";
/// Three stored capacity IVs, each comprising nine BabyBear elements.
pub const P24_NULLIFIER_SPARSE_PAYLOAD_LENGTH: usize = 108;
/// Exact byte size of the canonical `NXSM v1` candidate manifest.
pub const P24_NULLIFIER_SPARSE_MANIFEST_LENGTH: usize = 8_347;

const MANIFEST_MAGIC: [u8; 4] = *b"NXSM";
const MANIFEST_VERSION: u16 = 1;
const CANDIDATE_KIND: u8 = 1;
const FLAGS: u8 = 0;
const HEADER_LENGTH: usize = 64;
const CHECKSUM_LENGTH: usize = 32;
const IV_ELEMENTS: usize = 9;
const DIGEST_ELEMENTS: u8 = 16;
const RATE: u8 = 15;
const CAPACITY: u8 = 9;
const SPARSE_DEPTH: u16 = 512;
const CHECKSUM_DOMAIN: &[u8] = b"NOXIS/POSEIDON2-NULLIFIER-SPARSE-MERKLE-MANIFEST-CHECKSUM/V1\0";
const IV_KDF_PREFIX: &[u8] = b"NOXIS/POSEIDON2-NULLIFIER-SPARSE-MERKLE-IV/V1\0";
const LEAF_LABEL: &[u8] = b"NOXIS/POSEIDON2-PRIVACY/V1/NULLIFIER-SPARSE-LEAF\0";
const NODE_LABEL: &[u8] = b"NOXIS/POSEIDON2-PRIVACY/V1/NULLIFIER-SPARSE-NODE\0";
const EMPTY_LABEL: &[u8] = b"NOXIS/POSEIDON2-PRIVACY/V1/NULLIFIER-SPARSE-EMPTY\0";
const PAYLOAD_BASE64: &str =
    include_str!("../fixtures/poseidon2_babybear_p24_nullifier_sparse_candidate_v1.base64");
const EXPECTED_PAYLOAD_SHA256: [u8; 32] = [
    0xfa, 0x1d, 0x30, 0x6b, 0xf4, 0xa4, 0x7d, 0x77, 0xe7, 0x66, 0x2f, 0xfb, 0x48, 0xd9, 0xc7, 0xc9,
    0x22, 0x66, 0xd9, 0xda, 0xae, 0xe0, 0x79, 0x2b, 0x31, 0xbc, 0x6c, 0xf4, 0x9d, 0x97, 0x8f, 0x57,
];

/// One fixed role in the candidate 512-bit sparse nullifier tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Poseidon2P24NullifierSparseDomainV1 {
    /// Hashes exactly one canonical 64-byte `NullifierV2` as a spent leaf.
    Leaf,
    /// Hashes ordered left and right 64-byte child digests.
    Node,
    /// Derives the unspent leaf before recursive self-parenting.
    Empty,
}

impl Poseidon2P24NullifierSparseDomainV1 {
    /// Fixed source length; no caller-selected padding is permitted.
    pub const fn input_bytes(self) -> usize {
        match self {
            Self::Leaf => 64,
            Self::Node => 128,
            Self::Empty => 0,
        }
    }

    /// Exact candidate `BytePack3LE` input arity.
    pub const fn input_elements(self) -> usize {
        self.input_bytes().div_ceil(P24_BYTE_PACK_WIDTH)
    }

    const fn label(self) -> &'static [u8] {
        match self {
            Self::Leaf => LEAF_LABEL,
            Self::Node => NODE_LABEL,
            Self::Empty => EMPTY_LABEL,
        }
    }

    const fn payload_index(self) -> usize {
        match self {
            Self::Leaf => 0,
            Self::Node => 1,
            Self::Empty => 2,
        }
    }
}

/// Complete, rederivable candidate manifest for a sparse nullifier tree.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CandidatePoseidon2P24NullifierSparseManifestV1;

impl CandidatePoseidon2P24NullifierSparseManifestV1 {
    /// Returns the only `NXSM v1` candidate.
    pub const fn new() -> Self {
        Self
    }

    /// Encodes the exact header, immediate parent, descriptors and checksum.
    pub fn encode(self) -> Result<Vec<u8>, Poseidon2P24NullifierSparseCandidateError> {
        let parent = CandidatePoseidon2P24NoteDomainsManifestV1::new();
        let parent_bytes = parent.encode()?;
        let parent_id = parent.candidate_id()?;
        let payload = self.payload()?;
        let mut manifest = Vec::with_capacity(P24_NULLIFIER_SPARSE_MANIFEST_LENGTH);
        manifest.extend_from_slice(&MANIFEST_MAGIC);
        manifest.extend_from_slice(&MANIFEST_VERSION.to_be_bytes());
        manifest.extend_from_slice(&[CANDIDATE_KIND, FLAGS]);
        manifest.extend_from_slice(&(P24_NOTE_DOMAINS_MANIFEST_LENGTH as u16).to_be_bytes());
        manifest.extend_from_slice(&parent_id.as_bytes());
        manifest.extend_from_slice(&[
            1,
            1,
            DIGEST_ELEMENTS,
            24,
            RATE,
            CAPACITY,
            1,
            1,
            P24_BYTE_PACK_WIDTH as u8,
            1,
            1,
            1,
            1,
            3,
            IV_ELEMENTS as u8,
            1,
            (SPARSE_DEPTH >> 8) as u8,
            SPARSE_DEPTH as u8,
            1,
            1,
            1,
            1,
        ]);
        debug_assert_eq!(manifest.len(), HEADER_LENGTH);
        manifest.extend_from_slice(&parent_bytes);
        for domain in [
            Poseidon2P24NullifierSparseDomainV1::Leaf,
            Poseidon2P24NullifierSparseDomainV1::Node,
            Poseidon2P24NullifierSparseDomainV1::Empty,
        ] {
            append_descriptor(&mut manifest, domain, &payload);
        }
        manifest.extend_from_slice(&manifest_checksum(&manifest));
        debug_assert_eq!(manifest.len(), P24_NULLIFIER_SPARSE_MANIFEST_LENGTH);
        Ok(manifest)
    }

    /// Accepts only the byte-for-byte fixed candidate artifact.
    pub fn decode(bytes: &[u8]) -> Result<Self, Poseidon2P24NullifierSparseCandidateError> {
        if bytes.len() != P24_NULLIFIER_SPARSE_MANIFEST_LENGTH {
            return Err(
                Poseidon2P24NullifierSparseCandidateError::InvalidManifestLength {
                    actual: bytes.len(),
                    expected: P24_NULLIFIER_SPARSE_MANIFEST_LENGTH,
                },
            );
        }
        if bytes[..4] != MANIFEST_MAGIC {
            return Err(Poseidon2P24NullifierSparseCandidateError::InvalidManifestMagic);
        }
        if bytes[4..6] != MANIFEST_VERSION.to_be_bytes() {
            return Err(Poseidon2P24NullifierSparseCandidateError::UnsupportedManifestVersion);
        }
        if bytes[6] != CANDIDATE_KIND || bytes[7] != FLAGS {
            return Err(Poseidon2P24NullifierSparseCandidateError::NonCanonicalManifest);
        }
        let checksum_offset = bytes.len() - CHECKSUM_LENGTH;
        if bytes[checksum_offset..] != manifest_checksum(&bytes[..checksum_offset]) {
            return Err(Poseidon2P24NullifierSparseCandidateError::ManifestChecksumMismatch);
        }
        if bytes != Self::new().encode()? {
            return Err(Poseidon2P24NullifierSparseCandidateError::NonCanonicalManifest);
        }
        Ok(Self)
    }

    /// Returns a separate, non-allowlisted candidate identity.
    pub fn candidate_id(
        self,
    ) -> Result<CandidatePoseidon2P24NullifierSparseIdV1, Poseidon2P24NullifierSparseCandidateError>
    {
        let mut hasher = Sha256::new();
        hasher.update(P24_NULLIFIER_SPARSE_CANDIDATE_ID_DOMAIN);
        hasher.update(self.encode()?);
        Ok(CandidatePoseidon2P24NullifierSparseIdV1(
            hasher.finalize().into(),
        ))
    }

    /// Reads and validates the fixed three-IV payload.
    pub fn payload(self) -> Result<Vec<u8>, Poseidon2P24NullifierSparseCandidateError> {
        let compact: String = PAYLOAD_BASE64
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect();
        let payload = STANDARD
            .decode(compact)
            .map_err(|_| Poseidon2P24NullifierSparseCandidateError::InvalidEmbeddedBase64)?;
        validate_payload(&payload)?;
        Ok(payload)
    }

    /// Re-derives and checks one fixed capacity IV.
    pub fn iv(
        self,
        domain: Poseidon2P24NullifierSparseDomainV1,
    ) -> Result<[u32; IV_ELEMENTS], Poseidon2P24NullifierSparseCandidateError> {
        let payload = self.payload()?;
        let offset = domain.payload_index() * IV_ELEMENTS * 4;
        let stored = decode_iv(&payload[offset..offset + IV_ELEMENTS * 4]);
        if stored != derive_iv(domain)? {
            return Err(Poseidon2P24NullifierSparseCandidateError::InvalidDerivedIv { domain });
        }
        Ok(stored)
    }
}

fn append_descriptor(
    manifest: &mut Vec<u8>,
    domain: Poseidon2P24NullifierSparseDomainV1,
    payload: &[u8],
) {
    let label = domain.label();
    manifest.push(domain.payload_index() as u8 + 1);
    manifest.push(label.len() as u8);
    manifest.extend_from_slice(&(domain.input_bytes() as u16).to_be_bytes());
    manifest.push(domain.input_elements() as u8);
    manifest.extend_from_slice(label);
    let offset = domain.payload_index() * IV_ELEMENTS * 4;
    manifest.extend_from_slice(&payload[offset..offset + IV_ELEMENTS * 4]);
}

fn validate_payload(payload: &[u8]) -> Result<(), Poseidon2P24NullifierSparseCandidateError> {
    if payload.len() != P24_NULLIFIER_SPARSE_PAYLOAD_LENGTH {
        return Err(
            Poseidon2P24NullifierSparseCandidateError::InvalidPayloadLength {
                actual: payload.len(),
                expected: P24_NULLIFIER_SPARSE_PAYLOAD_LENGTH,
            },
        );
    }
    let digest: [u8; 32] = Sha256::digest(payload).into();
    if digest != EXPECTED_PAYLOAD_SHA256 {
        return Err(Poseidon2P24NullifierSparseCandidateError::PayloadChecksumMismatch);
    }
    for (index, chunk) in payload.chunks_exact(4).enumerate() {
        let value = u32::from_le_bytes(chunk.try_into().expect("fixed field element width"));
        if value >= BABYBEAR_MODULUS {
            return Err(
                Poseidon2P24NullifierSparseCandidateError::NonCanonicalFieldElement {
                    index,
                    value,
                },
            );
        }
    }
    for domain in [
        Poseidon2P24NullifierSparseDomainV1::Leaf,
        Poseidon2P24NullifierSparseDomainV1::Node,
        Poseidon2P24NullifierSparseDomainV1::Empty,
    ] {
        let offset = domain.payload_index() * IV_ELEMENTS * 4;
        if decode_iv(&payload[offset..offset + IV_ELEMENTS * 4]) != derive_iv(domain)? {
            return Err(Poseidon2P24NullifierSparseCandidateError::InvalidDerivedIv { domain });
        }
    }
    Ok(())
}

fn decode_iv(bytes: &[u8]) -> [u32; IV_ELEMENTS] {
    core::array::from_fn(|index| {
        u32::from_le_bytes(
            bytes[index * 4..index * 4 + 4]
                .try_into()
                .expect("fixed IV bounds"),
        )
    })
}

fn derive_iv(
    domain: Poseidon2P24NullifierSparseDomainV1,
) -> Result<[u32; IV_ELEMENTS], Poseidon2P24NullifierSparseCandidateError> {
    let parent_id = CandidatePoseidon2P24NoteDomainsManifestV1::new().candidate_id()?;
    let mut output = [0_u32; IV_ELEMENTS];
    let mut accepted = 0;
    let mut counter = 0_u32;
    while accepted < output.len() {
        let mut hasher = Sha256::new();
        hasher.update(IV_KDF_PREFIX);
        hasher.update(parent_id.as_bytes());
        hasher.update(domain.label());
        hasher.update(counter.to_be_bytes());
        for chunk in hasher.finalize().chunks_exact(4) {
            let candidate = u32::from_be_bytes(chunk.try_into().expect("SHA-256 word width"));
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
            .expect("IV rejection sampler exhausted counter");
    }
    Ok(output)
}

fn manifest_checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CHECKSUM_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Candidate identity that cannot be used as an approved network parameter.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CandidatePoseidon2P24NullifierSparseIdV1([u8; 32]);

impl CandidatePoseidon2P24NullifierSparseIdV1 {
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Display for CandidatePoseidon2P24NullifierSparseIdV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Fail-closed decoding and derivation errors for `NXSM`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Poseidon2P24NullifierSparseCandidateError {
    Parent(Poseidon2P24NoteDomainsCandidateError),
    InvalidEmbeddedBase64,
    InvalidPayloadLength {
        actual: usize,
        expected: usize,
    },
    PayloadChecksumMismatch,
    ManifestChecksumMismatch,
    NonCanonicalFieldElement {
        index: usize,
        value: u32,
    },
    InvalidDerivedIv {
        domain: Poseidon2P24NullifierSparseDomainV1,
    },
    InvalidManifestLength {
        actual: usize,
        expected: usize,
    },
    InvalidManifestMagic,
    UnsupportedManifestVersion,
    NonCanonicalManifest,
}

impl From<Poseidon2P24NoteDomainsCandidateError> for Poseidon2P24NullifierSparseCandidateError {
    fn from(value: Poseidon2P24NoteDomainsCandidateError) -> Self {
        Self::Parent(value)
    }
}

impl fmt::Display for Poseidon2P24NullifierSparseCandidateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "nullifier sparse candidate error: {self:?}")
    }
}

impl std::error::Error for Poseidon2P24NullifierSparseCandidateError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_is_canonical_and_domains_are_separate() {
        let manifest = CandidatePoseidon2P24NullifierSparseManifestV1::new();
        let encoded = manifest.encode().unwrap();
        assert_eq!(encoded.len(), P24_NULLIFIER_SPARSE_MANIFEST_LENGTH);
        assert_eq!(
            CandidatePoseidon2P24NullifierSparseManifestV1::decode(&encoded),
            Ok(manifest)
        );
        assert_eq!(
            Poseidon2P24NullifierSparseDomainV1::Leaf.input_elements(),
            22
        );
        assert_eq!(
            Poseidon2P24NullifierSparseDomainV1::Node.input_elements(),
            43
        );
        assert_eq!(
            Poseidon2P24NullifierSparseDomainV1::Empty.input_elements(),
            0
        );
        assert_ne!(
            manifest
                .iv(Poseidon2P24NullifierSparseDomainV1::Leaf)
                .unwrap(),
            manifest
                .iv(Poseidon2P24NullifierSparseDomainV1::Node)
                .unwrap()
        );
        assert_eq!(
            manifest.candidate_id().unwrap().as_bytes(),
            [
                23, 106, 134, 140, 133, 95, 60, 197, 33, 191, 21, 51, 137, 168, 62, 3, 180, 174,
                38, 252, 66, 106, 51, 4, 202, 237, 89, 236, 116, 135, 154, 241,
            ]
        );
    }

    #[test]
    fn manifest_rejects_mutation() {
        let mut encoded = CandidatePoseidon2P24NullifierSparseManifestV1::new()
            .encode()
            .unwrap();
        encoded[64] ^= 1;
        assert!(CandidatePoseidon2P24NullifierSparseManifestV1::decode(&encoded).is_err());
    }
}
