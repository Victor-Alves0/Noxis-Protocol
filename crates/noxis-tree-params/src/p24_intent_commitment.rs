//! Frozen, unselected commitment-domain candidate for a private transfer intent.
//!
//! `NXIC` is deliberately a child of the complete `NXPH` artifact. It freezes
//! only the framing and IV for a future reference implementation; it neither
//! selects parameters nor authorizes a consensus transaction or a proof.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use noxis_privacy_types::BABYBEAR_MODULUS;
use sha2::{Digest, Sha256};

use crate::{
    CandidatePoseidon2P24NoteDomainsManifestV1, P24_BYTE_PACK_WIDTH,
    P24_NOTE_DOMAINS_MANIFEST_LENGTH, Poseidon2P24NoteDomainsCandidateError,
};

/// SHA-256 domain for an `NXIC` candidate identity.
pub const P24_INTENT_COMMITMENT_CANDIDATE_ID_DOMAIN: &[u8] =
    b"NOXIS/POSEIDON2-INTENT-COMMITMENT-CANDIDATE-ID/V1\0";
/// Exact source length accepted by the fixed `H_INTENT` domain.
pub const P24_INTENT_COMMITMENT_INPUT_BYTES: usize = 640;
/// Exact `BytePack3LE` element count for the 640-byte intent encoding.
pub const P24_INTENT_COMMITMENT_INPUT_ELEMENTS: usize = 214;
/// Exact size of the stored nine-element capacity IV.
pub const P24_INTENT_COMMITMENT_PAYLOAD_LENGTH: usize = 36;
/// Exact size of the canonical `NXIC v1` candidate manifest.
pub const P24_INTENT_COMMITMENT_MANIFEST_LENGTH: usize = 8_162;

const MANIFEST_MAGIC: [u8; 4] = *b"NXIC";
const MANIFEST_VERSION: u16 = 1;
const CANDIDATE_KIND: u8 = 1;
const FLAGS: u8 = 0;
const HEADER_LENGTH: usize = 64;
const CHECKSUM_LENGTH: usize = 32;
const IV_ELEMENTS: usize = 9;
const DIGEST_ELEMENTS: u8 = 16;
const RATE: u8 = 15;
const CAPACITY: u8 = 9;
const CHECKSUM_DOMAIN: &[u8] = b"NOXIS/POSEIDON2-INTENT-COMMITMENT-MANIFEST-CHECKSUM/V1\0";
const IV_KDF_PREFIX: &[u8] = b"NOXIS/POSEIDON2-INTENT-COMMITMENT-IV/V1\0";
const INTENT_LABEL: &[u8] = b"NOXIS/POSEIDON2-PRIVACY/V1/INTENT-COMMITMENT\0";
const PAYLOAD_BASE64: &str =
    include_str!("../fixtures/poseidon2_babybear_p24_intent_commitment_candidate_v1.base64");
const EXPECTED_PAYLOAD_SHA256: [u8; 32] = [
    0xcf, 0x82, 0x83, 0xc1, 0x8d, 0xd1, 0xac, 0x74, 0xae, 0x1e, 0xb9, 0xb1, 0xd0, 0x5e, 0x4b, 0xb8,
    0x9e, 0xa4, 0x19, 0x96, 0x0d, 0xd6, 0xff, 0xf4, 0x27, 0x0a, 0xa5, 0x9f, 0x52, 0x74, 0xc4, 0x69,
];
#[cfg(test)]
const EXPECTED_MANIFEST_SHA256: [u8; 32] = [
    0x7d, 0x83, 0x95, 0xb7, 0x13, 0x4e, 0xad, 0x94, 0xe1, 0x5a, 0x65, 0xa5, 0x9e, 0x85, 0x6a, 0xfa,
    0xcf, 0x3d, 0xc2, 0xe9, 0xad, 0xd8, 0x82, 0xc1, 0xa2, 0xee, 0xe0, 0x0b, 0xe3, 0x0e, 0x29, 0x50,
];
#[cfg(test)]
const EXPECTED_CANDIDATE_ID: [u8; 32] = [
    0xfe, 0xc7, 0x3e, 0x2b, 0x82, 0x38, 0xb7, 0x49, 0x35, 0x70, 0x42, 0xbd, 0xba, 0x55, 0x47, 0x0d,
    0x67, 0x4f, 0xb1, 0x2c, 0xa4, 0x98, 0xc4, 0x7b, 0xb7, 0x61, 0x85, 0x4c, 0xa8, 0x5b, 0x20, 0xe5,
];

/// The only frozen `NXIC v1` domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Poseidon2P24IntentCommitmentDomainV1 {
    /// Commits to exactly one canonical 640-byte private-transfer intent.
    Intent,
}

impl Poseidon2P24IntentCommitmentDomainV1 {
    /// Fixed source length, so no variable-length padding rule exists.
    pub const fn input_bytes(self) -> usize {
        P24_INTENT_COMMITMENT_INPUT_BYTES
    }

    /// Number of source elements after the fixed `BytePack3LE` conversion.
    pub const fn input_elements(self) -> usize {
        P24_INTENT_COMMITMENT_INPUT_ELEMENTS
    }

    const fn label(self) -> &'static [u8] {
        INTENT_LABEL
    }
}

/// The canonical, unselected child of the frozen `NXPH` candidate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CandidatePoseidon2P24IntentCommitmentManifestV1;

impl CandidatePoseidon2P24IntentCommitmentManifestV1 {
    /// Returns the one canonical candidate for this framing version.
    pub const fn new() -> Self {
        Self
    }

    /// Encodes all framing, the full immediate parent, IV, and checksum.
    pub fn encode(self) -> Result<Vec<u8>, Poseidon2P24IntentCommitmentCandidateError> {
        let parent = CandidatePoseidon2P24NoteDomainsManifestV1::new();
        let parent_bytes = parent.encode()?;
        let parent_id = parent.candidate_id()?;
        let payload = self.payload()?;
        let mut manifest = Vec::with_capacity(P24_INTENT_COMMITMENT_MANIFEST_LENGTH);
        manifest.extend_from_slice(&MANIFEST_MAGIC);
        manifest.extend_from_slice(&MANIFEST_VERSION.to_be_bytes());
        manifest.push(CANDIDATE_KIND);
        manifest.push(FLAGS);
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
            1,
            IV_ELEMENTS as u8,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
        ]);
        debug_assert_eq!(manifest.len(), HEADER_LENGTH);
        manifest.extend_from_slice(&parent_bytes);
        append_descriptor(&mut manifest, &payload);
        manifest.extend_from_slice(&manifest_checksum(&manifest));
        debug_assert_eq!(manifest.len(), P24_INTENT_COMMITMENT_MANIFEST_LENGTH);
        Ok(manifest)
    }

    /// Decodes only byte-for-byte canonical `NXIC v1` candidate bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, Poseidon2P24IntentCommitmentCandidateError> {
        if bytes.len() != P24_INTENT_COMMITMENT_MANIFEST_LENGTH {
            return Err(
                Poseidon2P24IntentCommitmentCandidateError::InvalidManifestLength {
                    actual: bytes.len(),
                    expected: P24_INTENT_COMMITMENT_MANIFEST_LENGTH,
                },
            );
        }
        if bytes[..4] != MANIFEST_MAGIC {
            return Err(Poseidon2P24IntentCommitmentCandidateError::InvalidManifestMagic);
        }
        if bytes[4..6] != MANIFEST_VERSION.to_be_bytes() {
            return Err(Poseidon2P24IntentCommitmentCandidateError::UnsupportedManifestVersion);
        }
        if bytes[6] != CANDIDATE_KIND || bytes[7] != FLAGS {
            return Err(Poseidon2P24IntentCommitmentCandidateError::NonCanonicalManifest);
        }
        let checksum_offset = bytes.len() - CHECKSUM_LENGTH;
        if bytes[checksum_offset..] != manifest_checksum(&bytes[..checksum_offset]) {
            return Err(Poseidon2P24IntentCommitmentCandidateError::ManifestChecksumMismatch);
        }
        if bytes != Self::new().encode()? {
            return Err(Poseidon2P24IntentCommitmentCandidateError::NonCanonicalManifest);
        }
        Ok(Self)
    }

    /// Separate candidate identity; this is intentionally not a network parameter ID.
    pub fn candidate_id(
        self,
    ) -> Result<CandidatePoseidon2P24IntentCommitmentIdV1, Poseidon2P24IntentCommitmentCandidateError>
    {
        let mut hasher = Sha256::new();
        hasher.update(P24_INTENT_COMMITMENT_CANDIDATE_ID_DOMAIN);
        hasher.update(self.encode()?);
        Ok(CandidatePoseidon2P24IntentCommitmentIdV1(
            hasher.finalize().into(),
        ))
    }

    /// Returns the validated embedded IV payload.
    pub fn payload(self) -> Result<Vec<u8>, Poseidon2P24IntentCommitmentCandidateError> {
        let compact: String = PAYLOAD_BASE64
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect();
        let payload = STANDARD
            .decode(compact)
            .map_err(|_| Poseidon2P24IntentCommitmentCandidateError::InvalidEmbeddedBase64)?;
        validate_payload(&payload)?;
        Ok(payload)
    }

    /// Re-derives the sole fixed capacity IV from the complete parent identity.
    pub fn iv(
        self,
        domain: Poseidon2P24IntentCommitmentDomainV1,
    ) -> Result<[u32; IV_ELEMENTS], Poseidon2P24IntentCommitmentCandidateError> {
        let payload = self.payload()?;
        let stored = decode_iv(&payload);
        if stored != derive_iv(domain)? {
            return Err(Poseidon2P24IntentCommitmentCandidateError::InvalidDerivedIv);
        }
        Ok(stored)
    }
}

fn append_descriptor(manifest: &mut Vec<u8>, payload: &[u8]) {
    let domain = Poseidon2P24IntentCommitmentDomainV1::Intent;
    let label = domain.label();
    manifest.push(1);
    manifest.push(label.len() as u8);
    manifest.extend_from_slice(&(domain.input_bytes() as u16).to_be_bytes());
    manifest.push(domain.input_elements() as u8);
    manifest.extend_from_slice(label);
    manifest.extend_from_slice(payload);
}

fn validate_payload(payload: &[u8]) -> Result<(), Poseidon2P24IntentCommitmentCandidateError> {
    if payload.len() != P24_INTENT_COMMITMENT_PAYLOAD_LENGTH {
        return Err(
            Poseidon2P24IntentCommitmentCandidateError::InvalidPayloadLength {
                actual: payload.len(),
                expected: P24_INTENT_COMMITMENT_PAYLOAD_LENGTH,
            },
        );
    }
    let digest: [u8; 32] = Sha256::digest(payload).into();
    if digest != EXPECTED_PAYLOAD_SHA256 {
        return Err(Poseidon2P24IntentCommitmentCandidateError::PayloadChecksumMismatch);
    }
    for (index, chunk) in payload.chunks_exact(4).enumerate() {
        let value = u32::from_le_bytes(chunk.try_into().expect("fixed element width"));
        if value >= BABYBEAR_MODULUS {
            return Err(
                Poseidon2P24IntentCommitmentCandidateError::NonCanonicalFieldElement {
                    index,
                    value,
                },
            );
        }
    }
    if decode_iv(payload) != derive_iv(Poseidon2P24IntentCommitmentDomainV1::Intent)? {
        return Err(Poseidon2P24IntentCommitmentCandidateError::InvalidDerivedIv);
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
    domain: Poseidon2P24IntentCommitmentDomainV1,
) -> Result<[u32; IV_ELEMENTS], Poseidon2P24IntentCommitmentCandidateError> {
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

/// Candidate identity that cannot be mistaken for an approved network identity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CandidatePoseidon2P24IntentCommitmentIdV1([u8; 32]);

impl CandidatePoseidon2P24IntentCommitmentIdV1 {
    /// Returns canonical identity bytes.
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Display for CandidatePoseidon2P24IntentCommitmentIdV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Errors while reading the frozen `NXIC` candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Poseidon2P24IntentCommitmentCandidateError {
    Parent(Poseidon2P24NoteDomainsCandidateError),
    InvalidEmbeddedBase64,
    InvalidPayloadLength { actual: usize, expected: usize },
    PayloadChecksumMismatch,
    ManifestChecksumMismatch,
    NonCanonicalFieldElement { index: usize, value: u32 },
    InvalidDerivedIv,
    InvalidManifestLength { actual: usize, expected: usize },
    InvalidManifestMagic,
    UnsupportedManifestVersion,
    NonCanonicalManifest,
}

impl From<Poseidon2P24NoteDomainsCandidateError> for Poseidon2P24IntentCommitmentCandidateError {
    fn from(value: Poseidon2P24NoteDomainsCandidateError) -> Self {
        Self::Parent(value)
    }
}

impl fmt::Display for Poseidon2P24IntentCommitmentCandidateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parent(error) => write!(formatter, "invalid NXPH parent candidate: {error}"),
            Self::InvalidEmbeddedBase64 => {
                formatter.write_str("embedded intent-commitment payload is not base64")
            }
            Self::InvalidPayloadLength { actual, expected } => write!(
                formatter,
                "intent-commitment payload has {actual} bytes, expected {expected}"
            ),
            Self::PayloadChecksumMismatch => {
                formatter.write_str("intent-commitment payload checksum does not match")
            }
            Self::ManifestChecksumMismatch => {
                formatter.write_str("NXIC manifest checksum does not match")
            }
            Self::NonCanonicalFieldElement { index, value } => write!(
                formatter,
                "intent-commitment field element {index} is non-canonical: {value}"
            ),
            Self::InvalidDerivedIv => {
                formatter.write_str("intent-commitment IV differs from its prescribed derivation")
            }
            Self::InvalidManifestLength { actual, expected } => write!(
                formatter,
                "NXIC manifest has {actual} bytes, expected {expected}"
            ),
            Self::InvalidManifestMagic => formatter.write_str("invalid NXIC magic"),
            Self::UnsupportedManifestVersion => formatter.write_str("unsupported NXIC version"),
            Self::NonCanonicalManifest => {
                formatter.write_str("NXIC manifest differs from canonical bytes")
            }
        }
    }
}

impl std::error::Error for Poseidon2P24IntentCommitmentCandidateError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_and_iv_are_frozen_and_rederived() {
        let manifest = CandidatePoseidon2P24IntentCommitmentManifestV1::new();
        let payload = manifest.payload().unwrap();
        assert_eq!(payload.len(), P24_INTENT_COMMITMENT_PAYLOAD_LENGTH);
        assert_eq!(Sha256::digest(payload).as_slice(), EXPECTED_PAYLOAD_SHA256);
        assert_eq!(
            Poseidon2P24IntentCommitmentDomainV1::Intent.input_bytes(),
            640
        );
        assert_eq!(
            Poseidon2P24IntentCommitmentDomainV1::Intent.input_elements(),
            214
        );
        assert_eq!(
            manifest
                .iv(Poseidon2P24IntentCommitmentDomainV1::Intent)
                .unwrap()[0],
            1_819_200_036
        );
    }

    #[test]
    fn manifest_and_identity_are_frozen_and_reject_mutations() {
        let manifest = CandidatePoseidon2P24IntentCommitmentManifestV1::new();
        let canonical = manifest.encode().unwrap();
        assert_eq!(canonical.len(), P24_INTENT_COMMITMENT_MANIFEST_LENGTH);
        assert_eq!(
            Sha256::digest(&canonical).as_slice(),
            EXPECTED_MANIFEST_SHA256
        );
        assert_eq!(
            manifest.candidate_id().unwrap().as_bytes(),
            EXPECTED_CANDIDATE_ID
        );
        assert_eq!(
            CandidatePoseidon2P24IntentCommitmentManifestV1::decode(&canonical),
            Ok(manifest)
        );
        for index in [
            0,
            4,
            8,
            12,
            HEADER_LENGTH - 1,
            HEADER_LENGTH,
            canonical.len() - 1,
        ] {
            let mut changed = canonical.clone();
            changed[index] ^= 1;
            assert!(CandidatePoseidon2P24IntentCommitmentManifestV1::decode(&changed).is_err());
        }
    }
}
