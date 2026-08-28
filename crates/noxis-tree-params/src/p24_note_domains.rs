//! Frozen, unselected Poseidon2-BabyBear-P24 private-note domain candidate.
//!
//! This artifact extends the *identity* of the P24 tree candidate without
//! altering its manifest, parameters, or tree corpus. It supplies only three
//! rederivable capacity IVs; it is not an active note hash or proof backend.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use noxis_privacy_types::BABYBEAR_MODULUS;
use sha2::{Digest, Sha256};

use crate::{
    CandidatePoseidon2P24ManifestV2, P24_CANDIDATE_MANIFEST_LENGTH, Poseidon2P24CandidateError,
};

/// SHA-256 domain for the private-note-domain candidate identity.
pub const P24_NOTE_DOMAINS_CANDIDATE_ID_DOMAIN: &[u8] =
    b"NOXIS/POSEIDON2-PRIVACY-HASH-CANDIDATE-ID/V1\0";
/// Exact size of the three stored nine-element capacity IVs.
pub const P24_NOTE_DOMAINS_PAYLOAD_LENGTH: usize = 108;
/// Exact size of the canonical `NXPH v1` candidate manifest.
pub const P24_NOTE_DOMAINS_MANIFEST_LENGTH: usize = 7_980;
/// Number of source bytes carried by one canonical `BytePack3LE` element.
pub const P24_BYTE_PACK_WIDTH: usize = 3;

const MANIFEST_MAGIC: [u8; 4] = *b"NXPH";
const MANIFEST_VERSION: u16 = 1;
const CANDIDATE_KIND: u8 = 1;
const FLAGS: u8 = 0;
const KDF_PROFILE: u8 = 1;
const SPONGE_PROFILE: u8 = 1;
const BYTE_PACK_PROFILE: u8 = 1;
const LAST_GROUP_ZERO_PADDING: u8 = 1;
const SQUEEZE_PROFILE: u8 = 1;
const SHA256_PROFILE: u8 = 1;
const DESCRIPTOR_VERSION: u8 = 1;
const DOMAIN_COUNT: u8 = 3;
const DIGEST_ELEMENTS: u8 = 16;
const RATE: u8 = 15;
const CAPACITY: u8 = 9;
const HEADER_LENGTH: usize = 64;
const CHECKSUM_LENGTH: usize = 32;
const CHECKSUM_DOMAIN: &[u8] = b"NOXIS/POSEIDON2-PRIVACY-HASH-MANIFEST-CHECKSUM/V1\0";
const IV_ELEMENTS: usize = 9;
const IV_KDF_PREFIX: &[u8] = b"NOXIS/POSEIDON2-PRIVACY-HASH-IV/V1\0";
const PAYLOAD_BASE64: &str =
    include_str!("../fixtures/poseidon2_babybear_p24_note_domains_candidate_v1.base64");
const EXPECTED_PAYLOAD_SHA256: [u8; 32] = [
    0xd1, 0xec, 0x18, 0xbc, 0x78, 0xac, 0x13, 0xaa, 0xd2, 0xed, 0xd6, 0xa0, 0xe9, 0x99, 0x18, 0xa1,
    0xff, 0xb8, 0x96, 0x4b, 0x0e, 0xad, 0x25, 0x77, 0x30, 0xfa, 0xbd, 0xa2, 0xfa, 0x8d, 0xf0, 0x9c,
];
#[cfg(test)]
const EXPECTED_CANDIDATE_ID: [u8; 32] = [
    0x57, 0xe2, 0x27, 0xfd, 0x9d, 0x4c, 0xbc, 0xc6, 0x97, 0x19, 0x03, 0x72, 0xb8, 0x98, 0x3d, 0x2b,
    0xdc, 0x5e, 0x33, 0x94, 0x17, 0x75, 0x10, 0xee, 0xa5, 0x4f, 0x9f, 0x90, 0xf3, 0x63, 0x4b, 0x8e,
];

/// One of the fixed private-note functions in the candidate extension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Poseidon2P24NoteDomainV1 {
    Addr,
    Note,
    Nullifier,
}

impl Poseidon2P24NoteDomainV1 {
    /// Source input length fixed by this domain's candidate rule.
    pub const fn input_bytes(self) -> usize {
        match self {
            Self::Addr => 32,
            Self::Note => 178,
            Self::Nullifier => 132,
        }
    }

    /// Number of `BytePack3LE` elements absorbed by this domain.
    pub const fn input_elements(self) -> usize {
        self.input_bytes().div_ceil(P24_BYTE_PACK_WIDTH)
    }

    const fn label(self) -> &'static [u8] {
        match self {
            Self::Addr => b"NOXIS/POSEIDON2-PRIVACY/V1/ADDR\0",
            Self::Note => b"NOXIS/POSEIDON2-PRIVACY/V1/NOTE\0",
            Self::Nullifier => b"NOXIS/POSEIDON2-PRIVACY/V1/NULLIFIER\0",
        }
    }

    const fn payload_index(self) -> usize {
        match self {
            Self::Addr => 0,
            Self::Note => 1,
            Self::Nullifier => 2,
        }
    }
}

/// The sole canonical candidate that extends the frozen P24 tree artifact.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CandidatePoseidon2P24NoteDomainsManifestV1;

impl CandidatePoseidon2P24NoteDomainsManifestV1 {
    /// Returns the fixed, unselected candidate.
    pub const fn new() -> Self {
        Self
    }

    /// Encodes the complete canonical `NXPH v1` artifact.
    pub fn encode(self) -> Result<Vec<u8>, Poseidon2P24NoteDomainsCandidateError> {
        let parent = CandidatePoseidon2P24ManifestV2::new();
        let parent_bytes = parent.encode()?;
        let parent_id = parent.candidate_id()?;
        let payload = self.payload()?;
        let mut manifest = Vec::with_capacity(P24_NOTE_DOMAINS_MANIFEST_LENGTH);
        manifest.extend_from_slice(&MANIFEST_MAGIC);
        manifest.extend_from_slice(&MANIFEST_VERSION.to_be_bytes());
        manifest.push(CANDIDATE_KIND);
        manifest.push(FLAGS);
        manifest.extend_from_slice(&(P24_CANDIDATE_MANIFEST_LENGTH as u16).to_be_bytes());
        manifest.extend_from_slice(&parent_id.as_bytes());
        manifest.extend_from_slice(&[
            1,
            1,
            DIGEST_ELEMENTS,
            24,
            RATE,
            CAPACITY,
            SPONGE_PROFILE,
            BYTE_PACK_PROFILE,
            P24_BYTE_PACK_WIDTH as u8,
            LAST_GROUP_ZERO_PADDING,
            SQUEEZE_PROFILE,
            KDF_PROFILE,
            SHA256_PROFILE,
            DOMAIN_COUNT,
            IV_ELEMENTS as u8,
            DESCRIPTOR_VERSION,
            0,
            0,
            0,
            0,
            0,
            0,
        ]);
        debug_assert_eq!(manifest.len(), HEADER_LENGTH);
        manifest.extend_from_slice(&parent_bytes);
        for domain in [
            Poseidon2P24NoteDomainV1::Addr,
            Poseidon2P24NoteDomainV1::Note,
            Poseidon2P24NoteDomainV1::Nullifier,
        ] {
            append_descriptor(&mut manifest, domain, &payload);
        }
        let checksum = manifest_checksum(&manifest);
        manifest.extend_from_slice(&checksum);
        debug_assert_eq!(manifest.len(), P24_NOTE_DOMAINS_MANIFEST_LENGTH);
        Ok(manifest)
    }

    /// Decodes only the exact frozen candidate bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, Poseidon2P24NoteDomainsCandidateError> {
        if bytes.len() != P24_NOTE_DOMAINS_MANIFEST_LENGTH {
            return Err(
                Poseidon2P24NoteDomainsCandidateError::InvalidManifestLength {
                    actual: bytes.len(),
                    expected: P24_NOTE_DOMAINS_MANIFEST_LENGTH,
                },
            );
        }
        if bytes[..4] != MANIFEST_MAGIC {
            return Err(Poseidon2P24NoteDomainsCandidateError::InvalidManifestMagic);
        }
        if bytes[4..6] != MANIFEST_VERSION.to_be_bytes() {
            return Err(Poseidon2P24NoteDomainsCandidateError::UnsupportedManifestVersion);
        }
        if bytes[6] != CANDIDATE_KIND || bytes[7] != FLAGS {
            return Err(Poseidon2P24NoteDomainsCandidateError::NonCanonicalManifest);
        }
        let checksum_offset = bytes.len() - CHECKSUM_LENGTH;
        if bytes[checksum_offset..] != manifest_checksum(&bytes[..checksum_offset]) {
            return Err(Poseidon2P24NoteDomainsCandidateError::ManifestChecksumMismatch);
        }
        if bytes != Self::new().encode()? {
            return Err(Poseidon2P24NoteDomainsCandidateError::NonCanonicalManifest);
        }
        Ok(Self)
    }

    /// Returns this candidate's separate, non-allowlisted identity.
    pub fn candidate_id(
        self,
    ) -> Result<CandidatePoseidon2P24NoteDomainsIdV1, Poseidon2P24NoteDomainsCandidateError> {
        let manifest = self.encode()?;
        let mut hasher = Sha256::new();
        hasher.update(P24_NOTE_DOMAINS_CANDIDATE_ID_DOMAIN);
        hasher.update(manifest);
        Ok(CandidatePoseidon2P24NoteDomainsIdV1(
            hasher.finalize().into(),
        ))
    }

    /// Returns the validated raw IV payload in canonical domain order.
    pub fn payload(self) -> Result<Vec<u8>, Poseidon2P24NoteDomainsCandidateError> {
        let compact: String = PAYLOAD_BASE64
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect();
        let payload = STANDARD
            .decode(compact)
            .map_err(|_| Poseidon2P24NoteDomainsCandidateError::InvalidEmbeddedBase64)?;
        validate_payload(&payload)?;
        Ok(payload)
    }

    /// Re-derives and checks one fixed capacity IV.
    pub fn iv(
        self,
        domain: Poseidon2P24NoteDomainV1,
    ) -> Result<[u32; IV_ELEMENTS], Poseidon2P24NoteDomainsCandidateError> {
        let payload = self.payload()?;
        let offset = domain.payload_index() * IV_ELEMENTS * 4;
        let stored = decode_iv(&payload[offset..offset + IV_ELEMENTS * 4]);
        if stored != derive_iv(domain)? {
            return Err(Poseidon2P24NoteDomainsCandidateError::InvalidDerivedIv { domain });
        }
        Ok(stored)
    }
}

fn validate_payload(payload: &[u8]) -> Result<(), Poseidon2P24NoteDomainsCandidateError> {
    if payload.len() != P24_NOTE_DOMAINS_PAYLOAD_LENGTH {
        return Err(
            Poseidon2P24NoteDomainsCandidateError::InvalidPayloadLength {
                actual: payload.len(),
                expected: P24_NOTE_DOMAINS_PAYLOAD_LENGTH,
            },
        );
    }
    let digest: [u8; 32] = Sha256::digest(payload).into();
    if digest != EXPECTED_PAYLOAD_SHA256 {
        return Err(Poseidon2P24NoteDomainsCandidateError::PayloadChecksumMismatch);
    }
    for (index, chunk) in payload.chunks_exact(4).enumerate() {
        let value = u32::from_le_bytes(chunk.try_into().expect("fixed element width"));
        if value >= BABYBEAR_MODULUS {
            return Err(
                Poseidon2P24NoteDomainsCandidateError::NonCanonicalFieldElement { index, value },
            );
        }
    }
    for domain in [
        Poseidon2P24NoteDomainV1::Addr,
        Poseidon2P24NoteDomainV1::Note,
        Poseidon2P24NoteDomainV1::Nullifier,
    ] {
        let offset = domain.payload_index() * IV_ELEMENTS * 4;
        if decode_iv(&payload[offset..offset + IV_ELEMENTS * 4]) != derive_iv(domain)? {
            return Err(Poseidon2P24NoteDomainsCandidateError::InvalidDerivedIv { domain });
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

fn append_descriptor(manifest: &mut Vec<u8>, domain: Poseidon2P24NoteDomainV1, payload: &[u8]) {
    let label = domain.label();
    manifest.push(domain.payload_index() as u8 + 1);
    manifest.push(label.len() as u8);
    manifest.extend_from_slice(&(domain.input_bytes() as u16).to_be_bytes());
    manifest.push(domain.input_elements() as u8);
    manifest.extend_from_slice(label);
    let offset = domain.payload_index() * IV_ELEMENTS * 4;
    manifest.extend_from_slice(&payload[offset..offset + IV_ELEMENTS * 4]);
}

fn manifest_checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CHECKSUM_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn derive_iv(
    domain: Poseidon2P24NoteDomainV1,
) -> Result<[u32; IV_ELEMENTS], Poseidon2P24NoteDomainsCandidateError> {
    let parent_id = CandidatePoseidon2P24ManifestV2::new().candidate_id()?;
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

/// Candidate identity that cannot be used as an approved parameter identity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CandidatePoseidon2P24NoteDomainsIdV1([u8; 32]);

impl CandidatePoseidon2P24NoteDomainsIdV1 {
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Display for CandidatePoseidon2P24NoteDomainsIdV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Errors while reading the frozen private-note-domain candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Poseidon2P24NoteDomainsCandidateError {
    Parent(Poseidon2P24CandidateError),
    InvalidEmbeddedBase64,
    InvalidPayloadLength { actual: usize, expected: usize },
    PayloadChecksumMismatch,
    ManifestChecksumMismatch,
    NonCanonicalFieldElement { index: usize, value: u32 },
    InvalidDerivedIv { domain: Poseidon2P24NoteDomainV1 },
    InvalidManifestLength { actual: usize, expected: usize },
    InvalidManifestMagic,
    UnsupportedManifestVersion,
    NonCanonicalManifest,
}

impl From<Poseidon2P24CandidateError> for Poseidon2P24NoteDomainsCandidateError {
    fn from(value: Poseidon2P24CandidateError) -> Self {
        Self::Parent(value)
    }
}

impl fmt::Display for Poseidon2P24NoteDomainsCandidateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parent(error) => write!(formatter, "invalid P24 parent candidate: {error}"),
            Self::InvalidEmbeddedBase64 => {
                formatter.write_str("embedded private-note-domain payload is not base64")
            }
            Self::InvalidPayloadLength { actual, expected } => write!(
                formatter,
                "private-note-domain payload has {actual} bytes, expected {expected}"
            ),
            Self::PayloadChecksumMismatch => {
                formatter.write_str("private-note-domain payload checksum does not match")
            }
            Self::ManifestChecksumMismatch => {
                formatter.write_str("NXPH manifest checksum does not match")
            }
            Self::NonCanonicalFieldElement { index, value } => write!(
                formatter,
                "private-note-domain field element {index} is non-canonical: {value}"
            ),
            Self::InvalidDerivedIv { domain } => write!(
                formatter,
                "private-note-domain IV for {domain:?} differs from its prescribed derivation"
            ),
            Self::InvalidManifestLength { actual, expected } => write!(
                formatter,
                "private-note-domain manifest has {actual} bytes, expected {expected}"
            ),
            Self::InvalidManifestMagic => formatter.write_str("invalid NXPH magic"),
            Self::UnsupportedManifestVersion => formatter.write_str("unsupported NXPH version"),
            Self::NonCanonicalManifest => {
                formatter.write_str("NXPH manifest differs from canonical bytes")
            }
        }
    }
}

impl std::error::Error for Poseidon2P24NoteDomainsCandidateError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_and_domain_ivs_are_frozen_and_rederived() {
        let manifest = CandidatePoseidon2P24NoteDomainsManifestV1::new();
        let payload = manifest.payload().unwrap();
        assert_eq!(payload.len(), P24_NOTE_DOMAINS_PAYLOAD_LENGTH);
        assert_eq!(Sha256::digest(payload).as_slice(), EXPECTED_PAYLOAD_SHA256);
        assert_eq!(Poseidon2P24NoteDomainV1::Addr.input_elements(), 11);
        assert_eq!(Poseidon2P24NoteDomainV1::Note.input_elements(), 60);
        assert_eq!(Poseidon2P24NoteDomainV1::Nullifier.input_elements(), 44);
        assert_eq!(
            manifest.iv(Poseidon2P24NoteDomainV1::Addr).unwrap()[0],
            1_853_478_823
        );
        assert_eq!(
            manifest.iv(Poseidon2P24NoteDomainV1::Note).unwrap()[0],
            1_926_189_073
        );
        assert_eq!(
            manifest.iv(Poseidon2P24NoteDomainV1::Nullifier).unwrap()[0],
            1_717_594_402
        );
    }

    #[test]
    fn manifest_and_identity_are_frozen_and_reject_mutations() {
        let manifest = CandidatePoseidon2P24NoteDomainsManifestV1::new();
        let canonical = manifest.encode().unwrap();
        assert_eq!(canonical.len(), P24_NOTE_DOMAINS_MANIFEST_LENGTH);
        assert_eq!(
            Sha256::digest(&canonical).as_slice(),
            [
                0xbb, 0xcb, 0x4a, 0xda, 0xb8, 0x62, 0x78, 0x16, 0xa2, 0x77, 0x24, 0x7a, 0x47, 0x21,
                0xa8, 0x7f, 0x85, 0x16, 0x7a, 0x1b, 0x8c, 0x41, 0x75, 0xb5, 0xa3, 0x2f, 0xb4, 0x81,
                0x5a, 0x9d, 0x3e, 0x4c,
            ]
        );
        assert_eq!(
            manifest.candidate_id().unwrap().as_bytes(),
            EXPECTED_CANDIDATE_ID
        );
        assert_eq!(
            CandidatePoseidon2P24NoteDomainsManifestV1::decode(&canonical),
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
            assert!(CandidatePoseidon2P24NoteDomainsManifestV1::decode(&changed).is_err());
        }
    }
}
