//! NXNV v1 framing for the frozen P24 private-domain external KAT set.
//!
//! It is intentionally independent from NXTV: NXNV binds the NXPH private
//! domain candidate and verifies packed byte evidence, never tree vectors.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use noxis_privacy_types::{BABYBEAR_MODULUS, PrivacyTypesError};

use crate::{
    CandidatePoseidon2P24NoteDomainsManifestV1, P24_BYTE_PACK_WIDTH,
    P24_NOTE_DOMAINS_MANIFEST_LENGTH, P24TreeValueV2, P24TreeVectorV2Error,
    Poseidon2P24NoteDomainV1, Poseidon2P24NoteDomainsCandidateError,
};

/// Four-byte magic identifying private-domain evidence, not a tree corpus.
pub const P24_NOTE_VECTOR_MAGIC: [u8; 4] = *b"NXNV";
/// Version of the fixed NXNV framing.
pub const P24_NOTE_VECTOR_VERSION: u16 = 1;
/// Maximum accepted NXNV corpus size.
pub const P24_NOTE_VECTOR_LENGTH_LIMIT: usize = 16_384;
/// Header length including the full NXPH candidate artifact and its identity.
pub const P24_NOTE_VECTOR_HEADER_LENGTH: usize =
    4 + 2 + 2 + 2 + P24_NOTE_DOMAINS_MANIFEST_LENGTH + 32 + 2 + 2;

const FLAGS: u16 = 0;
const PROFILE_EXTERNAL_KATS: u16 = 1;
const RECORD_FLAGS: u8 = 0;
const RECORD_COUNT: usize = 6;
const FROZEN_BASE64: &str =
    include_str!("../fixtures/poseidon2_babybear_p24_private_domain_vectors_v1.base64");

/// One externally executed private-domain case in canonical form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P24NoteVectorRecordV1 {
    domain: Poseidon2P24NoteDomainV1,
    input: Vec<u8>,
    packed: Vec<u32>,
    digest: P24TreeValueV2,
}

impl P24NoteVectorRecordV1 {
    pub fn new(
        domain: Poseidon2P24NoteDomainV1,
        input: Vec<u8>,
        packed: Vec<u32>,
        digest: P24TreeValueV2,
    ) -> Result<Self, P24NoteVectorError> {
        validate_record_parts(domain, &input, &packed)?;
        Ok(Self {
            domain,
            input,
            packed,
            digest,
        })
    }

    pub const fn domain(&self) -> Poseidon2P24NoteDomainV1 {
        self.domain
    }
    pub fn input(&self) -> &[u8] {
        &self.input
    }
    pub fn packed(&self) -> &[u32] {
        &self.packed
    }
    pub const fn digest(&self) -> P24TreeValueV2 {
        self.digest
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(self.input.len() + self.packed.len() * 4 + 64);
        payload.extend_from_slice(&self.input);
        for element in &self.packed {
            payload.extend_from_slice(&element.to_le_bytes());
        }
        payload.extend_from_slice(&self.digest.as_bytes());
        let mut encoded = Vec::with_capacity(6 + payload.len());
        encoded.push(domain_tag(self.domain));
        encoded.push(RECORD_FLAGS);
        encoded.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&payload);
        encoded
    }
}

/// The closed six-case external KAT profile bound to the frozen NXPH manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P24NoteVectorCorpusV1 {
    records: Vec<P24NoteVectorRecordV1>,
}

impl P24NoteVectorCorpusV1 {
    pub fn new(mut records: Vec<P24NoteVectorRecordV1>) -> Result<Self, P24NoteVectorError> {
        if records.len() != RECORD_COUNT {
            return Err(P24NoteVectorError::InvalidCoverage);
        }
        records.sort_by_key(P24NoteVectorRecordV1::canonical_bytes);
        if records
            .windows(2)
            .any(|pair| pair[0].canonical_bytes() == pair[1].canonical_bytes())
        {
            return Err(P24NoteVectorError::DuplicateRecord);
        }
        validate_coverage(&records)?;
        Ok(Self { records })
    }

    pub fn records(&self) -> &[P24NoteVectorRecordV1] {
        &self.records
    }

    pub fn frozen_external_kat_corpus() -> Self {
        let compact: String = FROZEN_BASE64
            .chars()
            .filter(|value| !value.is_whitespace())
            .collect();
        let bytes = STANDARD
            .decode(compact)
            .expect("frozen NXNV base64 is valid");
        Self::decode(&bytes).expect("frozen NXNV bytes are canonical")
    }

    pub fn encode(&self) -> Result<Vec<u8>, P24NoteVectorError> {
        let manifest = CandidatePoseidon2P24NoteDomainsManifestV1::new();
        let manifest_bytes = manifest.encode()?;
        let candidate_id = manifest.candidate_id()?;
        let mut bytes = Vec::with_capacity(P24_NOTE_VECTOR_HEADER_LENGTH + 2_024);
        bytes.extend_from_slice(&P24_NOTE_VECTOR_MAGIC);
        bytes.extend_from_slice(&P24_NOTE_VECTOR_VERSION.to_be_bytes());
        bytes.extend_from_slice(&FLAGS.to_be_bytes());
        bytes.extend_from_slice(&(P24_NOTE_DOMAINS_MANIFEST_LENGTH as u16).to_be_bytes());
        bytes.extend_from_slice(&manifest_bytes);
        bytes.extend_from_slice(&candidate_id.as_bytes());
        bytes.extend_from_slice(&PROFILE_EXTERNAL_KATS.to_be_bytes());
        bytes.extend_from_slice(&(self.records.len() as u16).to_be_bytes());
        for record in &self.records {
            bytes.extend_from_slice(&record.canonical_bytes());
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, P24NoteVectorError> {
        if bytes.len() > P24_NOTE_VECTOR_LENGTH_LIMIT {
            return Err(P24NoteVectorError::CorpusTooLarge(bytes.len()));
        }
        let mut reader = Reader::new(bytes);
        if reader.array::<4>()? != P24_NOTE_VECTOR_MAGIC {
            return Err(P24NoteVectorError::InvalidMagic);
        }
        if reader.u16()? != P24_NOTE_VECTOR_VERSION {
            return Err(P24NoteVectorError::UnsupportedVersion);
        }
        if reader.u16()? != FLAGS {
            return Err(P24NoteVectorError::NonCanonicalHeader);
        }
        if reader.u16()? as usize != P24_NOTE_DOMAINS_MANIFEST_LENGTH {
            return Err(P24NoteVectorError::InvalidManifestLength);
        }
        let manifest = reader.bytes(P24_NOTE_DOMAINS_MANIFEST_LENGTH)?;
        CandidatePoseidon2P24NoteDomainsManifestV1::decode(manifest)?;
        let expected_id = CandidatePoseidon2P24NoteDomainsManifestV1::new()
            .candidate_id()?
            .as_bytes();
        if reader.array::<32>()? != expected_id {
            return Err(P24NoteVectorError::ManifestIdentityMismatch);
        }
        if reader.u16()? != PROFILE_EXTERNAL_KATS || reader.u16()? as usize != RECORD_COUNT {
            return Err(P24NoteVectorError::InvalidCoverage);
        }
        let mut records = Vec::with_capacity(RECORD_COUNT);
        for _ in 0..RECORD_COUNT {
            records.push(decode_record(&mut reader)?);
        }
        if !reader.finished() {
            return Err(P24NoteVectorError::TrailingBytes);
        }
        let corpus = Self::new(records)?;
        if corpus.encode()? != bytes {
            return Err(P24NoteVectorError::NonCanonicalRecordOrder);
        }
        Ok(corpus)
    }
}

fn domain_tag(domain: Poseidon2P24NoteDomainV1) -> u8 {
    match domain {
        Poseidon2P24NoteDomainV1::Addr => 1,
        Poseidon2P24NoteDomainV1::Note => 2,
        Poseidon2P24NoteDomainV1::Nullifier => 3,
    }
}
fn domain_from_tag(tag: u8) -> Result<Poseidon2P24NoteDomainV1, P24NoteVectorError> {
    match tag {
        1 => Ok(Poseidon2P24NoteDomainV1::Addr),
        2 => Ok(Poseidon2P24NoteDomainV1::Note),
        3 => Ok(Poseidon2P24NoteDomainV1::Nullifier),
        _ => Err(P24NoteVectorError::UnsupportedDomain(tag)),
    }
}

fn decode_record(reader: &mut Reader<'_>) -> Result<P24NoteVectorRecordV1, P24NoteVectorError> {
    let domain = domain_from_tag(reader.u8()?)?;
    if reader.u8()? != RECORD_FLAGS {
        return Err(P24NoteVectorError::NonCanonicalRecordFlags);
    }
    let payload_length = reader.u32()? as usize;
    let payload = reader.bytes(payload_length)?;
    let expected = domain.input_bytes() + domain.input_elements() * 4 + 64;
    if payload.len() != expected {
        return Err(P24NoteVectorError::InvalidRecordLength);
    }
    let input = payload[..domain.input_bytes()].to_vec();
    let packed_offset = domain.input_bytes();
    let packed = payload[packed_offset..packed_offset + domain.input_elements() * 4]
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("word width")))
        .collect();
    let digest = P24TreeValueV2::new(
        payload[payload.len() - 64..]
            .try_into()
            .expect("fixed digest"),
    )?;
    P24NoteVectorRecordV1::new(domain, input, packed, digest)
}

fn validate_record_parts(
    domain: Poseidon2P24NoteDomainV1,
    input: &[u8],
    packed: &[u32],
) -> Result<(), P24NoteVectorError> {
    if input.len() != domain.input_bytes() || packed.len() != domain.input_elements() {
        return Err(P24NoteVectorError::InvalidRecordLength);
    }
    let expected = byte_pack3le(input);
    if packed != expected {
        return Err(P24NoteVectorError::PackingMismatch);
    }
    if packed.iter().any(|value| *value >= BABYBEAR_MODULUS) {
        return Err(P24NoteVectorError::NonCanonicalPackedElement);
    }
    Ok(())
}

fn byte_pack3le(input: &[u8]) -> Vec<u32> {
    input
        .chunks(P24_BYTE_PACK_WIDTH)
        .map(|chunk| {
            chunk
                .iter()
                .enumerate()
                .fold(0_u32, |value, (offset, byte)| {
                    value | (u32::from(*byte) << (offset * 8))
                })
        })
        .collect()
}

fn validate_coverage(records: &[P24NoteVectorRecordV1]) -> Result<(), P24NoteVectorError> {
    for domain in [
        Poseidon2P24NoteDomainV1::Addr,
        Poseidon2P24NoteDomainV1::Note,
        Poseidon2P24NoteDomainV1::Nullifier,
    ] {
        let expected = known_inputs(domain);
        let actual: Vec<&[u8]> = records
            .iter()
            .filter(|record| record.domain == domain)
            .map(|record| record.input())
            .collect();
        if actual.len() != 2
            || !expected
                .iter()
                .all(|input| actual.contains(&input.as_slice()))
        {
            return Err(P24NoteVectorError::InvalidCoverage);
        }
    }
    Ok(())
}

fn known_inputs(domain: Poseidon2P24NoteDomainV1) -> [Vec<u8>; 2] {
    match domain {
        Poseidon2P24NoteDomainV1::Addr => [
            (0_u8..32).collect(),
            (0..32).map(|index| 255_u8 - index).collect(),
        ],
        Poseidon2P24NoteDomainV1::Note => [
            (0_u8..178).collect(),
            (0..178)
                .map(|index| 17_u8.wrapping_add(31_u8.wrapping_mul(index as u8)))
                .collect(),
        ],
        Poseidon2P24NoteDomainV1::Nullifier => {
            let mut zero: Vec<u8> = (0_u8..128).collect();
            zero.extend_from_slice(&0_u32.to_be_bytes());
            let mut maximum = Vec::with_capacity(132);
            maximum.extend(160_u8..192);
            maximum.extend(96_u8..128);
            maximum.extend((192_u8..=255).rev());
            maximum.extend_from_slice(&u32::MAX.to_be_bytes());
            [zero, maximum]
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn bytes(&mut self, length: usize) -> Result<&'a [u8], P24NoteVectorError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(P24NoteVectorError::Truncated)?;
        let output = self
            .bytes
            .get(self.offset..end)
            .ok_or(P24NoteVectorError::Truncated)?;
        self.offset = end;
        Ok(output)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], P24NoteVectorError> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| P24NoteVectorError::Truncated)
    }
    fn u8(&mut self) -> Result<u8, P24NoteVectorError> {
        Ok(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, P24NoteVectorError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, P24NoteVectorError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

/// Errors while framing the closed NXNV external KAT profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum P24NoteVectorError {
    Candidate(Poseidon2P24NoteDomainsCandidateError),
    InvalidDigest(PrivacyTypesError),
    VectorValue(P24TreeVectorV2Error),
    InvalidMagic,
    UnsupportedVersion,
    NonCanonicalHeader,
    InvalidManifestLength,
    ManifestIdentityMismatch,
    CorpusTooLarge(usize),
    UnsupportedDomain(u8),
    NonCanonicalRecordFlags,
    InvalidRecordLength,
    NonCanonicalPackedElement,
    PackingMismatch,
    InvalidCoverage,
    DuplicateRecord,
    NonCanonicalRecordOrder,
    Truncated,
    TrailingBytes,
}
impl From<Poseidon2P24NoteDomainsCandidateError> for P24NoteVectorError {
    fn from(value: Poseidon2P24NoteDomainsCandidateError) -> Self {
        Self::Candidate(value)
    }
}
impl From<PrivacyTypesError> for P24NoteVectorError {
    fn from(value: PrivacyTypesError) -> Self {
        Self::InvalidDigest(value)
    }
}
impl From<P24TreeVectorV2Error> for P24NoteVectorError {
    fn from(value: P24TreeVectorV2Error) -> Self {
        Self::VectorValue(value)
    }
}
impl fmt::Display for P24NoteVectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "NXNV v1 error: {self:?}")
    }
}
impl std::error::Error for P24NoteVectorError {}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    #[test]
    fn frozen_external_kats_round_trip_and_are_stable() {
        let corpus = P24NoteVectorCorpusV1::frozen_external_kat_corpus();
        assert_eq!(corpus.records().len(), 6);
        let encoded = corpus.encode().unwrap();
        assert_eq!(encoded.len(), 10_050);
        assert_eq!(
            format!("{:x}", Sha256::digest(&encoded)),
            "7d59452e61c2245b7c8f9e81279734fcb7ce51bdd8fe01e7764095f13d2b5827"
        );
        assert_eq!(P24NoteVectorCorpusV1::decode(&encoded), Ok(corpus));
    }
}
