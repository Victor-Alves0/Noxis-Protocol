//! NXIV v1 framing for external `H_INTENT` candidate evidence.
//!
//! The corpus is closed: it binds the complete `NXIC` parent and exactly two
//! independently produced, structurally valid private-transfer intent vectors.

use std::fmt;

use noxis_privacy_types::{
    PrivacyTypesError, PrivateTransferIntentCommitmentV2, PrivateTransferIntentV2,
};

use crate::{
    CandidatePoseidon2P24IntentCommitmentManifestV1, P24_BYTE_PACK_WIDTH,
    P24_INTENT_COMMITMENT_INPUT_BYTES, P24_INTENT_COMMITMENT_INPUT_ELEMENTS,
    P24_INTENT_COMMITMENT_MANIFEST_LENGTH, Poseidon2P24IntentCommitmentCandidateError,
};

/// Four-byte magic identifying candidate intent-vector evidence.
pub const P24_INTENT_VECTOR_MAGIC: [u8; 4] = *b"NXIV";
/// Version of the closed candidate evidence framing.
pub const P24_INTENT_VECTOR_VERSION: u16 = 1;
/// Exact encoded size of the fixed two-record corpus.
pub const P24_INTENT_VECTOR_LENGTH: usize = 11_340;
/// Maximum accepted encoded size, checked before parsing.
pub const P24_INTENT_VECTOR_LENGTH_LIMIT: usize = 12_288;
/// Header length including the full NXIC artifact and its identity.
pub const P24_INTENT_VECTOR_HEADER_LENGTH: usize =
    4 + 2 + 2 + 2 + P24_INTENT_COMMITMENT_MANIFEST_LENGTH + 32 + 2 + 2;

const FLAGS: u16 = 0;
const PROFILE_EXTERNAL_KATS: u16 = 1;
const RECORD_FLAGS: u8 = 0;
const RECORD_COUNT: usize = 2;
const RECORD_PAYLOAD_LENGTH: usize = P24_INTENT_COMMITMENT_INPUT_BYTES
    + P24_INTENT_COMMITMENT_INPUT_ELEMENTS * 4
    + PrivateTransferIntentCommitmentV2::LENGTH;
const RECORD_LENGTH: usize = 6 + RECORD_PAYLOAD_LENGTH;

/// The role of a closed external KAT record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum P24IntentVectorCaseV1 {
    StructuralBaseline,
    BoundaryElements,
}

impl P24IntentVectorCaseV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::StructuralBaseline => 1,
            Self::BoundaryElements => 2,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, P24IntentVectorError> {
        match tag {
            1 => Ok(Self::StructuralBaseline),
            2 => Ok(Self::BoundaryElements),
            _ => Err(P24IntentVectorError::UnsupportedCase(tag)),
        }
    }
}

/// One externally calculated `H_INTENT` KAT in its canonical transport form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P24IntentVectorRecordV1 {
    case: P24IntentVectorCaseV1,
    intent: [u8; P24_INTENT_COMMITMENT_INPUT_BYTES],
    packed: [u32; P24_INTENT_COMMITMENT_INPUT_ELEMENTS],
    digest: PrivateTransferIntentCommitmentV2,
}

impl P24IntentVectorRecordV1 {
    /// Constructs a record only if its input is canonical and packing agrees.
    pub fn new(
        case: P24IntentVectorCaseV1,
        intent: [u8; P24_INTENT_COMMITMENT_INPUT_BYTES],
        packed: [u32; P24_INTENT_COMMITMENT_INPUT_ELEMENTS],
        digest: PrivateTransferIntentCommitmentV2,
    ) -> Result<Self, P24IntentVectorError> {
        let decoded = PrivateTransferIntentV2::decode(&intent)?;
        if decoded.encode() != intent {
            return Err(P24IntentVectorError::NonCanonicalIntent);
        }
        if packed != byte_pack3le(&intent) {
            return Err(P24IntentVectorError::PackingMismatch);
        }
        Ok(Self {
            case,
            intent,
            packed,
            digest,
        })
    }

    pub const fn case(&self) -> P24IntentVectorCaseV1 {
        self.case
    }
    pub const fn intent(&self) -> &[u8; P24_INTENT_COMMITMENT_INPUT_BYTES] {
        &self.intent
    }
    pub const fn packed(&self) -> &[u32; P24_INTENT_COMMITMENT_INPUT_ELEMENTS] {
        &self.packed
    }
    pub const fn digest(&self) -> PrivateTransferIntentCommitmentV2 {
        self.digest
    }

    fn canonical_bytes(&self) -> [u8; RECORD_LENGTH] {
        let mut bytes = [0_u8; RECORD_LENGTH];
        bytes[0] = self.case.tag();
        bytes[1] = RECORD_FLAGS;
        bytes[2..6].copy_from_slice(&(RECORD_PAYLOAD_LENGTH as u32).to_be_bytes());
        bytes[6..6 + P24_INTENT_COMMITMENT_INPUT_BYTES].copy_from_slice(&self.intent);
        let packed_offset = 6 + P24_INTENT_COMMITMENT_INPUT_BYTES;
        for (index, element) in self.packed.iter().enumerate() {
            bytes[packed_offset + index * 4..packed_offset + (index + 1) * 4]
                .copy_from_slice(&element.to_le_bytes());
        }
        bytes[packed_offset + self.packed.len() * 4..].copy_from_slice(&self.digest.as_bytes());
        bytes
    }
}

/// The exact two-case external KAT profile bound to the frozen NXIC candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P24IntentVectorCorpusV1 {
    records: [P24IntentVectorRecordV1; RECORD_COUNT],
}

impl P24IntentVectorCorpusV1 {
    /// Builds the closed corpus; any different case, input, packing or digest fails.
    pub fn new(
        mut records: [P24IntentVectorRecordV1; RECORD_COUNT],
    ) -> Result<Self, P24IntentVectorError> {
        records.sort_by_key(P24IntentVectorRecordV1::canonical_bytes);
        if records[0].case == records[1].case {
            return Err(P24IntentVectorError::DuplicateCase);
        }
        let corpus = Self { records };
        corpus.validate_closed_profile()?;
        Ok(corpus)
    }

    /// Returns the exact two externally produced candidate records.
    pub fn frozen_external_kat_corpus() -> Self {
        let records = [
            known_record(P24IntentVectorCaseV1::StructuralBaseline),
            known_record(P24IntentVectorCaseV1::BoundaryElements),
        ];
        Self::new(records).expect("fixed NXIV records are canonical")
    }

    pub fn records(&self) -> &[P24IntentVectorRecordV1; RECORD_COUNT] {
        &self.records
    }

    /// Encodes full NXIC provenance and the exact KAT record order.
    pub fn encode(&self) -> Result<Vec<u8>, P24IntentVectorError> {
        let manifest = CandidatePoseidon2P24IntentCommitmentManifestV1::new();
        let manifest_bytes = manifest.encode()?;
        let candidate_id = manifest.candidate_id()?;
        let mut bytes = Vec::with_capacity(P24_INTENT_VECTOR_LENGTH);
        bytes.extend_from_slice(&P24_INTENT_VECTOR_MAGIC);
        bytes.extend_from_slice(&P24_INTENT_VECTOR_VERSION.to_be_bytes());
        bytes.extend_from_slice(&FLAGS.to_be_bytes());
        bytes.extend_from_slice(&(P24_INTENT_COMMITMENT_MANIFEST_LENGTH as u16).to_be_bytes());
        bytes.extend_from_slice(&manifest_bytes);
        bytes.extend_from_slice(&candidate_id.as_bytes());
        bytes.extend_from_slice(&PROFILE_EXTERNAL_KATS.to_be_bytes());
        bytes.extend_from_slice(&(RECORD_COUNT as u16).to_be_bytes());
        for record in &self.records {
            bytes.extend_from_slice(&record.canonical_bytes());
        }
        debug_assert_eq!(bytes.len(), P24_INTENT_VECTOR_LENGTH);
        Ok(bytes)
    }

    /// Parses only the complete, byte-for-byte frozen two-vector profile.
    pub fn decode(bytes: &[u8]) -> Result<Self, P24IntentVectorError> {
        if bytes.len() > P24_INTENT_VECTOR_LENGTH_LIMIT {
            return Err(P24IntentVectorError::CorpusTooLarge(bytes.len()));
        }
        if bytes.len() != P24_INTENT_VECTOR_LENGTH {
            return Err(P24IntentVectorError::InvalidCorpusLength(bytes.len()));
        }
        let mut reader = Reader::new(bytes);
        if reader.array::<4>()? != P24_INTENT_VECTOR_MAGIC {
            return Err(P24IntentVectorError::InvalidMagic);
        }
        if reader.u16()? != P24_INTENT_VECTOR_VERSION {
            return Err(P24IntentVectorError::UnsupportedVersion);
        }
        if reader.u16()? != FLAGS || reader.u16()? as usize != P24_INTENT_COMMITMENT_MANIFEST_LENGTH
        {
            return Err(P24IntentVectorError::NonCanonicalHeader);
        }
        CandidatePoseidon2P24IntentCommitmentManifestV1::decode(
            reader.bytes(P24_INTENT_COMMITMENT_MANIFEST_LENGTH)?,
        )?;
        let expected_id = CandidatePoseidon2P24IntentCommitmentManifestV1::new()
            .candidate_id()?
            .as_bytes();
        if reader.array::<32>()? != expected_id {
            return Err(P24IntentVectorError::ManifestIdentityMismatch);
        }
        if reader.u16()? != PROFILE_EXTERNAL_KATS || reader.u16()? as usize != RECORD_COUNT {
            return Err(P24IntentVectorError::InvalidCoverage);
        }
        let records = [decode_record(&mut reader)?, decode_record(&mut reader)?];
        if !reader.finished() {
            return Err(P24IntentVectorError::TrailingBytes);
        }
        let corpus = Self::new(records)?;
        if corpus.encode()? != bytes {
            return Err(P24IntentVectorError::NonCanonicalRecordOrder);
        }
        Ok(corpus)
    }

    fn validate_closed_profile(&self) -> Result<(), P24IntentVectorError> {
        for case in [
            P24IntentVectorCaseV1::StructuralBaseline,
            P24IntentVectorCaseV1::BoundaryElements,
        ] {
            let actual = self
                .records
                .iter()
                .find(|record| record.case == case)
                .ok_or(P24IntentVectorError::InvalidCoverage)?;
            if actual != &known_record(case) {
                return Err(P24IntentVectorError::InvalidCoverage);
            }
        }
        Ok(())
    }
}

fn decode_record(reader: &mut Reader<'_>) -> Result<P24IntentVectorRecordV1, P24IntentVectorError> {
    let case = P24IntentVectorCaseV1::from_tag(reader.u8()?)?;
    if reader.u8()? != RECORD_FLAGS || reader.u32()? as usize != RECORD_PAYLOAD_LENGTH {
        return Err(P24IntentVectorError::InvalidRecordLength);
    }
    let intent = reader.array::<P24_INTENT_COMMITMENT_INPUT_BYTES>()?;
    let packed = core::array::from_fn(|_| {
        reader
            .u32_le()
            .expect("record packing is bounded by header")
    });
    let digest = PrivateTransferIntentCommitmentV2::new(reader.array()?)?;
    P24IntentVectorRecordV1::new(case, intent, packed, digest)
}

fn byte_pack3le(
    input: &[u8; P24_INTENT_COMMITMENT_INPUT_BYTES],
) -> [u32; P24_INTENT_COMMITMENT_INPUT_ELEMENTS] {
    core::array::from_fn(|index| {
        input[index * P24_BYTE_PACK_WIDTH
            ..core::cmp::min((index + 1) * P24_BYTE_PACK_WIDTH, input.len())]
            .iter()
            .enumerate()
            .fold(0_u32, |value, (offset, byte)| {
                value | (u32::from(*byte) << (offset * 8))
            })
    })
}

fn known_record(case: P24IntentVectorCaseV1) -> P24IntentVectorRecordV1 {
    let intent = known_intent(case);
    let digest = PrivateTransferIntentCommitmentV2::from_elements(match case {
        P24IntentVectorCaseV1::StructuralBaseline => [
            1098549077, 1235522076, 1478424652, 1481381536, 528608958, 1330079375, 362586605,
            1738919005, 1916043278, 1954911332, 1841702528, 1249444496, 400154715, 294159042,
            1980980091, 376305720,
        ],
        P24IntentVectorCaseV1::BoundaryElements => [
            1434497478, 1681194821, 1869074451, 1023130484, 560801581, 1937059648, 540867581,
            1942987663, 730711795, 1218251084, 43830160, 533681248, 971936176, 1743410686,
            1304665704, 981526481,
        ],
    })
    .expect("external digest is canonical");
    P24IntentVectorRecordV1::new(case, intent, byte_pack3le(&intent), digest)
        .expect("external record is canonical")
}

fn known_intent(case: P24IntentVectorCaseV1) -> [u8; P24_INTENT_COMMITMENT_INPUT_BYTES] {
    let mut bytes = Vec::with_capacity(P24_INTENT_COMMITMENT_INPUT_BYTES);
    match case {
        P24IntentVectorCaseV1::StructuralBaseline => {
            for value in [1_u8, 2, 3, 4, 5] {
                bytes.extend_from_slice(&[value; 32]);
            }
            push_repeated(&mut bytes, 6);
            bytes.extend_from_slice(&[7; 32]);
            for value in 8..=13 {
                push_repeated(&mut bytes, value);
            }
        }
        P24IntentVectorCaseV1::BoundaryElements => {
            for value in [21_u8, 22, 23, 24, 25] {
                bytes.extend_from_slice(&[value; 32]);
            }
            for index in 0..16 {
                bytes.extend_from_slice(
                    &[0_u32, 1, 2_013_265_919, 2_013_265_920][index % 4].to_le_bytes(),
                );
            }
            bytes.extend_from_slice(&[26; 32]);
            push_repeated(&mut bytes, 0);
            push_repeated(&mut bytes, 1);
            push_repeated(&mut bytes, 0);
            push_repeated(&mut bytes, 2_013_265_920);
            push_repeated(&mut bytes, 2_013_265_919);
            push_repeated(&mut bytes, 2_013_265_920);
        }
    }
    bytes
        .try_into()
        .expect("fixed external intent has 640 bytes")
}

fn push_repeated(bytes: &mut Vec<u8>, value: u32) {
    for _ in 0..16 {
        bytes.extend_from_slice(&value.to_le_bytes());
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
    fn bytes(&mut self, length: usize) -> Result<&'a [u8], P24IntentVectorError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(P24IntentVectorError::Truncated)?;
        let output = self
            .bytes
            .get(self.offset..end)
            .ok_or(P24IntentVectorError::Truncated)?;
        self.offset = end;
        Ok(output)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], P24IntentVectorError> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| P24IntentVectorError::Truncated)
    }
    fn u8(&mut self) -> Result<u8, P24IntentVectorError> {
        Ok(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, P24IntentVectorError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, P24IntentVectorError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u32_le(&mut self) -> Result<u32, P24IntentVectorError> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

/// Errors while parsing or constructing the closed NXIV candidate corpus.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum P24IntentVectorError {
    Candidate(Poseidon2P24IntentCommitmentCandidateError),
    Privacy(PrivacyTypesError),
    InvalidMagic,
    UnsupportedVersion,
    NonCanonicalHeader,
    ManifestIdentityMismatch,
    CorpusTooLarge(usize),
    InvalidCorpusLength(usize),
    UnsupportedCase(u8),
    InvalidRecordLength,
    NonCanonicalIntent,
    PackingMismatch,
    DuplicateCase,
    InvalidCoverage,
    NonCanonicalRecordOrder,
    Truncated,
    TrailingBytes,
}
impl From<Poseidon2P24IntentCommitmentCandidateError> for P24IntentVectorError {
    fn from(value: Poseidon2P24IntentCommitmentCandidateError) -> Self {
        Self::Candidate(value)
    }
}
impl From<PrivacyTypesError> for P24IntentVectorError {
    fn from(value: PrivacyTypesError) -> Self {
        Self::Privacy(value)
    }
}
impl fmt::Display for P24IntentVectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "NXIV v1 error: {self:?}")
    }
}
impl std::error::Error for P24IntentVectorError {}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn frozen_external_kats_round_trip_and_have_stable_bytes() {
        let corpus = P24IntentVectorCorpusV1::frozen_external_kat_corpus();
        let encoded = corpus.encode().unwrap();
        assert_eq!(encoded.len(), P24_INTENT_VECTOR_LENGTH);
        assert_eq!(
            format!("{:x}", Sha256::digest(&encoded)),
            "732a2607da61d26b233150b7b288508d0226a9e53d6bbc471b85abfa4899cc2e"
        );
        assert_eq!(P24IntentVectorCorpusV1::decode(&encoded), Ok(corpus));
    }

    #[test]
    fn decoder_rejects_framing_parent_and_record_mutations() {
        let canonical = P24IntentVectorCorpusV1::frozen_external_kat_corpus()
            .encode()
            .unwrap();
        for index in [
            0,
            4,
            8,
            P24_INTENT_VECTOR_HEADER_LENGTH - 1,
            P24_INTENT_VECTOR_HEADER_LENGTH,
            P24_INTENT_VECTOR_HEADER_LENGTH + RECORD_LENGTH,
            canonical.len() - 1,
        ] {
            let mut changed = canonical.clone();
            changed[index] ^= 1;
            assert!(P24IntentVectorCorpusV1::decode(&changed).is_err());
        }
        assert!(P24IntentVectorCorpusV1::decode(&canonical[..canonical.len() - 1]).is_err());
    }
}
