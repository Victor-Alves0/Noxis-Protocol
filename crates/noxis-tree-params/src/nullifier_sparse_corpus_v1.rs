//! Closed `NXSV v1` external evidence for the unselected `NXSM` candidate.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use noxis_privacy_types::{
    BABYBEAR_ELEMENTS_PER_VALUE, BABYBEAR_VECTOR_BYTES, NullifierV2, PrivacyTypesError,
};
use sha2::{Digest, Sha256};

use crate::{
    CandidatePoseidon2P24NullifierSparseManifestV1, Poseidon2P24NullifierSparseCandidateError,
};

/// Magic for a candidate sparse-nullifier external vector corpus.
pub const P24_NULLIFIER_SPARSE_VECTOR_MAGIC: [u8; 4] = *b"NXSV";
/// The only supported `NXSV` framing version.
pub const P24_NULLIFIER_SPARSE_VECTOR_VERSION: u16 = 1;
/// Upper bound checked before record allocation.
pub const P24_NULLIFIER_SPARSE_VECTOR_LENGTH_LIMIT: usize = 1_048_576;
/// Fixed `NXSV v1` header length.
pub const P24_NULLIFIER_SPARSE_VECTOR_HEADER_LENGTH: usize = 44;

const FLAGS: u16 = 0;
const RECORD_FLAGS: u8 = 0;
const LEAF_TAG: u8 = 1;
const NODE_TAG: u8 = 2;
const EMPTY_TAG: u8 = 3;
const ROOT_TAG: u8 = 4;
const MAX_RECORDS: usize = 128;
const FOCUSED_EXTERNAL_KAT_RECORDS: usize = 15;
const FIXTURE_BASE64: &str =
    include_str!("../fixtures/poseidon2_babybear_p24_nullifier_sparse_vectors_v1.base64");
const FIXTURE_SHA256: [u8; 32] = [
    0xe0, 0x30, 0x9d, 0xd9, 0xcb, 0x24, 0x15, 0xcc, 0xf4, 0xea, 0x3a, 0x0a, 0x97, 0xfc, 0x4f, 0x00,
    0x2f, 0xec, 0x60, 0x24, 0xf4, 0x39, 0x82, 0x1f, 0x03, 0x0a, 0x7e, 0xfa, 0x79, 0x0c, 0x9b, 0x0d,
];

/// A canonical 16-element BabyBear value used only as sparse-tree evidence.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NullifierSparseVectorValueV1([u8; BABYBEAR_VECTOR_BYTES]);

impl NullifierSparseVectorValueV1 {
    /// Accepts only sixteen canonical `u32le` BabyBear elements.
    pub fn new(bytes: [u8; BABYBEAR_VECTOR_BYTES]) -> Result<Self, P24NullifierSparseVectorError> {
        NullifierV2::new(bytes).map_err(P24NullifierSparseVectorError::InvalidFieldValue)?;
        Ok(Self(bytes))
    }

    /// Builds a vector from canonical elements in semantic order.
    pub fn from_elements(
        elements: [u32; BABYBEAR_ELEMENTS_PER_VALUE],
    ) -> Result<Self, P24NullifierSparseVectorError> {
        let value = NullifierV2::from_elements(elements)
            .map_err(P24NullifierSparseVectorError::InvalidFieldValue)?;
        Ok(Self(value.as_bytes()))
    }

    /// Exact canonical little-endian encoding.
    pub const fn as_bytes(self) -> [u8; BABYBEAR_VECTOR_BYTES] {
        self.0
    }

    /// Semantic BabyBear elements in canonical order.
    pub fn elements(self) -> [u32; BABYBEAR_ELEMENTS_PER_VALUE] {
        NullifierV2::new(self.0)
            .expect("constructor validates canonical field encoding")
            .elements()
    }
}

/// The fixed coverage claim of the external candidate corpus.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum P24NullifierSparseVectorCoverageV1 {
    /// Two leaves, ordered nodes, selected empties and roots for 0–2 spends.
    FocusedExternalKats,
}

impl P24NullifierSparseVectorCoverageV1 {
    const fn encode(self) -> u16 {
        match self {
            Self::FocusedExternalKats => 1,
        }
    }

    fn decode(value: u16) -> Result<Self, P24NullifierSparseVectorError> {
        match value {
            1 => Ok(Self::FocusedExternalKats),
            _ => Err(P24NullifierSparseVectorError::UnsupportedCoverage(value)),
        }
    }
}

/// One externally generated `NXSM` evidence record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum P24NullifierSparseVectorRecordV1 {
    /// `H_NF_LEAF(nullifier)`.
    Leaf {
        nullifier: NullifierV2,
        leaf: NullifierSparseVectorValueV1,
    },
    /// Ordered `H_NF_NODE(left || right)`.
    Node {
        left: NullifierSparseVectorValueV1,
        right: NullifierSparseVectorValueV1,
        parent: NullifierSparseVectorValueV1,
    },
    /// `E[level]` for a selected level from zero through 512.
    Empty {
        level: u16,
        value: NullifierSparseVectorValueV1,
    },
    /// Sparse root for a strict, canonical set of zero to two nullifiers.
    Root {
        nullifiers: Vec<NullifierV2>,
        root: NullifierSparseVectorValueV1,
    },
}

impl P24NullifierSparseVectorRecordV1 {
    fn tag(&self) -> u8 {
        match self {
            Self::Leaf { .. } => LEAF_TAG,
            Self::Node { .. } => NODE_TAG,
            Self::Empty { .. } => EMPTY_TAG,
            Self::Root { .. } => ROOT_TAG,
        }
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        match self {
            Self::Leaf { nullifier, leaf } => {
                payload.extend_from_slice(&nullifier.as_bytes());
                payload.extend_from_slice(&leaf.as_bytes());
            }
            Self::Node {
                left,
                right,
                parent,
            } => {
                payload.extend_from_slice(&left.as_bytes());
                payload.extend_from_slice(&right.as_bytes());
                payload.extend_from_slice(&parent.as_bytes());
            }
            Self::Empty { level, value } => {
                payload.extend_from_slice(&level.to_be_bytes());
                payload.extend_from_slice(&value.as_bytes());
            }
            Self::Root { nullifiers, root } => {
                payload.push(nullifiers.len() as u8);
                for nullifier in nullifiers {
                    payload.extend_from_slice(&nullifier.as_bytes());
                }
                payload.extend_from_slice(&root.as_bytes());
            }
        }
        let mut bytes = Vec::with_capacity(6 + payload.len());
        bytes.push(self.tag());
        bytes.push(RECORD_FLAGS);
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&payload);
        bytes
    }
}

/// A canonical, externally generated evidence corpus bound to `NXSM v1`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P24NullifierSparseVectorCorpusV1 {
    records: Vec<P24NullifierSparseVectorRecordV1>,
}

impl P24NullifierSparseVectorCorpusV1 {
    /// Builds only the closed, focused external-KAT coverage profile.
    pub fn new(
        mut records: Vec<P24NullifierSparseVectorRecordV1>,
    ) -> Result<Self, P24NullifierSparseVectorError> {
        if records.len() > MAX_RECORDS {
            return Err(P24NullifierSparseVectorError::TooManyRecords(records.len()));
        }
        for record in &records {
            validate_record(record)?;
        }
        records.sort_by_key(P24NullifierSparseVectorRecordV1::canonical_bytes);
        if records
            .windows(2)
            .any(|pair| pair[0].canonical_bytes() == pair[1].canonical_bytes())
        {
            return Err(P24NullifierSparseVectorError::DuplicateRecord);
        }
        validate_focused_coverage(&records)?;
        let corpus = Self { records };
        if corpus.encode()?.len() > P24_NULLIFIER_SPARSE_VECTOR_LENGTH_LIMIT {
            return Err(P24NullifierSparseVectorError::CorpusTooLarge);
        }
        Ok(corpus)
    }

    /// Decodes the byte-for-byte frozen external artifact.
    pub fn frozen_external_kat_corpus() -> Result<Self, P24NullifierSparseVectorError> {
        let compact: String = FIXTURE_BASE64
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect();
        let bytes = STANDARD
            .decode(compact)
            .map_err(|_| P24NullifierSparseVectorError::InvalidEmbeddedBase64)?;
        if Sha256::digest(&bytes).as_slice() != FIXTURE_SHA256 {
            return Err(P24NullifierSparseVectorError::FixtureChecksumMismatch);
        }
        Self::decode(&bytes)
    }

    pub fn records(&self) -> &[P24NullifierSparseVectorRecordV1] {
        &self.records
    }

    /// Canonically encodes the corpus with the current `NXSM` candidate identity.
    pub fn encode(&self) -> Result<Vec<u8>, P24NullifierSparseVectorError> {
        let candidate = CandidatePoseidon2P24NullifierSparseManifestV1::new();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&P24_NULLIFIER_SPARSE_VECTOR_MAGIC);
        bytes.extend_from_slice(&P24_NULLIFIER_SPARSE_VECTOR_VERSION.to_be_bytes());
        bytes.extend_from_slice(&FLAGS.to_be_bytes());
        bytes.extend_from_slice(&candidate.candidate_id()?.as_bytes());
        bytes.extend_from_slice(
            &P24NullifierSparseVectorCoverageV1::FocusedExternalKats
                .encode()
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&(self.records.len() as u16).to_be_bytes());
        for record in &self.records {
            bytes.extend_from_slice(&record.canonical_bytes());
        }
        Ok(bytes)
    }

    /// Parses only canonical evidence bound to the current `NXSM` candidate.
    pub fn decode(bytes: &[u8]) -> Result<Self, P24NullifierSparseVectorError> {
        if bytes.len() > P24_NULLIFIER_SPARSE_VECTOR_LENGTH_LIMIT {
            return Err(P24NullifierSparseVectorError::CorpusTooLarge);
        }
        let mut reader = Reader::new(bytes);
        if reader.array::<4>()? != P24_NULLIFIER_SPARSE_VECTOR_MAGIC {
            return Err(P24NullifierSparseVectorError::InvalidMagic);
        }
        if reader.u16()? != P24_NULLIFIER_SPARSE_VECTOR_VERSION {
            return Err(P24NullifierSparseVectorError::UnsupportedVersion);
        }
        if reader.u16()? != FLAGS {
            return Err(P24NullifierSparseVectorError::NonCanonicalHeader);
        }
        let expected = CandidatePoseidon2P24NullifierSparseManifestV1::new()
            .candidate_id()?
            .as_bytes();
        if reader.array::<32>()? != expected {
            return Err(P24NullifierSparseVectorError::CandidateIdentityMismatch);
        }
        let coverage = P24NullifierSparseVectorCoverageV1::decode(reader.u16()?)?;
        if coverage != P24NullifierSparseVectorCoverageV1::FocusedExternalKats {
            return Err(P24NullifierSparseVectorError::NonCanonicalHeader);
        }
        let count = reader.u16()? as usize;
        if count != FOCUSED_EXTERNAL_KAT_RECORDS {
            return Err(P24NullifierSparseVectorError::InvalidCoverage);
        }
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let tag = reader.u8()?;
            if reader.u8()? != RECORD_FLAGS {
                return Err(P24NullifierSparseVectorError::NonCanonicalRecordFlags);
            }
            let length = reader.u32()? as usize;
            records.push(decode_record(tag, reader.bytes(length)?)?);
        }
        if !reader.is_finished() {
            return Err(P24NullifierSparseVectorError::TrailingBytes);
        }
        let corpus = Self::new(records)?;
        if corpus.encode()? != bytes {
            return Err(P24NullifierSparseVectorError::NonCanonicalRecordOrder);
        }
        Ok(corpus)
    }
}

fn validate_record(
    record: &P24NullifierSparseVectorRecordV1,
) -> Result<(), P24NullifierSparseVectorError> {
    match record {
        P24NullifierSparseVectorRecordV1::Empty { level, .. } if *level > 512 => {
            Err(P24NullifierSparseVectorError::InvalidEmptyLevel(*level))
        }
        P24NullifierSparseVectorRecordV1::Root { nullifiers, .. } => {
            if nullifiers.len() > 2 || nullifiers.windows(2).any(|pair| pair[0] >= pair[1]) {
                Err(P24NullifierSparseVectorError::NonCanonicalNullifierSet)
            } else {
                Ok(())
            }
        }
        _ => Ok(()),
    }
}

fn validate_focused_coverage(
    records: &[P24NullifierSparseVectorRecordV1],
) -> Result<(), P24NullifierSparseVectorError> {
    if records.len() != FOCUSED_EXTERNAL_KAT_RECORDS {
        return Err(P24NullifierSparseVectorError::InvalidCoverage);
    }
    let leaves: Vec<_> = records
        .iter()
        .filter_map(|record| match record {
            P24NullifierSparseVectorRecordV1::Leaf { nullifier, leaf } => Some((*nullifier, *leaf)),
            _ => None,
        })
        .collect();
    if leaves.len() != 2 || leaves[0].0 == leaves[1].0 {
        return Err(P24NullifierSparseVectorError::InvalidCoverage);
    }
    let node_pairs: Vec<_> = records
        .iter()
        .filter_map(|record| match record {
            P24NullifierSparseVectorRecordV1::Node { left, right, .. } => Some((*left, *right)),
            _ => None,
        })
        .collect();
    if node_pairs.len() != 2
        || !node_pairs.contains(&(leaves[0].1, leaves[1].1))
        || !node_pairs.contains(&(leaves[1].1, leaves[0].1))
    {
        return Err(P24NullifierSparseVectorError::InvalidCoverage);
    }
    let empty_levels: Vec<_> = records
        .iter()
        .filter_map(|record| match record {
            P24NullifierSparseVectorRecordV1::Empty { level, .. } => Some(*level),
            _ => None,
        })
        .collect();
    if empty_levels.len() != 7
        || [0, 1, 2, 32, 255, 511, 512]
            .iter()
            .any(|level| !empty_levels.contains(level))
    {
        return Err(P24NullifierSparseVectorError::InvalidCoverage);
    }
    let mut leaf_nullifiers = leaves
        .iter()
        .map(|(nullifier, _)| *nullifier)
        .collect::<Vec<_>>();
    leaf_nullifiers.sort_unstable();
    let mut root_sets: Vec<_> = records
        .iter()
        .filter_map(|record| match record {
            P24NullifierSparseVectorRecordV1::Root { nullifiers, .. } => Some(nullifiers.clone()),
            _ => None,
        })
        .collect();
    root_sets.sort_unstable();
    let mut expected = vec![
        Vec::new(),
        vec![leaf_nullifiers[0]],
        vec![leaf_nullifiers[1]],
        leaf_nullifiers,
    ];
    expected.sort_unstable();
    if root_sets != expected {
        return Err(P24NullifierSparseVectorError::InvalidCoverage);
    }
    Ok(())
}

fn decode_record(
    tag: u8,
    bytes: &[u8],
) -> Result<P24NullifierSparseVectorRecordV1, P24NullifierSparseVectorError> {
    let mut reader = Reader::new(bytes);
    let record = match tag {
        LEAF_TAG => P24NullifierSparseVectorRecordV1::Leaf {
            nullifier: reader.nullifier()?,
            leaf: reader.value()?,
        },
        NODE_TAG => P24NullifierSparseVectorRecordV1::Node {
            left: reader.value()?,
            right: reader.value()?,
            parent: reader.value()?,
        },
        EMPTY_TAG => P24NullifierSparseVectorRecordV1::Empty {
            level: reader.u16()?,
            value: reader.value()?,
        },
        ROOT_TAG => {
            let count = reader.u8()? as usize;
            if count > 2 {
                return Err(P24NullifierSparseVectorError::NonCanonicalNullifierSet);
            }
            let mut nullifiers = Vec::with_capacity(count);
            for _ in 0..count {
                nullifiers.push(reader.nullifier()?);
            }
            P24NullifierSparseVectorRecordV1::Root {
                nullifiers,
                root: reader.value()?,
            }
        }
        _ => return Err(P24NullifierSparseVectorError::UnsupportedRecordKind(tag)),
    };
    if !reader.is_finished() {
        return Err(P24NullifierSparseVectorError::InvalidRecordLength);
    }
    Ok(record)
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], P24NullifierSparseVectorError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(P24NullifierSparseVectorError::Truncated)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(P24NullifierSparseVectorError::Truncated)?;
        self.offset = end;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], P24NullifierSparseVectorError> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| P24NullifierSparseVectorError::Truncated)
    }

    fn u8(&mut self) -> Result<u8, P24NullifierSparseVectorError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, P24NullifierSparseVectorError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, P24NullifierSparseVectorError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn nullifier(&mut self) -> Result<NullifierV2, P24NullifierSparseVectorError> {
        NullifierV2::new(self.array()?).map_err(P24NullifierSparseVectorError::InvalidNullifier)
    }

    fn value(&mut self) -> Result<NullifierSparseVectorValueV1, P24NullifierSparseVectorError> {
        NullifierSparseVectorValueV1::new(self.array()?)
    }

    const fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

/// Fail-closed decoding and coverage errors for `NXSV v1`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum P24NullifierSparseVectorError {
    Candidate(Poseidon2P24NullifierSparseCandidateError),
    InvalidFieldValue(PrivacyTypesError),
    InvalidNullifier(PrivacyTypesError),
    InvalidEmbeddedBase64,
    FixtureChecksumMismatch,
    CorpusTooLarge,
    TooManyRecords(usize),
    InvalidMagic,
    UnsupportedVersion,
    UnsupportedCoverage(u16),
    NonCanonicalHeader,
    CandidateIdentityMismatch,
    NonCanonicalRecordFlags,
    UnsupportedRecordKind(u8),
    InvalidRecordLength,
    InvalidEmptyLevel(u16),
    NonCanonicalNullifierSet,
    DuplicateRecord,
    InvalidCoverage,
    NonCanonicalRecordOrder,
    Truncated,
    TrailingBytes,
}

impl From<Poseidon2P24NullifierSparseCandidateError> for P24NullifierSparseVectorError {
    fn from(value: Poseidon2P24NullifierSparseCandidateError) -> Self {
        Self::Candidate(value)
    }
}

impl fmt::Display for P24NullifierSparseVectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "NXSV v1 error: {self:?}")
    }
}

impl std::error::Error for P24NullifierSparseVectorError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_external_corpus_is_canonical_and_closed() {
        let corpus = P24NullifierSparseVectorCorpusV1::frozen_external_kat_corpus().unwrap();
        assert_eq!(corpus.records().len(), FOCUSED_EXTERNAL_KAT_RECORDS);
        assert_eq!(corpus.encode().unwrap().len(), 1_752);
        assert_eq!(
            P24NullifierSparseVectorCorpusV1::decode(&corpus.encode().unwrap()),
            Ok(corpus)
        );
    }

    #[test]
    fn decoder_rejects_header_record_and_fixture_mutations() {
        let bytes = P24NullifierSparseVectorCorpusV1::frozen_external_kat_corpus()
            .unwrap()
            .encode()
            .unwrap();
        for index in [0, 4, 6, 8, P24_NULLIFIER_SPARSE_VECTOR_HEADER_LENGTH] {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            assert!(P24NullifierSparseVectorCorpusV1::decode(&changed).is_err());
        }
        let mut noncanonical_value = bytes.clone();
        noncanonical_value[bytes.len() - 1] = u8::MAX;
        assert!(P24NullifierSparseVectorCorpusV1::decode(&noncanonical_value).is_err());
        assert!(P24NullifierSparseVectorCorpusV1::decode(&bytes[..bytes.len() - 1]).is_err());
        assert!(P24NullifierSparseVectorCorpusV1::frozen_external_kat_corpus().is_ok());
    }
}
