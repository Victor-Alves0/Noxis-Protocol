//! Canonical NXTV framing for external tree-vector evidence.
//!
//! This module parses and writes test evidence only. It deliberately exposes
//! no tree hash, root, proof, allowlist, or production parameter resolution.

use std::fmt;

use noxis_privacy_types::{
    BABYBEAR_ELEMENTS_PER_VALUE, BABYBEAR_VECTOR_BYTES, NoteCommitmentV2, PrivacyTypesError,
};

use crate::{CandidateTreeManifestId, DRAFT_TREE_MANIFEST_LENGTH, DraftTreeManifestV1};

/// Four-byte magic identifying an external draft tree-vector corpus.
pub const DRAFT_TREE_VECTOR_MAGIC: [u8; 4] = *b"NXTV";
/// Framing version for the external draft tree-vector corpus.
pub const DRAFT_TREE_VECTOR_VERSION: u16 = 1;
/// Maximum total encoded corpus size accepted before any record allocation.
pub const DRAFT_TREE_VECTOR_LENGTH_LIMIT: usize = 1_048_576;
const DRAFT_TREE_VECTOR_HEADER_LENGTH: usize = 70;
const DRAFT_TREE_VECTOR_MAX_RECORDS: usize = 4_096;
const DRAFT_TREE_VECTOR_FLAGS: u16 = 0;
const RECORD_FLAGS: u8 = 0;
const TREE_DEPTH: usize = 32;
const MAX_SMALL_TREE_LEAVES: usize = 4;

const PERMUTATION_TAG: u8 = 1;
const LEAF_TAG: u8 = 2;
const NODE_TAG: u8 = 3;
const EMPTY_TAG: u8 = 4;
const TREE_TAG: u8 = 5;
const PATH_TAG: u8 = 6;

/// One canonical 64-byte BabyBear vector used as corpus input or output.
///
/// It is intentionally not named as a commitment or root: the corpus is
/// evidence for a future tree definition and cannot assign that meaning.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TreeVectorValueV1([u8; BABYBEAR_VECTOR_BYTES]);

impl TreeVectorValueV1 {
    /// Checks the shared sixteen-element canonical BabyBear representation.
    pub fn new(bytes: [u8; BABYBEAR_VECTOR_BYTES]) -> Result<Self, TreeVectorError> {
        NoteCommitmentV2::new(bytes).map_err(TreeVectorError::InvalidFieldValue)?;
        Ok(Self(bytes))
    }

    /// Builds a vector from semantic BabyBear elements in canonical order.
    pub fn from_elements(
        elements: [u32; BABYBEAR_ELEMENTS_PER_VALUE],
    ) -> Result<Self, TreeVectorError> {
        let value = NoteCommitmentV2::from_elements(elements)
            .map_err(TreeVectorError::InvalidFieldValue)?;
        Ok(Self(value.as_bytes()))
    }

    /// Returns the exact canonical little-endian field encoding.
    pub const fn as_bytes(self) -> [u8; BABYBEAR_VECTOR_BYTES] {
        self.0
    }

    /// Returns the sixteen semantic BabyBear elements.
    pub fn elements(self) -> [u32; BABYBEAR_ELEMENTS_PER_VALUE] {
        NoteCommitmentV2::new(self.0)
            .expect("TreeVectorValueV1 validates construction")
            .elements()
    }
}

/// One evidence record in a draft v2 tree-vector corpus.
///
/// Tags deliberately encode the domain role rather than accepting arbitrary
/// textual aliases. The records state expected outputs; they do not implement
/// the corresponding operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TreeVectorRecordV1 {
    /// A width-16 Poseidon2 permutation input/output pair.
    Permutation {
        input: TreeVectorValueV1,
        output: TreeVectorValueV1,
    },
    /// A future `LEAF`-domain commitment-to-leaf test case.
    Leaf {
        note: TreeVectorValueV1,
        leaf: TreeVectorValueV1,
    },
    /// A future ordered `NODE(left, right)` test case.
    Node {
        left: TreeVectorValueV1,
        right: TreeVectorValueV1,
        parent: TreeVectorValueV1,
    },
    /// One future `EMPTY[level]` value, where level is in `0..=32`.
    Empty { level: u8, value: TreeVectorValueV1 },
    /// A future append-only tree from index zero with at most four leaves.
    SmallTree {
        leaves: Vec<TreeVectorValueV1>,
        root: TreeVectorValueV1,
    },
    /// A future depth-32 path; sibling zero is adjacent to the leaf.
    Path {
        leaf_index: u32,
        leaf: TreeVectorValueV1,
        siblings: Box<[TreeVectorValueV1; TREE_DEPTH]>,
        root: TreeVectorValueV1,
    },
}

impl TreeVectorRecordV1 {
    fn encode_payload(&self, output: &mut Vec<u8>) {
        match self {
            Self::Permutation {
                input,
                output: expected,
            } => {
                output.extend_from_slice(&input.as_bytes());
                output.extend_from_slice(&expected.as_bytes());
            }
            Self::Leaf { note, leaf } => {
                output.extend_from_slice(&note.as_bytes());
                output.extend_from_slice(&leaf.as_bytes());
            }
            Self::Node {
                left,
                right,
                parent,
            } => {
                output.extend_from_slice(&left.as_bytes());
                output.extend_from_slice(&right.as_bytes());
                output.extend_from_slice(&parent.as_bytes());
            }
            Self::Empty { level, value } => {
                output.push(*level);
                output.extend_from_slice(&value.as_bytes());
            }
            Self::SmallTree { leaves, root } => {
                output.push(leaves.len() as u8);
                for leaf in leaves {
                    output.extend_from_slice(&leaf.as_bytes());
                }
                output.extend_from_slice(&root.as_bytes());
            }
            Self::Path {
                leaf_index,
                leaf,
                siblings,
                root,
            } => {
                output.extend_from_slice(&leaf_index.to_be_bytes());
                output.extend_from_slice(&leaf.as_bytes());
                for sibling in siblings.iter() {
                    output.extend_from_slice(&sibling.as_bytes());
                }
                output.extend_from_slice(&root.as_bytes());
            }
        }
    }

    fn tag(&self) -> u8 {
        match self {
            Self::Permutation { .. } => PERMUTATION_TAG,
            Self::Leaf { .. } => LEAF_TAG,
            Self::Node { .. } => NODE_TAG,
            Self::Empty { .. } => EMPTY_TAG,
            Self::SmallTree { .. } => TREE_TAG,
            Self::Path { .. } => PATH_TAG,
        }
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        self.encode_payload(&mut payload);
        let mut bytes = Vec::with_capacity(6 + payload.len());
        bytes.push(self.tag());
        bytes.push(RECORD_FLAGS);
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&payload);
        bytes
    }
}

/// A bounded, canonically ordered NXTV v1 evidence corpus.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeVectorCorpusV1 {
    records: Vec<TreeVectorRecordV1>,
}

impl TreeVectorCorpusV1 {
    /// Builds a canonical corpus bound only to the current unselected NXTM.
    pub fn new(mut records: Vec<TreeVectorRecordV1>) -> Result<Self, TreeVectorError> {
        if records.len() > DRAFT_TREE_VECTOR_MAX_RECORDS {
            return Err(TreeVectorError::TooManyRecords {
                actual: records.len(),
                limit: DRAFT_TREE_VECTOR_MAX_RECORDS,
            });
        }
        for record in &records {
            validate_record(record)?;
        }
        records.sort_by_key(TreeVectorRecordV1::canonical_bytes);
        if records
            .windows(2)
            .any(|pair| pair[0].canonical_bytes() == pair[1].canonical_bytes())
        {
            return Err(TreeVectorError::DuplicateRecord);
        }
        let encoded_length = encoded_length(&records)?;
        if encoded_length > DRAFT_TREE_VECTOR_LENGTH_LIMIT {
            return Err(TreeVectorError::CorpusTooLarge {
                actual: encoded_length,
                limit: DRAFT_TREE_VECTOR_LENGTH_LIMIT,
            });
        }
        Ok(Self { records })
    }

    /// Returns the records in the only permitted canonical order.
    pub fn records(&self) -> &[TreeVectorRecordV1] {
        &self.records
    }

    /// Encodes the complete NXTV v1 corpus.
    pub fn encode(&self) -> Vec<u8> {
        let manifest = DraftTreeManifestV1::new();
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&DRAFT_TREE_VECTOR_MAGIC);
        encoded.extend_from_slice(&DRAFT_TREE_VECTOR_VERSION.to_be_bytes());
        encoded.extend_from_slice(&DRAFT_TREE_VECTOR_FLAGS.to_be_bytes());
        encoded.extend_from_slice(&(DRAFT_TREE_MANIFEST_LENGTH as u16).to_be_bytes());
        encoded.extend_from_slice(&manifest.encode());
        encoded.extend_from_slice(&manifest.candidate_id().as_bytes());
        encoded.extend_from_slice(&(self.records.len() as u32).to_be_bytes());
        for record in &self.records {
            encoded.extend_from_slice(&record.canonical_bytes());
        }
        encoded
    }

    /// Decodes only a corpus bound to the current unselected NXTM candidate.
    pub fn decode(bytes: &[u8]) -> Result<Self, TreeVectorError> {
        if bytes.len() > DRAFT_TREE_VECTOR_LENGTH_LIMIT {
            return Err(TreeVectorError::CorpusTooLarge {
                actual: bytes.len(),
                limit: DRAFT_TREE_VECTOR_LENGTH_LIMIT,
            });
        }
        let mut reader = Reader::new(bytes);
        if reader.array::<4>()? != DRAFT_TREE_VECTOR_MAGIC {
            return Err(TreeVectorError::InvalidMagic);
        }
        if reader.u16()? != DRAFT_TREE_VECTOR_VERSION {
            return Err(TreeVectorError::UnsupportedVersion);
        }
        if reader.u16()? != DRAFT_TREE_VECTOR_FLAGS {
            return Err(TreeVectorError::NonCanonicalHeader);
        }
        if reader.u16()? as usize != DRAFT_TREE_MANIFEST_LENGTH {
            return Err(TreeVectorError::InvalidManifestLength);
        }
        let manifest = reader.array::<DRAFT_TREE_MANIFEST_LENGTH>()?;
        DraftTreeManifestV1::decode(&manifest).map_err(TreeVectorError::InvalidManifest)?;
        let actual_id =
            CandidateTreeManifestId::as_bytes(DraftTreeManifestV1::new().candidate_id());
        if reader.array::<32>()? != actual_id {
            return Err(TreeVectorError::ManifestIdentityMismatch);
        }
        let count = reader.u32()? as usize;
        if count > DRAFT_TREE_VECTOR_MAX_RECORDS {
            return Err(TreeVectorError::TooManyRecords {
                actual: count,
                limit: DRAFT_TREE_VECTOR_MAX_RECORDS,
            });
        }
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let tag = reader.u8()?;
            if reader.u8()? != RECORD_FLAGS {
                return Err(TreeVectorError::NonCanonicalRecordFlags);
            }
            let payload_length = reader.u32()? as usize;
            let payload = reader.bytes(payload_length)?;
            records.push(decode_record(tag, payload)?);
        }
        if !reader.is_finished() {
            return Err(TreeVectorError::TrailingBytes);
        }
        let corpus = Self::new(records)?;
        if corpus.encode() != bytes {
            return Err(TreeVectorError::NonCanonicalRecordOrder);
        }
        Ok(corpus)
    }

    /// Returns the two externally cross-validated permutation vectors in NXTV.
    pub fn frozen_permutation_corpus() -> Self {
        let records = crate::Poseidon2BabyBear16ReferenceVectorV1::frozen()
            .into_iter()
            .map(|vector| TreeVectorRecordV1::Permutation {
                input: TreeVectorValueV1::from_elements(vector.input())
                    .expect("frozen BabyBear input is canonical"),
                output: TreeVectorValueV1::from_elements(vector.output())
                    .expect("frozen BabyBear output is canonical"),
            })
            .collect();
        Self::new(records).expect("frozen reference corpus is canonical")
    }
}

fn validate_record(record: &TreeVectorRecordV1) -> Result<(), TreeVectorError> {
    match record {
        TreeVectorRecordV1::Empty { level, .. } if *level > TREE_DEPTH as u8 => {
            Err(TreeVectorError::InvalidEmptyLevel(*level))
        }
        TreeVectorRecordV1::SmallTree { leaves, .. } if leaves.len() > MAX_SMALL_TREE_LEAVES => {
            Err(TreeVectorError::TooManySmallTreeLeaves {
                actual: leaves.len(),
                limit: MAX_SMALL_TREE_LEAVES,
            })
        }
        _ => Ok(()),
    }
}

fn encoded_length(records: &[TreeVectorRecordV1]) -> Result<usize, TreeVectorError> {
    let mut length = DRAFT_TREE_VECTOR_HEADER_LENGTH;
    for record in records {
        let record_length = record.canonical_bytes().len();
        length = length
            .checked_add(record_length)
            .ok_or(TreeVectorError::CorpusTooLarge {
                actual: usize::MAX,
                limit: DRAFT_TREE_VECTOR_LENGTH_LIMIT,
            })?;
    }
    Ok(length)
}

fn decode_record(tag: u8, payload: &[u8]) -> Result<TreeVectorRecordV1, TreeVectorError> {
    let mut reader = Reader::new(payload);
    let record = match tag {
        PERMUTATION_TAG => TreeVectorRecordV1::Permutation {
            input: reader.value()?,
            output: reader.value()?,
        },
        LEAF_TAG => TreeVectorRecordV1::Leaf {
            note: reader.value()?,
            leaf: reader.value()?,
        },
        NODE_TAG => TreeVectorRecordV1::Node {
            left: reader.value()?,
            right: reader.value()?,
            parent: reader.value()?,
        },
        EMPTY_TAG => TreeVectorRecordV1::Empty {
            level: reader.u8()?,
            value: reader.value()?,
        },
        TREE_TAG => {
            let count = reader.u8()? as usize;
            if count > MAX_SMALL_TREE_LEAVES {
                return Err(TreeVectorError::TooManySmallTreeLeaves {
                    actual: count,
                    limit: MAX_SMALL_TREE_LEAVES,
                });
            }
            let mut leaves = Vec::with_capacity(count);
            for _ in 0..count {
                leaves.push(reader.value()?);
            }
            TreeVectorRecordV1::SmallTree {
                leaves,
                root: reader.value()?,
            }
        }
        PATH_TAG => {
            let leaf_index = reader.u32()?;
            let leaf = reader.value()?;
            let mut sibling_values = Vec::with_capacity(TREE_DEPTH);
            for _ in 0..TREE_DEPTH {
                sibling_values.push(reader.value()?);
            }
            let siblings = sibling_values
                .try_into()
                .map_err(|_| TreeVectorError::Truncated)?;
            TreeVectorRecordV1::Path {
                leaf_index,
                leaf,
                siblings: Box::new(siblings),
                root: reader.value()?,
            }
        }
        _ => return Err(TreeVectorError::UnsupportedRecordKind(tag)),
    };
    if !reader.is_finished() {
        return Err(TreeVectorError::InvalidRecordLength);
    }
    validate_record(&record)?;
    Ok(record)
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn bytes(&mut self, count: usize) -> Result<&'a [u8], TreeVectorError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(TreeVectorError::Truncated)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(TreeVectorError::Truncated)?;
        self.offset = end;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], TreeVectorError> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| TreeVectorError::Truncated)
    }

    fn u8(&mut self) -> Result<u8, TreeVectorError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, TreeVectorError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, TreeVectorError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn value(&mut self) -> Result<TreeVectorValueV1, TreeVectorError> {
        TreeVectorValueV1::new(self.array()?)
    }

    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

/// Errors produced while framing external NXTV evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TreeVectorError {
    CorpusTooLarge { actual: usize, limit: usize },
    InvalidMagic,
    UnsupportedVersion,
    NonCanonicalHeader,
    InvalidManifestLength,
    InvalidManifest(crate::TreeParamsError),
    ManifestIdentityMismatch,
    TooManyRecords { actual: usize, limit: usize },
    NonCanonicalRecordFlags,
    UnsupportedRecordKind(u8),
    InvalidRecordLength,
    InvalidFieldValue(PrivacyTypesError),
    InvalidEmptyLevel(u8),
    TooManySmallTreeLeaves { actual: usize, limit: usize },
    DuplicateRecord,
    NonCanonicalRecordOrder,
    Truncated,
    TrailingBytes,
}

impl fmt::Display for TreeVectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CorpusTooLarge { actual, limit } => {
                write!(
                    formatter,
                    "NXTV corpus length is {actual}, limit is {limit}"
                )
            }
            Self::InvalidMagic => formatter.write_str("invalid NXTV magic"),
            Self::UnsupportedVersion => formatter.write_str("unsupported NXTV version"),
            Self::NonCanonicalHeader => formatter.write_str("non-canonical NXTV header"),
            Self::InvalidManifestLength => {
                formatter.write_str("invalid NXTM length in NXTV header")
            }
            Self::InvalidManifest(error) => {
                write!(formatter, "invalid NXTM in NXTV header: {error}")
            }
            Self::ManifestIdentityMismatch => {
                formatter.write_str("NXTV candidate manifest identity mismatch")
            }
            Self::TooManyRecords { actual, limit } => {
                write!(formatter, "NXTV has {actual} records, limit is {limit}")
            }
            Self::NonCanonicalRecordFlags => formatter.write_str("non-canonical NXTV record flags"),
            Self::UnsupportedRecordKind(kind) => {
                write!(formatter, "unsupported NXTV record kind {kind}")
            }
            Self::InvalidRecordLength => formatter.write_str("invalid NXTV record payload length"),
            Self::InvalidFieldValue(error) => {
                write!(formatter, "invalid NXTV BabyBear value: {error}")
            }
            Self::InvalidEmptyLevel(level) => write!(formatter, "invalid NXTV empty level {level}"),
            Self::TooManySmallTreeLeaves { actual, limit } => {
                write!(
                    formatter,
                    "NXTV small tree has {actual} leaves, limit is {limit}"
                )
            }
            Self::DuplicateRecord => formatter.write_str("duplicate NXTV record"),
            Self::NonCanonicalRecordOrder => formatter.write_str("non-canonical NXTV record order"),
            Self::Truncated => formatter.write_str("truncated NXTV corpus"),
            Self::TrailingBytes => formatter.write_str("trailing bytes in NXTV corpus"),
        }
    }
}

impl std::error::Error for TreeVectorError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(seed: u32) -> TreeVectorValueV1 {
        TreeVectorValueV1::from_elements(core::array::from_fn(|index| seed + index as u32)).unwrap()
    }

    #[test]
    fn frozen_permutation_corpus_round_trips_exactly() {
        let corpus = TreeVectorCorpusV1::frozen_permutation_corpus();
        let encoded = corpus.encode();
        assert_eq!(encoded[..4], DRAFT_TREE_VECTOR_MAGIC);
        assert_eq!(TreeVectorCorpusV1::decode(&encoded), Ok(corpus));
    }

    #[test]
    fn every_record_shape_is_framed_without_implementing_a_tree() {
        let corpus = TreeVectorCorpusV1::new(vec![
            TreeVectorRecordV1::Leaf {
                note: value(1),
                leaf: value(2),
            },
            TreeVectorRecordV1::Node {
                left: value(3),
                right: value(4),
                parent: value(5),
            },
            TreeVectorRecordV1::Empty {
                level: 32,
                value: value(6),
            },
            TreeVectorRecordV1::SmallTree {
                leaves: vec![value(7), value(8)],
                root: value(9),
            },
            TreeVectorRecordV1::Path {
                leaf_index: u32::MAX,
                leaf: value(10),
                siblings: Box::new(core::array::from_fn(|index| value(11 + index as u32))),
                root: value(43),
            },
        ])
        .unwrap();
        assert_eq!(TreeVectorCorpusV1::decode(&corpus.encode()), Ok(corpus));
    }

    #[test]
    fn decoder_rejects_header_field_and_record_mutations() {
        let encoded = TreeVectorCorpusV1::frozen_permutation_corpus().encode();
        let mut changed_header = encoded.clone();
        changed_header[8] ^= 1;
        assert_eq!(
            TreeVectorCorpusV1::decode(&changed_header),
            Err(TreeVectorError::InvalidManifestLength)
        );

        let mut changed_value = encoded.clone();
        changed_value[DRAFT_TREE_VECTOR_HEADER_LENGTH + 6..DRAFT_TREE_VECTOR_HEADER_LENGTH + 10]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            TreeVectorCorpusV1::decode(&changed_value),
            Err(TreeVectorError::InvalidFieldValue(_))
        ));

        let mut changed_tag = encoded.clone();
        changed_tag[DRAFT_TREE_VECTOR_HEADER_LENGTH] = 99;
        assert_eq!(
            TreeVectorCorpusV1::decode(&changed_tag),
            Err(TreeVectorError::UnsupportedRecordKind(99))
        );
        assert_eq!(
            TreeVectorCorpusV1::decode(&encoded[..encoded.len() - 1]),
            Err(TreeVectorError::Truncated)
        );
    }

    #[test]
    fn record_limits_and_duplicates_are_rejected() {
        assert_eq!(
            TreeVectorCorpusV1::new(vec![TreeVectorRecordV1::Empty {
                level: 33,
                value: value(1),
            }]),
            Err(TreeVectorError::InvalidEmptyLevel(33))
        );
        assert!(matches!(
            TreeVectorCorpusV1::new(vec![TreeVectorRecordV1::SmallTree {
                leaves: vec![value(1), value(2), value(3), value(4), value(5)],
                root: value(6),
            }]),
            Err(TreeVectorError::TooManySmallTreeLeaves { .. })
        ));
        let record = TreeVectorRecordV1::Empty {
            level: 0,
            value: value(1),
        };
        assert_eq!(
            TreeVectorCorpusV1::new(vec![record.clone(), record]),
            Err(TreeVectorError::DuplicateRecord)
        );
    }

    #[test]
    fn constructor_refuses_a_corpus_the_decoder_would_refuse_for_size() {
        let path = TreeVectorRecordV1::Path {
            leaf_index: 0,
            leaf: value(1),
            siblings: Box::new(core::array::from_fn(|index| value(2 + index as u32))),
            root: value(34),
        };
        let records = (0..480)
            .map(|index| {
                let mut record = path.clone();
                if let TreeVectorRecordV1::Path { leaf_index, .. } = &mut record {
                    *leaf_index = index;
                }
                record
            })
            .collect();
        assert!(matches!(
            TreeVectorCorpusV1::new(records),
            Err(TreeVectorError::CorpusTooLarge { .. })
        ));
    }
}
