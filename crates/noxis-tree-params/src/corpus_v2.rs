//! NXTV v2 framing for the frozen Poseidon2-BabyBear-P24 candidate evidence.
//!
//! The format is intentionally separate from NXTV v1: P24 permutation states
//! have 24 elements, while tree values retain the public 16-element encoding.
//! It transports test evidence only and cannot select parameters or authorize
//! ledger behavior.

use std::fmt;

use noxis_privacy_types::{
    BABYBEAR_ELEMENTS_PER_VALUE, BABYBEAR_MODULUS, BABYBEAR_VECTOR_BYTES, NoteCommitmentV2,
    PrivacyTypesError,
};

use crate::{
    CandidatePoseidon2P24ManifestV2, P24_CANDIDATE_MANIFEST_LENGTH, Poseidon2P24CandidateError,
};

/// Four-byte magic identifying a P24 candidate vector corpus.
pub const P24_TREE_VECTOR_MAGIC: [u8; 4] = *b"NXTV";
/// Framing version bound only to the frozen candidate P24 manifest.
pub const P24_TREE_VECTOR_VERSION: u16 = 2;
/// Maximum accepted encoded P24 candidate corpus length.
pub const P24_TREE_VECTOR_LENGTH_LIMIT: usize = 1_048_576;
/// Exact v2 header size, including the full candidate manifest and identity.
pub const P24_TREE_VECTOR_HEADER_LENGTH: usize =
    4 + 2 + 2 + 2 + P24_CANDIDATE_MANIFEST_LENGTH + 32 + 4;

const P24_STATE_ELEMENTS: usize = 24;
const P24_STATE_BYTES: usize = P24_STATE_ELEMENTS * 4;
const P24_TREE_DEPTH: usize = 32;
const P24_MAX_RECORDS: usize = 4_096;
const P24_MAX_SMALL_TREE_NOTES: usize = 4;
const FLAGS: u16 = 0;
const RECORD_FLAGS: u8 = 0;
const PERMUTATION_TAG: u8 = 1;
const LEAF_TAG: u8 = 2;
const NODE_TAG: u8 = 3;
const EMPTY_TAG: u8 = 4;
const SMALL_TREE_TAG: u8 = 5;
const PATH_TAG: u8 = 6;

/// Declares the amount of evidence included in an NXTV v2 corpus.
///
/// `Initial` carries independently checked KATs but does not pretend to
/// contain every case required by a future parameter-selection gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum P24TreeVectorCoverageProfileV2 {
    Initial,
}

impl P24TreeVectorCoverageProfileV2 {
    const fn encode(self) -> u16 {
        match self {
            Self::Initial => 0,
        }
    }

    fn decode(value: u16) -> Result<Self, P24TreeVectorV2Error> {
        match value {
            0 => Ok(Self::Initial),
            _ => Err(P24TreeVectorV2Error::UnsupportedCoverageProfile(value)),
        }
    }
}

/// A complete canonical P24 permutation state encoded as 24 `u32le` values.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct P24PermutationStateV2([u8; P24_STATE_BYTES]);

impl P24PermutationStateV2 {
    /// Creates a state only from canonical BabyBear elements.
    pub fn from_elements(
        elements: [u32; P24_STATE_ELEMENTS],
    ) -> Result<Self, P24TreeVectorV2Error> {
        let mut bytes = [0_u8; P24_STATE_BYTES];
        for (index, element) in elements.into_iter().enumerate() {
            if element >= BABYBEAR_MODULUS {
                return Err(P24TreeVectorV2Error::NonCanonicalStateElement { index, element });
            }
            bytes[index * 4..(index + 1) * 4].copy_from_slice(&element.to_le_bytes());
        }
        Ok(Self(bytes))
    }

    /// Parses exact canonical state bytes.
    pub fn new(bytes: [u8; P24_STATE_BYTES]) -> Result<Self, P24TreeVectorV2Error> {
        let mut elements = [0_u32; P24_STATE_ELEMENTS];
        for (index, element) in elements.iter_mut().enumerate() {
            *element = u32::from_le_bytes(
                bytes[index * 4..(index + 1) * 4]
                    .try_into()
                    .expect("fixed state bounds"),
            );
        }
        Self::from_elements(elements)
    }

    /// Returns the canonical little-endian state encoding.
    pub const fn as_bytes(self) -> [u8; P24_STATE_BYTES] {
        self.0
    }
}

/// One public v2 tree value: 16 canonical BabyBear elements in 64 bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct P24TreeValueV2([u8; BABYBEAR_VECTOR_BYTES]);

impl P24TreeValueV2 {
    /// Creates a value only from canonical field encoding bytes.
    pub fn new(bytes: [u8; BABYBEAR_VECTOR_BYTES]) -> Result<Self, P24TreeVectorV2Error> {
        NoteCommitmentV2::new(bytes).map_err(P24TreeVectorV2Error::InvalidTreeValue)?;
        Ok(Self(bytes))
    }

    /// Creates a value from semantic elements in canonical order.
    pub fn from_elements(
        elements: [u32; BABYBEAR_ELEMENTS_PER_VALUE],
    ) -> Result<Self, P24TreeVectorV2Error> {
        let value = NoteCommitmentV2::from_elements(elements)
            .map_err(P24TreeVectorV2Error::InvalidTreeValue)?;
        Ok(Self(value.as_bytes()))
    }

    /// Returns the exact canonical field encoding.
    pub const fn as_bytes(self) -> [u8; BABYBEAR_VECTOR_BYTES] {
        self.0
    }
}

/// One P24 candidate evidence record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum P24TreeVectorRecordV2 {
    /// One complete P24 permutation input/output pair.
    Permutation {
        input: P24PermutationStateV2,
        output: P24PermutationStateV2,
    },
    /// Candidate `LEAF(note)` evidence.
    Leaf {
        note: P24TreeValueV2,
        leaf: P24TreeValueV2,
    },
    /// Ordered candidate `NODE(left, right)` evidence.
    Node {
        left: P24TreeValueV2,
        right: P24TreeValueV2,
        parent: P24TreeValueV2,
    },
    /// Candidate `EMPTY[level]` evidence for levels zero through 32.
    Empty { level: u8, value: P24TreeValueV2 },
    /// A depth-32 root for zero to four notes appended from index zero.
    SmallTree {
        notes: Vec<P24TreeValueV2>,
        root: P24TreeValueV2,
    },
    /// A depth-32 path where sibling zero is adjacent to the leaf.
    Path {
        leaf_index: u32,
        leaf: P24TreeValueV2,
        siblings: Box<[P24TreeValueV2; P24_TREE_DEPTH]>,
        root: P24TreeValueV2,
    },
}

impl P24TreeVectorRecordV2 {
    fn tag(&self) -> u8 {
        match self {
            Self::Permutation { .. } => PERMUTATION_TAG,
            Self::Leaf { .. } => LEAF_TAG,
            Self::Node { .. } => NODE_TAG,
            Self::Empty { .. } => EMPTY_TAG,
            Self::SmallTree { .. } => SMALL_TREE_TAG,
            Self::Path { .. } => PATH_TAG,
        }
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        match self {
            Self::Permutation { input, output } => {
                payload.extend_from_slice(&input.as_bytes());
                payload.extend_from_slice(&output.as_bytes());
            }
            Self::Leaf { note, leaf } => {
                payload.extend_from_slice(&note.as_bytes());
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
                payload.push(*level);
                payload.extend_from_slice(&value.as_bytes());
            }
            Self::SmallTree { notes, root } => {
                payload.push(notes.len() as u8);
                for note in notes {
                    payload.extend_from_slice(&note.as_bytes());
                }
                payload.extend_from_slice(&root.as_bytes());
            }
            Self::Path {
                leaf_index,
                leaf,
                siblings,
                root,
            } => {
                payload.extend_from_slice(&leaf_index.to_be_bytes());
                payload.extend_from_slice(&leaf.as_bytes());
                for sibling in siblings.iter() {
                    payload.extend_from_slice(&sibling.as_bytes());
                }
                payload.extend_from_slice(&root.as_bytes());
            }
        }
        let mut encoded = Vec::with_capacity(6 + payload.len());
        encoded.push(self.tag());
        encoded.push(RECORD_FLAGS);
        encoded.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&payload);
        encoded
    }
}

/// A bounded, canonically ordered NXTV v2 evidence corpus.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P24TreeVectorCorpusV2 {
    profile: P24TreeVectorCoverageProfileV2,
    records: Vec<P24TreeVectorRecordV2>,
}

impl P24TreeVectorCorpusV2 {
    /// Constructs a canonical candidate corpus after limits and ordering checks.
    pub fn new_initial(
        mut records: Vec<P24TreeVectorRecordV2>,
    ) -> Result<Self, P24TreeVectorV2Error> {
        if records.len() > P24_MAX_RECORDS {
            return Err(P24TreeVectorV2Error::TooManyRecords {
                actual: records.len(),
                limit: P24_MAX_RECORDS,
            });
        }
        for record in &records {
            validate_record(record)?;
        }
        records.sort_by_key(P24TreeVectorRecordV2::canonical_bytes);
        if records
            .windows(2)
            .any(|pair| pair[0].canonical_bytes() == pair[1].canonical_bytes())
        {
            return Err(P24TreeVectorV2Error::DuplicateRecord);
        }
        let length = encoded_length(&records)?;
        if length > P24_TREE_VECTOR_LENGTH_LIMIT {
            return Err(P24TreeVectorV2Error::CorpusTooLarge {
                actual: length,
                limit: P24_TREE_VECTOR_LENGTH_LIMIT,
            });
        }
        Ok(Self {
            profile: P24TreeVectorCoverageProfileV2::Initial,
            records,
        })
    }

    /// Returns the explicit coverage declaration for this corpus.
    pub const fn profile(&self) -> P24TreeVectorCoverageProfileV2 {
        self.profile
    }

    /// Returns records in their only canonical order.
    pub fn records(&self) -> &[P24TreeVectorRecordV2] {
        &self.records
    }

    /// Returns the initial externally cross-checked P24 candidate evidence.
    ///
    /// Its `Initial` coverage profile makes its deliberate incompleteness
    /// explicit. It is not the later selection-gate corpus.
    pub fn frozen_initial_candidate_corpus() -> Self {
        let ascending = value(core::array::from_fn(|index| index as u32));
        let forties = value([42; BABYBEAR_ELEMENTS_PER_VALUE]);
        Self::new_initial(vec![
            P24TreeVectorRecordV2::Permutation {
                input: state([0; P24_STATE_ELEMENTS]),
                output: state([
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
                ]),
            },
            P24TreeVectorRecordV2::Permutation {
                input: state(core::array::from_fn(|index| index as u32)),
                output: state([
                    785_637_949,
                    311_566_256,
                    241_540_729,
                    1_641_553_353,
                    851_108_667,
                    1_648_913_123,
                    510_139_232,
                    616_108_837,
                    707_720_633,
                    1_357_404_478,
                    1_539_840_236,
                    275_323_287,
                    899_761_440,
                    732_341_189,
                    664_618_988,
                    1_426_148_993,
                    1_498_654_335,
                    792_736_017,
                    1_804_085_503,
                    402_731_039,
                    659_103_866,
                    1_036_635_937,
                    1_016_617_890,
                    1_470_732_388,
                ]),
            },
            P24TreeVectorRecordV2::Leaf {
                note: ascending,
                leaf: value([
                    1_885_520_353,
                    817_880_247,
                    179_016_861,
                    1_670_698_945,
                    1_003_043_622,
                    1_660_823_950,
                    418_310_182,
                    145_631_727,
                    1_931_043_094,
                    552_715_547,
                    217_320_907,
                    336_527_988,
                    950_393_991,
                    29_613_778,
                    1_342_823_976,
                    594_627_989,
                ]),
            },
            P24TreeVectorRecordV2::Empty {
                level: 0,
                value: value([
                    1_512_554_497,
                    689_510_411,
                    298_804_240,
                    226_781_819,
                    1_699_451_698,
                    1_897_505_306,
                    494_919_784,
                    91_749_885,
                    525_457_148,
                    1_975_785_775,
                    1_454_528_822,
                    1_425_803_620,
                    1_638_267_585,
                    196_224_467,
                    1_850_954_458,
                    742_553_555,
                ]),
            },
            P24TreeVectorRecordV2::SmallTree {
                notes: Vec::new(),
                root: value([
                    421_415_291,
                    1_439_096_942,
                    1_801_418_607,
                    791_648_458,
                    923_180_062,
                    336_216_405,
                    1_548_328_837,
                    276_941_737,
                    1_646_407_031,
                    1_355_632_884,
                    1_840_068_405,
                    1_655_848_893,
                    1_322_611_759,
                    1_198_810_312,
                    1_439_237_937,
                    217_027_717,
                ]),
            },
            P24TreeVectorRecordV2::SmallTree {
                notes: vec![ascending],
                root: value([
                    373_411_015,
                    446_667_222,
                    1_283_249_050,
                    1_030_415_401,
                    1_153_863_167,
                    863_056_528,
                    1_182_887_606,
                    1_734_020_832,
                    976_592_531,
                    1_273_310_725,
                    52_195_675,
                    1_618_911_086,
                    636_297_535,
                    40_446_655,
                    578_434_053,
                    7_846_796,
                ]),
            },
            P24TreeVectorRecordV2::SmallTree {
                notes: vec![ascending, forties],
                root: value([
                    947_471_769,
                    1_312_214_486,
                    1_702_539_332,
                    1_169_609_440,
                    1_835_023_530,
                    50_898_665,
                    1_106_025_759,
                    1_856_856_533,
                    409_234_260,
                    1_172_338_941,
                    592_960_369,
                    1_793_134_602,
                    1_319_057_675,
                    671_860_240,
                    311_526_041,
                    511_993_212,
                ]),
            },
        ])
        .expect("frozen P24 candidate vectors are canonical")
    }

    /// Encodes this corpus with the full canonical candidate P24 manifest.
    pub fn encode(&self) -> Result<Vec<u8>, P24TreeVectorV2Error> {
        let manifest = CandidatePoseidon2P24ManifestV2::new();
        let manifest_bytes = manifest.encode()?;
        let candidate_id = manifest.candidate_id()?;
        let mut encoded =
            Vec::with_capacity(P24_TREE_VECTOR_HEADER_LENGTH + self.records.len() * 6);
        encoded.extend_from_slice(&P24_TREE_VECTOR_MAGIC);
        encoded.extend_from_slice(&P24_TREE_VECTOR_VERSION.to_be_bytes());
        encoded.extend_from_slice(&FLAGS.to_be_bytes());
        encoded.extend_from_slice(&(P24_CANDIDATE_MANIFEST_LENGTH as u16).to_be_bytes());
        encoded.extend_from_slice(&manifest_bytes);
        encoded.extend_from_slice(&candidate_id.as_bytes());
        encoded.extend_from_slice(&self.profile.encode().to_be_bytes());
        encoded.extend_from_slice(&(self.records.len() as u16).to_be_bytes());
        for record in &self.records {
            encoded.extend_from_slice(&record.canonical_bytes());
        }
        Ok(encoded)
    }

    /// Decodes only a corpus bound to the exact current candidate P24 manifest.
    pub fn decode(bytes: &[u8]) -> Result<Self, P24TreeVectorV2Error> {
        if bytes.len() > P24_TREE_VECTOR_LENGTH_LIMIT {
            return Err(P24TreeVectorV2Error::CorpusTooLarge {
                actual: bytes.len(),
                limit: P24_TREE_VECTOR_LENGTH_LIMIT,
            });
        }
        let mut reader = Reader::new(bytes);
        if reader.array::<4>()? != P24_TREE_VECTOR_MAGIC {
            return Err(P24TreeVectorV2Error::InvalidMagic);
        }
        if reader.u16()? != P24_TREE_VECTOR_VERSION {
            return Err(P24TreeVectorV2Error::UnsupportedVersion);
        }
        if reader.u16()? != FLAGS {
            return Err(P24TreeVectorV2Error::NonCanonicalHeader);
        }
        if reader.u16()? as usize != P24_CANDIDATE_MANIFEST_LENGTH {
            return Err(P24TreeVectorV2Error::InvalidManifestLength);
        }
        let manifest = reader.bytes(P24_CANDIDATE_MANIFEST_LENGTH)?;
        CandidatePoseidon2P24ManifestV2::decode(manifest)
            .map_err(P24TreeVectorV2Error::InvalidManifest)?;
        let expected_id = CandidatePoseidon2P24ManifestV2::new()
            .candidate_id()?
            .as_bytes();
        if reader.array::<32>()? != expected_id {
            return Err(P24TreeVectorV2Error::ManifestIdentityMismatch);
        }
        let profile = P24TreeVectorCoverageProfileV2::decode(reader.u16()?)?;
        let count = reader.u16()? as usize;
        if count > P24_MAX_RECORDS {
            return Err(P24TreeVectorV2Error::TooManyRecords {
                actual: count,
                limit: P24_MAX_RECORDS,
            });
        }
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let tag = reader.u8()?;
            if reader.u8()? != RECORD_FLAGS {
                return Err(P24TreeVectorV2Error::NonCanonicalRecordFlags);
            }
            let length = reader.u32()? as usize;
            records.push(decode_record(tag, reader.bytes(length)?)?);
        }
        if !reader.is_finished() {
            return Err(P24TreeVectorV2Error::TrailingBytes);
        }
        let corpus = match profile {
            P24TreeVectorCoverageProfileV2::Initial => Self::new_initial(records)?,
        };
        if corpus.encode()? != bytes {
            return Err(P24TreeVectorV2Error::NonCanonicalRecordOrder);
        }
        Ok(corpus)
    }
}

fn state(elements: [u32; P24_STATE_ELEMENTS]) -> P24PermutationStateV2 {
    P24PermutationStateV2::from_elements(elements)
        .expect("frozen P24 permutation state is canonical")
}

fn value(elements: [u32; BABYBEAR_ELEMENTS_PER_VALUE]) -> P24TreeValueV2 {
    P24TreeValueV2::from_elements(elements).expect("frozen P24 tree value is canonical")
}

fn validate_record(record: &P24TreeVectorRecordV2) -> Result<(), P24TreeVectorV2Error> {
    match record {
        P24TreeVectorRecordV2::Empty { level, .. } if *level > P24_TREE_DEPTH as u8 => {
            Err(P24TreeVectorV2Error::InvalidEmptyLevel(*level))
        }
        P24TreeVectorRecordV2::SmallTree { notes, .. }
            if notes.len() > P24_MAX_SMALL_TREE_NOTES =>
        {
            Err(P24TreeVectorV2Error::TooManySmallTreeNotes {
                actual: notes.len(),
                limit: P24_MAX_SMALL_TREE_NOTES,
            })
        }
        _ => Ok(()),
    }
}

fn encoded_length(records: &[P24TreeVectorRecordV2]) -> Result<usize, P24TreeVectorV2Error> {
    records
        .iter()
        .try_fold(P24_TREE_VECTOR_HEADER_LENGTH, |length, record| {
            length.checked_add(record.canonical_bytes().len()).ok_or(
                P24TreeVectorV2Error::CorpusTooLarge {
                    actual: usize::MAX,
                    limit: P24_TREE_VECTOR_LENGTH_LIMIT,
                },
            )
        })
}

fn decode_record(tag: u8, payload: &[u8]) -> Result<P24TreeVectorRecordV2, P24TreeVectorV2Error> {
    let mut reader = Reader::new(payload);
    let record = match tag {
        PERMUTATION_TAG => P24TreeVectorRecordV2::Permutation {
            input: reader.state()?,
            output: reader.state()?,
        },
        LEAF_TAG => P24TreeVectorRecordV2::Leaf {
            note: reader.value()?,
            leaf: reader.value()?,
        },
        NODE_TAG => P24TreeVectorRecordV2::Node {
            left: reader.value()?,
            right: reader.value()?,
            parent: reader.value()?,
        },
        EMPTY_TAG => P24TreeVectorRecordV2::Empty {
            level: reader.u8()?,
            value: reader.value()?,
        },
        SMALL_TREE_TAG => {
            let count = reader.u8()? as usize;
            if count > P24_MAX_SMALL_TREE_NOTES {
                return Err(P24TreeVectorV2Error::TooManySmallTreeNotes {
                    actual: count,
                    limit: P24_MAX_SMALL_TREE_NOTES,
                });
            }
            let mut notes = Vec::with_capacity(count);
            for _ in 0..count {
                notes.push(reader.value()?);
            }
            P24TreeVectorRecordV2::SmallTree {
                notes,
                root: reader.value()?,
            }
        }
        PATH_TAG => {
            let leaf_index = reader.u32()?;
            let leaf = reader.value()?;
            let mut values = Vec::with_capacity(P24_TREE_DEPTH);
            for _ in 0..P24_TREE_DEPTH {
                values.push(reader.value()?);
            }
            let siblings = values
                .try_into()
                .map_err(|_| P24TreeVectorV2Error::Truncated)?;
            P24TreeVectorRecordV2::Path {
                leaf_index,
                leaf,
                siblings: Box::new(siblings),
                root: reader.value()?,
            }
        }
        _ => return Err(P24TreeVectorV2Error::UnsupportedRecordKind(tag)),
    };
    if !reader.is_finished() {
        return Err(P24TreeVectorV2Error::InvalidRecordLength);
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
    fn bytes(&mut self, length: usize) -> Result<&'a [u8], P24TreeVectorV2Error> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(P24TreeVectorV2Error::Truncated)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(P24TreeVectorV2Error::Truncated)?;
        self.offset = end;
        Ok(bytes)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], P24TreeVectorV2Error> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| P24TreeVectorV2Error::Truncated)
    }
    fn u8(&mut self) -> Result<u8, P24TreeVectorV2Error> {
        Ok(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, P24TreeVectorV2Error> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, P24TreeVectorV2Error> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn value(&mut self) -> Result<P24TreeValueV2, P24TreeVectorV2Error> {
        P24TreeValueV2::new(self.array()?)
    }
    fn state(&mut self) -> Result<P24PermutationStateV2, P24TreeVectorV2Error> {
        P24PermutationStateV2::new(self.array()?)
    }
    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

/// Errors produced while framing NXTV v2 P24 evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum P24TreeVectorV2Error {
    Candidate(Poseidon2P24CandidateError),
    CorpusTooLarge { actual: usize, limit: usize },
    InvalidMagic,
    UnsupportedVersion,
    NonCanonicalHeader,
    InvalidManifestLength,
    InvalidManifest(Poseidon2P24CandidateError),
    ManifestIdentityMismatch,
    UnsupportedCoverageProfile(u16),
    TooManyRecords { actual: usize, limit: usize },
    NonCanonicalRecordFlags,
    UnsupportedRecordKind(u8),
    InvalidRecordLength,
    InvalidTreeValue(PrivacyTypesError),
    NonCanonicalStateElement { index: usize, element: u32 },
    InvalidEmptyLevel(u8),
    TooManySmallTreeNotes { actual: usize, limit: usize },
    DuplicateRecord,
    NonCanonicalRecordOrder,
    Truncated,
    TrailingBytes,
}

impl From<Poseidon2P24CandidateError> for P24TreeVectorV2Error {
    fn from(value: Poseidon2P24CandidateError) -> Self {
        Self::Candidate(value)
    }
}

impl fmt::Display for P24TreeVectorV2Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Candidate(error) => write!(formatter, "invalid P24 candidate: {error}"),
            Self::CorpusTooLarge { actual, limit } => write!(
                formatter,
                "NXTV v2 corpus length is {actual}, limit is {limit}"
            ),
            Self::InvalidMagic => formatter.write_str("invalid NXTV v2 magic"),
            Self::UnsupportedVersion => formatter.write_str("unsupported NXTV v2 version"),
            Self::NonCanonicalHeader => formatter.write_str("non-canonical NXTV v2 header"),
            Self::InvalidManifestLength => {
                formatter.write_str("invalid P24 manifest length in NXTV v2 header")
            }
            Self::InvalidManifest(error) => {
                write!(formatter, "invalid P24 manifest in NXTV v2 header: {error}")
            }
            Self::ManifestIdentityMismatch => {
                formatter.write_str("NXTV v2 P24 manifest identity mismatch")
            }
            Self::UnsupportedCoverageProfile(profile) => {
                write!(formatter, "unsupported NXTV v2 coverage profile {profile}")
            }
            Self::TooManyRecords { actual, limit } => {
                write!(formatter, "NXTV v2 has {actual} records, limit is {limit}")
            }
            Self::NonCanonicalRecordFlags => {
                formatter.write_str("non-canonical NXTV v2 record flags")
            }
            Self::UnsupportedRecordKind(kind) => {
                write!(formatter, "unsupported NXTV v2 record kind {kind}")
            }
            Self::InvalidRecordLength => {
                formatter.write_str("invalid NXTV v2 record payload length")
            }
            Self::InvalidTreeValue(error) => {
                write!(formatter, "invalid NXTV v2 tree value: {error}")
            }
            Self::NonCanonicalStateElement { index, element } => write!(
                formatter,
                "non-canonical NXTV v2 P24 state element {index}: {element}"
            ),
            Self::InvalidEmptyLevel(level) => {
                write!(formatter, "invalid NXTV v2 empty level {level}")
            }
            Self::TooManySmallTreeNotes { actual, limit } => write!(
                formatter,
                "NXTV v2 small tree has {actual} notes, limit is {limit}"
            ),
            Self::DuplicateRecord => formatter.write_str("duplicate NXTV v2 record"),
            Self::NonCanonicalRecordOrder => {
                formatter.write_str("non-canonical NXTV v2 record order")
            }
            Self::Truncated => formatter.write_str("truncated NXTV v2 corpus"),
            Self::TrailingBytes => formatter.write_str("trailing bytes in NXTV v2 corpus"),
        }
    }
}

impl std::error::Error for P24TreeVectorV2Error {}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(seed: u32) -> P24PermutationStateV2 {
        P24PermutationStateV2::from_elements(core::array::from_fn(|index| seed + index as u32))
            .unwrap()
    }
    fn value(seed: u32) -> P24TreeValueV2 {
        P24TreeValueV2::from_elements(core::array::from_fn(|index| seed + index as u32)).unwrap()
    }

    #[test]
    fn corpus_round_trips_and_binds_the_full_p24_manifest() {
        let corpus = P24TreeVectorCorpusV2::new_initial(vec![
            P24TreeVectorRecordV2::Permutation {
                input: state(0),
                output: state(42),
            },
            P24TreeVectorRecordV2::Leaf {
                note: value(1),
                leaf: value(2),
            },
            P24TreeVectorRecordV2::Node {
                left: value(3),
                right: value(4),
                parent: value(5),
            },
            P24TreeVectorRecordV2::Empty {
                level: 32,
                value: value(6),
            },
            P24TreeVectorRecordV2::SmallTree {
                notes: vec![value(7), value(8)],
                root: value(9),
            },
            P24TreeVectorRecordV2::Path {
                leaf_index: u32::MAX,
                leaf: value(10),
                siblings: Box::new(core::array::from_fn(|index| value(11 + index as u32))),
                root: value(43),
            },
        ])
        .unwrap();
        let encoded = corpus.encode().unwrap();
        assert_eq!(
            encoded.len(),
            P24_TREE_VECTOR_HEADER_LENGTH
                + corpus
                    .records()
                    .iter()
                    .map(P24TreeVectorRecordV2::canonical_bytes)
                    .map(|record| record.len())
                    .sum::<usize>()
        );
        assert_eq!(P24TreeVectorCorpusV2::decode(&encoded), Ok(corpus));
    }

    #[test]
    fn frozen_initial_corpus_is_explicitly_partial_and_round_trips() {
        let corpus = P24TreeVectorCorpusV2::frozen_initial_candidate_corpus();
        assert_eq!(corpus.profile(), P24TreeVectorCoverageProfileV2::Initial);
        assert_eq!(corpus.records().len(), 7);
        let encoded = corpus.encode().unwrap();
        assert_eq!(encoded.len(), 8_712);
        assert_eq!(P24TreeVectorCorpusV2::decode(&encoded), Ok(corpus));
    }

    #[test]
    fn decoder_rejects_header_state_and_record_mutations() {
        let corpus = P24TreeVectorCorpusV2::new_initial(vec![P24TreeVectorRecordV2::Permutation {
            input: state(0),
            output: state(42),
        }])
        .unwrap();
        let encoded = corpus.encode().unwrap();
        let mut invalid_manifest_length = encoded.clone();
        invalid_manifest_length[8] ^= 1;
        assert_eq!(
            P24TreeVectorCorpusV2::decode(&invalid_manifest_length),
            Err(P24TreeVectorV2Error::InvalidManifestLength)
        );
        let mut invalid_state = encoded.clone();
        invalid_state[P24_TREE_VECTOR_HEADER_LENGTH + 6..P24_TREE_VECTOR_HEADER_LENGTH + 10]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            P24TreeVectorCorpusV2::decode(&invalid_state),
            Err(P24TreeVectorV2Error::NonCanonicalStateElement { .. })
        ));
        let mut invalid_tag = encoded.clone();
        invalid_tag[P24_TREE_VECTOR_HEADER_LENGTH] = 99;
        assert_eq!(
            P24TreeVectorCorpusV2::decode(&invalid_tag),
            Err(P24TreeVectorV2Error::UnsupportedRecordKind(99))
        );
        let mut unsupported_profile = encoded;
        unsupported_profile[P24_TREE_VECTOR_HEADER_LENGTH - 4..P24_TREE_VECTOR_HEADER_LENGTH - 2]
            .copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            P24TreeVectorCorpusV2::decode(&unsupported_profile),
            Err(P24TreeVectorV2Error::UnsupportedCoverageProfile(1))
        );
    }

    #[test]
    fn record_limits_and_duplicates_are_rejected() {
        assert_eq!(
            P24TreeVectorCorpusV2::new_initial(vec![P24TreeVectorRecordV2::Empty {
                level: 33,
                value: value(1)
            }]),
            Err(P24TreeVectorV2Error::InvalidEmptyLevel(33))
        );
        assert!(matches!(
            P24TreeVectorCorpusV2::new_initial(vec![P24TreeVectorRecordV2::SmallTree {
                notes: vec![value(1), value(2), value(3), value(4), value(5)],
                root: value(6)
            }]),
            Err(P24TreeVectorV2Error::TooManySmallTreeNotes { .. })
        ));
        let record = P24TreeVectorRecordV2::Empty {
            level: 0,
            value: value(1),
        };
        assert_eq!(
            P24TreeVectorCorpusV2::new_initial(vec![record.clone(), record]),
            Err(P24TreeVectorV2Error::DuplicateRecord)
        );
    }
}
