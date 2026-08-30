//! Canonical framing for unselected Noxis v2 tree-parameter candidates.
//!
//! This crate intentionally cannot create a recognized `TreeParametersId`, a
//! Merkle root, a proof, or a transaction-validation authorization. It freezes
//! the bytes and candidate identity that future independently verified
//! Poseidon2 parameters must use before they can enter an allowlist.

use std::fmt;

use noxis_privacy_types::{BABYBEAR_ELEMENTS_PER_VALUE, BABYBEAR_MODULUS, BABYBEAR_VECTOR_BYTES};
use sha2::{Digest, Sha256};

mod corpus;
mod corpus_v2;
mod intent_corpus_v1;
mod note_corpus_v1;
mod nullifier_sparse_corpus_v1;
mod p24;
mod p24_envelope_digest;
mod p24_intent_commitment;
mod p24_note_domains;
mod p24_nullifier_sparse;

pub use corpus::{
    DRAFT_TREE_VECTOR_LENGTH_LIMIT, DRAFT_TREE_VECTOR_MAGIC, DRAFT_TREE_VECTOR_VERSION,
    TreeVectorCorpusV1, TreeVectorError, TreeVectorRecordV1, TreeVectorValueV1,
};
pub use corpus_v2::{
    P24_TREE_VECTOR_HEADER_LENGTH, P24_TREE_VECTOR_LENGTH_LIMIT, P24_TREE_VECTOR_MAGIC,
    P24_TREE_VECTOR_VERSION, P24PermutationStateV2, P24TreeValueV2, P24TreeVectorCorpusV2,
    P24TreeVectorCoverageProfileV2, P24TreeVectorRecordV2, P24TreeVectorV2Error,
};
pub use intent_corpus_v1::{
    P24_INTENT_VECTOR_HEADER_LENGTH, P24_INTENT_VECTOR_LENGTH, P24_INTENT_VECTOR_LENGTH_LIMIT,
    P24_INTENT_VECTOR_MAGIC, P24_INTENT_VECTOR_VERSION, P24IntentVectorCaseV1,
    P24IntentVectorCorpusV1, P24IntentVectorError, P24IntentVectorRecordV1,
};
pub use note_corpus_v1::{
    P24_NOTE_VECTOR_HEADER_LENGTH, P24_NOTE_VECTOR_LENGTH_LIMIT, P24_NOTE_VECTOR_MAGIC,
    P24_NOTE_VECTOR_VERSION, P24NoteVectorCorpusV1, P24NoteVectorError, P24NoteVectorRecordV1,
};
pub use nullifier_sparse_corpus_v1::{
    NullifierSparseVectorValueV1, P24_NULLIFIER_SPARSE_VECTOR_HEADER_LENGTH,
    P24_NULLIFIER_SPARSE_VECTOR_LENGTH_LIMIT, P24_NULLIFIER_SPARSE_VECTOR_MAGIC,
    P24_NULLIFIER_SPARSE_VECTOR_VERSION, P24NullifierSparseVectorCorpusV1,
    P24NullifierSparseVectorCoverageV1, P24NullifierSparseVectorError,
    P24NullifierSparseVectorRecordV1,
};
pub use p24::{
    CandidatePoseidon2P24ManifestIdV2, CandidatePoseidon2P24ManifestV2,
    P24_CANDIDATE_MANIFEST_ID_DOMAIN, P24_CANDIDATE_MANIFEST_LENGTH, P24_PARAMETER_PAYLOAD_LENGTH,
    Poseidon2P24CandidateError, Poseidon2P24TreeDomainV1,
};
pub use p24_envelope_digest::{
    CandidatePoseidon2P24EnvelopeDigestIdV1, CandidatePoseidon2P24EnvelopeDigestV1,
    P24_ENVELOPE_DIGEST_CANDIDATE_ID_DOMAIN, P24_ENVELOPE_DIGEST_FRAME_PREFIX_BYTES,
    P24_ENVELOPE_DIGEST_LABEL, P24_ENVELOPE_DIGEST_MAX_INPUT_BYTES,
    P24_ENVELOPE_DIGEST_MAX_INPUT_ELEMENTS, P24_ENVELOPE_DIGEST_MAX_NXRE_BYTES,
    Poseidon2P24EnvelopeDigestCandidateError, Poseidon2P24EnvelopeDigestDomainV1,
};
pub use p24_intent_commitment::{
    CandidatePoseidon2P24IntentCommitmentIdV1, CandidatePoseidon2P24IntentCommitmentManifestV1,
    P24_INTENT_COMMITMENT_CANDIDATE_ID_DOMAIN, P24_INTENT_COMMITMENT_INPUT_BYTES,
    P24_INTENT_COMMITMENT_INPUT_ELEMENTS, P24_INTENT_COMMITMENT_MANIFEST_LENGTH,
    P24_INTENT_COMMITMENT_PAYLOAD_LENGTH, Poseidon2P24IntentCommitmentCandidateError,
    Poseidon2P24IntentCommitmentDomainV1,
};
pub use p24_note_domains::{
    CandidatePoseidon2P24NoteDomainsIdV1, CandidatePoseidon2P24NoteDomainsManifestV1,
    P24_BYTE_PACK_WIDTH, P24_NOTE_DOMAINS_CANDIDATE_ID_DOMAIN, P24_NOTE_DOMAINS_MANIFEST_LENGTH,
    P24_NOTE_DOMAINS_PAYLOAD_LENGTH, Poseidon2P24NoteDomainV1,
    Poseidon2P24NoteDomainsCandidateError,
};
pub use p24_nullifier_sparse::{
    CandidatePoseidon2P24NullifierSparseIdV1, CandidatePoseidon2P24NullifierSparseManifestV1,
    P24_NULLIFIER_SPARSE_CANDIDATE_ID_DOMAIN, P24_NULLIFIER_SPARSE_MANIFEST_LENGTH,
    P24_NULLIFIER_SPARSE_PAYLOAD_LENGTH, Poseidon2P24NullifierSparseCandidateError,
    Poseidon2P24NullifierSparseDomainV1,
};

/// Four-byte magic identifying a draft tree-parameter manifest.
pub const DRAFT_TREE_MANIFEST_MAGIC: [u8; 4] = *b"NXTM";
/// Framing version of a draft tree-parameter manifest.
pub const DRAFT_TREE_MANIFEST_VERSION: u16 = 1;
/// Exact byte length of the fixed v1 draft manifest.
pub const DRAFT_TREE_MANIFEST_LENGTH: usize = 24;
/// SHA-256 domain for candidate tree-manifest identities.
pub const TREE_MANIFEST_ID_DOMAIN: &[u8] = b"NOXIS/TREE-PARAMETERS-ID/V2\0";

const DRAFT_UNSELECTED_KIND: u8 = 0;
const BINARY_TREE_ARITY: u8 = 2;
const TREE_DEPTH_V2: u8 = 32;
const BABYBEAR_FIELD_ID: u8 = 1;
const BABYBEAR_LE32X16_ENCODING: u8 = 1;

/// A fixed, unselected v2 tree manifest candidate.
///
/// Its empty parameter payload proves that no Poseidon2 variant, constants,
/// sponge or tree function has been selected. It exists only to freeze the
/// canonical field representation and the candidate-ID derivation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DraftTreeManifestV1;

impl DraftTreeManifestV1 {
    /// Returns the single canonical draft candidate allowed by v1 framing.
    pub const fn new() -> Self {
        Self
    }

    /// Encodes the complete canonical draft manifest.
    pub const fn encode(self) -> [u8; DRAFT_TREE_MANIFEST_LENGTH] {
        [
            b'N',
            b'X',
            b'T',
            b'M',
            0,
            DRAFT_TREE_MANIFEST_VERSION as u8,
            DRAFT_UNSELECTED_KIND,
            0,
            TREE_DEPTH_V2,
            BINARY_TREE_ARITY,
            BABYBEAR_FIELD_ID,
            BABYBEAR_LE32X16_ENCODING,
            BABYBEAR_ELEMENTS_PER_VALUE as u8,
            0,
            0,
            0,
            0x78,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
        ]
    }

    /// Decodes only the exact, currently unselected draft manifest.
    pub fn decode(bytes: &[u8]) -> Result<Self, TreeParamsError> {
        if bytes.len() != DRAFT_TREE_MANIFEST_LENGTH {
            return Err(TreeParamsError::InvalidManifestLength {
                actual: bytes.len(),
                expected: DRAFT_TREE_MANIFEST_LENGTH,
            });
        }
        let canonical = Self::new().encode();
        if bytes[..4] != DRAFT_TREE_MANIFEST_MAGIC {
            return Err(TreeParamsError::InvalidManifestMagic);
        }
        if bytes[4..6] != DRAFT_TREE_MANIFEST_VERSION.to_be_bytes() {
            return Err(TreeParamsError::UnsupportedManifestVersion);
        }
        if bytes[6] != DRAFT_UNSELECTED_KIND {
            return Err(TreeParamsError::UnsupportedManifestKind);
        }
        if bytes != canonical {
            return Err(TreeParamsError::NonCanonicalDraftManifest);
        }
        Ok(Self)
    }

    /// Returns a candidate identity, not a recognized tree-parameter identity.
    pub fn candidate_id(self) -> CandidateTreeManifestId {
        let mut hasher = Sha256::new();
        hasher.update(TREE_MANIFEST_ID_DOMAIN);
        hasher.update(self.encode());
        CandidateTreeManifestId(hasher.finalize().into())
    }
}

impl Default for DraftTreeManifestV1 {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash identity of a canonical but unselected draft manifest.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CandidateTreeManifestId([u8; 32]);

impl CandidateTreeManifestId {
    /// Returns the SHA-256 digest bytes in canonical order.
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Display for CandidateTreeManifestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Frozen v1 interoperability vector for BabyBear field serialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalBabyBearVectorV1 {
    elements: [u32; BABYBEAR_ELEMENTS_PER_VALUE],
    encoded: [u8; BABYBEAR_VECTOR_BYTES],
}

impl CanonicalBabyBearVectorV1 {
    /// A mixed boundary vector represented independently as canonical integers.
    pub const fn frozen() -> Self {
        Self {
            elements: [
                0,
                1,
                2,
                BABYBEAR_MODULUS - 2,
                BABYBEAR_MODULUS - 1,
                42,
                65_535,
                65_536,
                16_909_060,
                987_654_321,
                5,
                6,
                7,
                8,
                9,
                10,
            ],
            encoded: [
                0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 255, 255, 255, 119, 0, 0, 0, 120, 42, 0, 0, 0,
                255, 255, 0, 0, 0, 0, 1, 0, 4, 3, 2, 1, 177, 104, 222, 58, 5, 0, 0, 0, 6, 0, 0, 0,
                7, 0, 0, 0, 8, 0, 0, 0, 9, 0, 0, 0, 10, 0, 0, 0,
            ],
        }
    }

    /// Integers in the vector's machine-independent semantic order.
    pub const fn elements(self) -> [u32; BABYBEAR_ELEMENTS_PER_VALUE] {
        self.elements
    }

    /// Exact Noxis little-endian field-element encoding.
    pub const fn encoded(self) -> [u8; BABYBEAR_VECTOR_BYTES] {
        self.encoded
    }
}

/// A fixed Poseidon2 BabyBear-16 permutation vector from two independently
/// executed external references.
///
/// This is an interoperability oracle only. It does not select a Noxis tree
/// function, constants, sponge construction, domains, or a recognized
/// `TreeParametersId`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Poseidon2BabyBear16ReferenceVectorV1 {
    input: [u32; BABYBEAR_ELEMENTS_PER_VALUE],
    output: [u32; BABYBEAR_ELEMENTS_PER_VALUE],
}

impl Poseidon2BabyBear16ReferenceVectorV1 {
    /// Returns the two fixed permutation vectors: all zeroes and all 42s.
    pub const fn frozen() -> [Self; 2] {
        [
            Self {
                input: [0; BABYBEAR_ELEMENTS_PER_VALUE],
                output: [
                    1_337_856_655,
                    1_843_094_405,
                    328_115_114,
                    964_209_316,
                    1_365_212_758,
                    1_431_554_563,
                    210_126_733,
                    1_214_932_203,
                    1_929_553_766,
                    1_647_595_522,
                    1_496_863_878,
                    324_695_999,
                    1_569_728_319,
                    1_634_598_391,
                    597_968_641,
                    679_989_771,
                ],
            },
            Self {
                input: [42; BABYBEAR_ELEMENTS_PER_VALUE],
                output: [
                    1_000_818_763,
                    32_822_117,
                    1_516_162_362,
                    1_002_505_990,
                    932_515_653,
                    770_559_770,
                    350_012_663,
                    846_936_440,
                    1_676_802_609,
                    1_007_988_059,
                    883_957_027,
                    738_985_594,
                    6_104_526,
                    338_187_715,
                    611_171_673,
                    414_573_522,
                ],
            },
        ]
    }

    /// Input elements in the permutation's semantic order.
    pub const fn input(self) -> [u32; BABYBEAR_ELEMENTS_PER_VALUE] {
        self.input
    }

    /// Expected output elements in the permutation's semantic order.
    pub const fn output(self) -> [u32; BABYBEAR_ELEMENTS_PER_VALUE] {
        self.output
    }
}

/// Errors produced when parsing canonical parameter-candidate framing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TreeParamsError {
    InvalidManifestLength { actual: usize, expected: usize },
    InvalidManifestMagic,
    UnsupportedManifestVersion,
    UnsupportedManifestKind,
    NonCanonicalDraftManifest,
}

impl fmt::Display for TreeParamsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidManifestLength { actual, expected } => write!(
                formatter,
                "draft tree manifest length is {actual}, expected {expected}"
            ),
            Self::InvalidManifestMagic => formatter.write_str("invalid draft tree manifest magic"),
            Self::UnsupportedManifestVersion => {
                formatter.write_str("unsupported draft tree manifest version")
            }
            Self::UnsupportedManifestKind => {
                formatter.write_str("unsupported draft tree manifest kind")
            }
            Self::NonCanonicalDraftManifest => {
                formatter.write_str("draft tree manifest differs from canonical v1 bytes")
            }
        }
    }
}

impl std::error::Error for TreeParamsError {}

#[cfg(test)]
mod tests {
    use super::*;
    use noxis_privacy_types::NoteCommitmentV2;

    #[test]
    fn manifest_bytes_and_candidate_identity_are_frozen() {
        let manifest = DraftTreeManifestV1::new();
        assert_eq!(
            manifest.encode(),
            [
                0x4e, 0x58, 0x54, 0x4d, 0, 1, 0, 0, 32, 2, 1, 1, 16, 0, 0, 0, 0x78, 0, 0, 1, 0, 0,
                0, 0,
            ]
        );
        assert_eq!(
            manifest.candidate_id().as_bytes(),
            [
                0x33, 0x52, 0xdd, 0xb4, 0x1c, 0xcc, 0x2d, 0x1b, 0x3e, 0x8b, 0x37, 0xd3, 0xb9, 0x3a,
                0xca, 0xe9, 0x1a, 0x81, 0xde, 0xf5, 0x7c, 0x94, 0xe7, 0x6f, 0xac, 0x14, 0x85, 0xfc,
                0xb2, 0x4e, 0xdb, 0x76,
            ]
        );
    }

    #[test]
    fn decoder_rejects_every_noncanonical_manifest_mutation() {
        let canonical = DraftTreeManifestV1::new().encode();
        assert_eq!(
            DraftTreeManifestV1::decode(&canonical),
            Ok(DraftTreeManifestV1)
        );
        for index in 0..canonical.len() {
            let mut changed = canonical;
            changed[index] ^= 1;
            assert!(DraftTreeManifestV1::decode(&changed).is_err());
        }
        assert!(DraftTreeManifestV1::decode(&canonical[..canonical.len() - 1]).is_err());
    }

    #[test]
    fn frozen_field_vector_matches_the_shared_canonical_type() {
        let vector = CanonicalBabyBearVectorV1::frozen();
        let commitment = NoteCommitmentV2::from_elements(vector.elements()).unwrap();
        assert_eq!(commitment.as_bytes(), vector.encoded());
        assert_eq!(commitment.elements(), vector.elements());
    }

    #[test]
    fn frozen_poseidon2_reference_vectors_stay_canonical_and_distinct() {
        let vectors = Poseidon2BabyBear16ReferenceVectorV1::frozen();
        assert_eq!(vectors.len(), 2);
        assert_eq!(vectors[0].input(), [0; BABYBEAR_ELEMENTS_PER_VALUE]);
        assert_eq!(vectors[1].input(), [42; BABYBEAR_ELEMENTS_PER_VALUE]);
        assert_ne!(vectors[0].output(), vectors[1].output());

        for vector in vectors {
            assert!(
                vector
                    .input()
                    .into_iter()
                    .all(|element| element < BABYBEAR_MODULUS)
            );
            assert!(
                vector
                    .output()
                    .into_iter()
                    .all(|element| element < BABYBEAR_MODULUS)
            );
        }
    }
}
