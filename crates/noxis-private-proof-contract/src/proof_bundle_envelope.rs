//! Canonical local research envelope for one retained three-proof bundle.
//!
//! `NXPP v1` is deliberately separate from `NXPT v1`. It binds raw
//! pinned-research proof chunks to the current frozen candidate deployment
//! and a caller-supplied `NXPU v1` statement, but it is not network, ABCI,
//! wallet, consensus, or selected-verifier admission. Decoding returns a
//! usable bundle only after independently verifying all three proofs.

use std::fmt;

use noxis_nullifier_tree_state::NullifierSparseTreeStateV1;
use noxis_poseidon2_reference::BabyBearDigestV2;
use noxis_privacy_types::{NoteCommitmentV2, PrivacyTypesError};
use sha2::{Digest, Sha256};

use crate::{
    CANDIDATE_PRIVATE_PROOF_TRANSPORT_MAX_ENVELOPE_BYTES,
    CandidatePrivateProofTransportBudgetError, CandidatePrivateProofTransportBudgetV1,
    CandidatePrivateTransferProofBundleError, CandidatePrivateTransferProofBundleV1,
    CandidatePrivateTransferProofDeploymentV1, CandidatePrivateTransferProofPublicStatementV1,
    PrivateTransferProofDeploymentError,
};

/// `NXPP v1` envelope version.
pub const CANDIDATE_PRIVATE_PROOF_BUNDLE_ENVELOPE_VERSION: u16 = 1;
/// SHA-256 checksum domain for the exact `NXPP v1` bytes before the checksum.
pub const CANDIDATE_PRIVATE_PROOF_BUNDLE_ENVELOPE_CHECKSUM_DOMAIN: &[u8] =
    b"NOXIS/CANDIDATE-PRIVATE-PROOF-BUNDLE-ENVELOPE-CHECKSUM/V1\0";
/// SHA-256 domain for a local identity of exact `NXPP v1` bytes.
///
/// This is a local receipt correlation handle, not a transaction ID,
/// consensus identity or permission to disclose an envelope.
pub const CANDIDATE_PRIVATE_PROOF_BUNDLE_ENVELOPE_ID_DOMAIN: &[u8] =
    b"NOXIS/CANDIDATE-PRIVATE-PROOF-BUNDLE-ENVELOPE-ID/V1\0";

const MAGIC: [u8; 4] = *b"NXPP";
const FLAGS: u16 = 0;
const DEPLOYMENT_ID_OFFSET: usize = 8;
const STATEMENT_ID_OFFSET: usize = DEPLOYMENT_ID_OFFSET + 32;
const INPUT_COMMITMENTS_OFFSET: usize = STATEMENT_ID_OFFSET + 32;
const PROOF_LENGTHS_OFFSET: usize = INPUT_COMMITMENTS_OFFSET + (2 * NoteCommitmentV2::LENGTH);
const PROOF_CHUNKS_OFFSET: usize = PROOF_LENGTHS_OFFSET + (3 * 4);
const CHECKSUM_LENGTH: usize = 32;
const FIXED_OVERHEAD_BYTES: usize = PROOF_CHUNKS_OFFSET + CHECKSUM_LENGTH;

/// Canonical local envelope around one complete research proof bundle.
///
/// The type has no public fields and no plain `decode`: raw bytes are not
/// useful until their statement/current-state bindings and three P3 proofs
/// have been independently checked.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CandidatePrivateProofBundleEnvelopeV1;

/// Local identity of exact `NXPP v1` bytes after successful admission.
///
/// It has no decoder and cannot authenticate, authorize or recreate the
/// envelope. Repeated byte-for-byte submissions have the same value.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CandidatePrivateProofBundleEnvelopeIdV1([u8; 32]);

impl CandidatePrivateProofBundleEnvelopeIdV1 {
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Display for CandidatePrivateProofBundleEnvelopeIdV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl CandidatePrivateProofBundleEnvelopeV1 {
    /// Canonically serializes a typed in-memory bundle under this research
    /// envelope. It does not substitute for later decode-and-verify admission.
    pub fn encode(
        bundle: &CandidatePrivateTransferProofBundleV1,
        statement: &CandidatePrivateTransferProofPublicStatementV1,
    ) -> Result<Vec<u8>, CandidatePrivateProofBundleEnvelopeError> {
        if bundle.statement_id() != statement.statement_id() {
            return Err(CandidatePrivateProofBundleEnvelopeError::StatementIdMismatch);
        }
        let parts = bundle.pinned_research_transport_parts()?;
        let proof_lengths = [
            parts.intent_value_proof.len(),
            parts.input_ownership_proofs[0].len(),
            parts.input_ownership_proofs[1].len(),
        ];
        let proof_bytes = proof_lengths.iter().try_fold(0_usize, |total, length| {
            total
                .checked_add(*length)
                .ok_or(CandidatePrivateProofBundleEnvelopeError::ProofLengthOverflow)
        })?;
        let total = CandidatePrivateProofTransportBudgetV1::ensure_envelope_components(
            proof_bytes,
            FIXED_OVERHEAD_BYTES,
        )?;
        let expected = FIXED_OVERHEAD_BYTES
            .checked_add(proof_bytes)
            .ok_or(CandidatePrivateProofBundleEnvelopeError::ProofLengthOverflow)?;
        debug_assert_eq!(total, expected);
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&CANDIDATE_PRIVATE_PROOF_BUNDLE_ENVELOPE_VERSION.to_be_bytes());
        bytes.extend_from_slice(&FLAGS.to_be_bytes());
        bytes.extend_from_slice(
            &CandidatePrivateTransferProofDeploymentV1::new()
                .candidate_id()?
                .as_bytes(),
        );
        bytes.extend_from_slice(&statement.statement_id().as_bytes());
        for commitment in parts.input_note_commitments {
            bytes.extend_from_slice(&NoteCommitmentV2::from_elements(commitment)?.as_bytes());
        }
        for length in proof_lengths {
            let length = u32::try_from(length)
                .map_err(|_| CandidatePrivateProofBundleEnvelopeError::ProofLengthOverflow)?;
            bytes.extend_from_slice(&length.to_be_bytes());
        }
        bytes.extend_from_slice(&parts.intent_value_proof);
        bytes.extend_from_slice(&parts.input_ownership_proofs[0]);
        bytes.extend_from_slice(&parts.input_ownership_proofs[1]);
        bytes.extend_from_slice(&checksum(&bytes));
        debug_assert_eq!(bytes.len(), total);
        Ok(bytes)
    }

    /// Strictly frames, reconstructs and independently verifies all proof
    /// relations against the exact supplied statement and current tree.
    pub fn decode_and_verify(
        bytes: &[u8],
        statement: &CandidatePrivateTransferProofPublicStatementV1,
        current_tree: &NullifierSparseTreeStateV1,
    ) -> Result<CandidatePrivateTransferProofBundleV1, CandidatePrivateProofBundleEnvelopeError>
    {
        let frame = parse_frame(bytes, statement)?;
        let bundle = CandidatePrivateTransferProofBundleV1::decode_pinned_research_transport_parts(
            statement,
            frame.input_note_commitments,
            frame.proof_chunks[0],
            [frame.proof_chunks[1], frame.proof_chunks[2]],
        )?;
        crate::verify_candidate_private_transfer_proof_bundle(&bundle, statement, current_tree)?;
        Ok(bundle)
    }
}

struct ParsedFrame<'a> {
    input_note_commitments: [BabyBearDigestV2; 2],
    proof_chunks: [&'a [u8]; 3],
}

fn parse_frame<'a>(
    bytes: &'a [u8],
    statement: &CandidatePrivateTransferProofPublicStatementV1,
) -> Result<ParsedFrame<'a>, CandidatePrivateProofBundleEnvelopeError> {
    if bytes.len() < FIXED_OVERHEAD_BYTES {
        return Err(CandidatePrivateProofBundleEnvelopeError::Truncated);
    }
    if bytes.len() > CANDIDATE_PRIVATE_PROOF_TRANSPORT_MAX_ENVELOPE_BYTES {
        return Err(
            CandidatePrivateProofBundleEnvelopeError::EnvelopeBytesExceedLimit {
                actual: bytes.len(),
                maximum: CANDIDATE_PRIVATE_PROOF_TRANSPORT_MAX_ENVELOPE_BYTES,
            },
        );
    }
    if bytes[..4] != MAGIC {
        return Err(CandidatePrivateProofBundleEnvelopeError::InvalidMagic);
    }
    if bytes[4..6] != CANDIDATE_PRIVATE_PROOF_BUNDLE_ENVELOPE_VERSION.to_be_bytes() {
        return Err(CandidatePrivateProofBundleEnvelopeError::UnsupportedVersion);
    }
    if bytes[6..8] != FLAGS.to_be_bytes() {
        return Err(CandidatePrivateProofBundleEnvelopeError::NonCanonicalFlags);
    }
    let expected_deployment_id = CandidatePrivateTransferProofDeploymentV1::new()
        .candidate_id()?
        .as_bytes();
    if bytes[DEPLOYMENT_ID_OFFSET..STATEMENT_ID_OFFSET] != expected_deployment_id {
        return Err(CandidatePrivateProofBundleEnvelopeError::DeploymentIdMismatch);
    }
    if bytes[STATEMENT_ID_OFFSET..INPUT_COMMITMENTS_OFFSET] != statement.statement_id().as_bytes() {
        return Err(CandidatePrivateProofBundleEnvelopeError::StatementIdMismatch);
    }
    let input_note_commitments: [Result<BabyBearDigestV2, PrivacyTypesError>; 2] =
        core::array::from_fn(|index| {
            let start = INPUT_COMMITMENTS_OFFSET + (index * NoteCommitmentV2::LENGTH);
            let end = start + NoteCommitmentV2::LENGTH;
            let raw: [u8; NoteCommitmentV2::LENGTH] = bytes[start..end]
                .try_into()
                .expect("fixed candidate envelope commitment width");
            NoteCommitmentV2::new(raw).map(|value| value.elements())
        });
    let input_note_commitments = [input_note_commitments[0]?, input_note_commitments[1]?];
    let proof_lengths: [usize; 3] = core::array::from_fn(|index| {
        let start = PROOF_LENGTHS_OFFSET + (index * 4);
        u32::from_be_bytes(
            bytes[start..start + 4]
                .try_into()
                .expect("fixed candidate envelope proof-length width"),
        ) as usize
    });
    if let Some((index, _)) = proof_lengths
        .iter()
        .enumerate()
        .find(|(_, length)| **length == 0)
    {
        return Err(CandidatePrivateProofBundleEnvelopeError::EmptyProofChunk { index });
    }
    let proof_bytes = proof_lengths.iter().try_fold(0_usize, |total, length| {
        total
            .checked_add(*length)
            .ok_or(CandidatePrivateProofBundleEnvelopeError::ProofLengthOverflow)
    })?;
    let expected_length = FIXED_OVERHEAD_BYTES
        .checked_add(proof_bytes)
        .ok_or(CandidatePrivateProofBundleEnvelopeError::ProofLengthOverflow)?;
    if bytes.len() != expected_length {
        return Err(
            CandidatePrivateProofBundleEnvelopeError::DeclaredLengthMismatch {
                actual: bytes.len(),
                expected: expected_length,
            },
        );
    }
    CandidatePrivateProofTransportBudgetV1::ensure_envelope_components(
        proof_bytes,
        FIXED_OVERHEAD_BYTES,
    )?;
    let checksum_start = bytes.len() - CHECKSUM_LENGTH;
    if bytes[checksum_start..] != checksum(&bytes[..checksum_start]) {
        return Err(CandidatePrivateProofBundleEnvelopeError::ChecksumMismatch);
    }
    let mut cursor = PROOF_CHUNKS_OFFSET;
    let proof_chunks = core::array::from_fn(|index| {
        let end = cursor + proof_lengths[index];
        let chunk = &bytes[cursor..end];
        cursor = end;
        chunk
    });
    debug_assert_eq!(cursor, checksum_start);
    Ok(ParsedFrame {
        input_note_commitments,
        proof_chunks,
    })
}

fn checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CANDIDATE_PRIVATE_PROOF_BUNDLE_ENVELOPE_CHECKSUM_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().into()
}

pub(crate) fn candidate_private_proof_bundle_envelope_id(
    bytes: &[u8],
) -> CandidatePrivateProofBundleEnvelopeIdV1 {
    let mut hasher = Sha256::new();
    hasher.update(CANDIDATE_PRIVATE_PROOF_BUNDLE_ENVELOPE_ID_DOMAIN);
    hasher.update(bytes);
    CandidatePrivateProofBundleEnvelopeIdV1(hasher.finalize().into())
}

/// Fail-closed `NXPP v1` framing, reconstruction and verification errors.
#[derive(Debug)]
pub enum CandidatePrivateProofBundleEnvelopeError {
    Bundle(CandidatePrivateTransferProofBundleError),
    Budget(CandidatePrivateProofTransportBudgetError),
    Deployment(PrivateTransferProofDeploymentError),
    PrivacyTypes(PrivacyTypesError),
    EnvelopeBytesExceedLimit { actual: usize, maximum: usize },
    ProofLengthOverflow,
    Truncated,
    InvalidMagic,
    UnsupportedVersion,
    NonCanonicalFlags,
    DeploymentIdMismatch,
    StatementIdMismatch,
    EmptyProofChunk { index: usize },
    DeclaredLengthMismatch { actual: usize, expected: usize },
    ChecksumMismatch,
}

impl From<CandidatePrivateTransferProofBundleError> for CandidatePrivateProofBundleEnvelopeError {
    fn from(value: CandidatePrivateTransferProofBundleError) -> Self {
        Self::Bundle(value)
    }
}
impl From<CandidatePrivateProofTransportBudgetError> for CandidatePrivateProofBundleEnvelopeError {
    fn from(value: CandidatePrivateProofTransportBudgetError) -> Self {
        Self::Budget(value)
    }
}
impl From<PrivateTransferProofDeploymentError> for CandidatePrivateProofBundleEnvelopeError {
    fn from(value: PrivateTransferProofDeploymentError) -> Self {
        Self::Deployment(value)
    }
}
impl From<PrivacyTypesError> for CandidatePrivateProofBundleEnvelopeError {
    fn from(value: PrivacyTypesError) -> Self {
        Self::PrivacyTypes(value)
    }
}
impl fmt::Display for CandidatePrivateProofBundleEnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "candidate private-proof bundle envelope error: {self:?}"
        )
    }
}
impl std::error::Error for CandidatePrivateProofBundleEnvelopeError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical_synthetic_frame(proof_lengths: [usize; 3]) -> Vec<u8> {
        let proof_bytes = proof_lengths.iter().sum::<usize>();
        let total = FIXED_OVERHEAD_BYTES + proof_bytes;
        let mut bytes = vec![0_u8; total];
        bytes[..4].copy_from_slice(&MAGIC);
        bytes[4..6].copy_from_slice(&CANDIDATE_PRIVATE_PROOF_BUNDLE_ENVELOPE_VERSION.to_be_bytes());
        bytes[6..8].copy_from_slice(&FLAGS.to_be_bytes());
        let deployment = CandidatePrivateTransferProofDeploymentV1::new()
            .candidate_id()
            .unwrap()
            .as_bytes();
        bytes[DEPLOYMENT_ID_OFFSET..STATEMENT_ID_OFFSET].copy_from_slice(&deployment);
        for index in 0..2 {
            let start = INPUT_COMMITMENTS_OFFSET + (index * NoteCommitmentV2::LENGTH);
            bytes[start..start + NoteCommitmentV2::LENGTH].copy_from_slice(
                &NoteCommitmentV2::from_elements([index as u32 + 1; 16])
                    .unwrap()
                    .as_bytes(),
            );
        }
        for (index, length) in proof_lengths.into_iter().enumerate() {
            let start = PROOF_LENGTHS_OFFSET + (index * 4);
            bytes[start..start + 4].copy_from_slice(&(length as u32).to_be_bytes());
        }
        let mut cursor = PROOF_CHUNKS_OFFSET;
        for length in proof_lengths {
            bytes[cursor..cursor + length].fill(0xA5);
            cursor += length;
        }
        let checksum_start = bytes.len() - CHECKSUM_LENGTH;
        let value = checksum(&bytes[..checksum_start]);
        bytes[checksum_start..].copy_from_slice(&value);
        bytes
    }

    #[test]
    fn parser_rejects_frame_violations_before_proof_deserialization() {
        let statement = statement_fixture();
        let mut canonical = canonical_synthetic_frame([1, 1, 1]);
        canonical[STATEMENT_ID_OFFSET..INPUT_COMMITMENTS_OFFSET]
            .copy_from_slice(&statement.statement_id().as_bytes());
        let checksum_start = canonical.len() - CHECKSUM_LENGTH;
        let value = checksum(&canonical[..checksum_start]);
        canonical[checksum_start..].copy_from_slice(&value);
        assert!(parse_frame(&canonical, &statement).is_ok());

        let mut changed = canonical.clone();
        changed[0] ^= 1;
        assert!(matches!(
            parse_frame(&changed, &statement),
            Err(CandidatePrivateProofBundleEnvelopeError::InvalidMagic)
        ));
        let mut changed = canonical.clone();
        changed[6] = 1;
        assert!(matches!(
            parse_frame(&changed, &statement),
            Err(CandidatePrivateProofBundleEnvelopeError::NonCanonicalFlags)
        ));
        let mut changed = canonical.clone();
        changed[PROOF_LENGTHS_OFFSET..PROOF_LENGTHS_OFFSET + 4]
            .copy_from_slice(&0_u32.to_be_bytes());
        assert!(matches!(
            parse_frame(&changed, &statement),
            Err(CandidatePrivateProofBundleEnvelopeError::EmptyProofChunk { index: 0 })
        ));
        let mut changed = canonical.clone();
        changed.push(0);
        assert!(matches!(
            parse_frame(&changed, &statement),
            Err(CandidatePrivateProofBundleEnvelopeError::DeclaredLengthMismatch { .. })
        ));
        let mut changed = canonical;
        changed[PROOF_CHUNKS_OFFSET] ^= 1;
        assert!(matches!(
            parse_frame(&changed, &statement),
            Err(CandidatePrivateProofBundleEnvelopeError::ChecksumMismatch)
        ));
    }

    #[test]
    fn envelope_identity_is_domain_separated_and_binds_exact_bytes() {
        let first = candidate_private_proof_bundle_envelope_id(b"candidate-envelope");
        let second = candidate_private_proof_bundle_envelope_id(b"candidate-envelope");
        let changed = candidate_private_proof_bundle_envelope_id(b"candidate-envelope!");
        assert_eq!(first, second);
        assert_ne!(first, changed);
        assert_ne!(first.as_bytes(), [0; 32]);
    }

    fn statement_fixture() -> CandidatePrivateTransferProofPublicStatementV1 {
        use noxis_poseidon2_reference::Poseidon2P24Reference;
        use noxis_privacy_types::{
            CiphertextDigestV2, CircuitId, NullifierV2, PrivateTransferIntentV2,
            PrivateTransferOutputV2, TreeParametersId, TreeParametersV2,
        };
        use noxis_private_state::{CandidatePrivateStateSnapshotV1, PrivateStateAnchorV2};
        use noxis_tree_params::CandidatePoseidon2P24ManifestV2;
        use noxis_types::{AssetId, GenesisId, ValidationContextId};

        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        let tree = NullifierSparseTreeStateV1::new_candidate().unwrap();
        let snapshot = CandidatePrivateStateSnapshotV1::new(
            vec![
                NoteCommitmentV2::from_elements([3; 16]).unwrap(),
                NoteCommitmentV2::from_elements([4; 16]).unwrap(),
            ],
            vec![],
            &reference,
        )
        .unwrap();
        let tree_parameters = TreeParametersV2::new(TreeParametersId::new(
            CandidatePoseidon2P24ManifestV2::new()
                .candidate_id()
                .unwrap()
                .as_bytes(),
        ));
        let anchor = PrivateStateAnchorV2::new(
            GenesisId::new([1; 32]),
            ValidationContextId::new([2; 32]),
            tree_parameters,
            &snapshot,
            &tree,
        )
        .unwrap();
        let intent = PrivateTransferIntentV2::new(
            CircuitId::new([4; 32]),
            GenesisId::new([1; 32]),
            ValidationContextId::new([2; 32]),
            anchor.state_id(),
            anchor.note_tree_parameters(),
            anchor.note_root(),
            AssetId::new([5; 32]),
            [
                NullifierV2::from_elements([6; 16]).unwrap(),
                NullifierV2::from_elements([7; 16]).unwrap(),
            ],
            [
                PrivateTransferOutputV2::new(
                    NoteCommitmentV2::from_elements([8; 16]).unwrap(),
                    CiphertextDigestV2::from_elements([9; 16]).unwrap(),
                ),
                PrivateTransferOutputV2::new(
                    NoteCommitmentV2::from_elements([10; 16]).unwrap(),
                    CiphertextDigestV2::from_elements([11; 16]).unwrap(),
                ),
            ],
        )
        .unwrap();
        CandidatePrivateTransferProofPublicStatementV1::new(anchor, &tree, intent).unwrap()
    }
}
