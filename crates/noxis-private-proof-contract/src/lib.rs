//! Frozen, fail-closed candidate deployment framing for the private-transfer AIR.
//!
//! `NXPD v1` preserves the exact candidate parameter and KAT chain, but has no
//! selected backend, verifier, proof format, or conversion to `ProofVerifierId`.

use std::fmt;

use noxis_privacy_types::{BABYBEAR_MODULUS, PRIVATE_TRANSFER_V2_TREE_DEPTH};
use noxis_tree_params::{
    CandidatePoseidon2P24IntentCommitmentManifestV1, P24_INTENT_COMMITMENT_INPUT_ELEMENTS,
    P24_INTENT_COMMITMENT_MANIFEST_LENGTH, P24_INTENT_VECTOR_LENGTH, P24IntentVectorCorpusV1,
    P24IntentVectorError, Poseidon2P24IntentCommitmentCandidateError,
};
use sha2::{Digest, Sha256};

mod air_profile;
mod anchored_ownership;
mod nxsm_transition;
mod nxsm_witness;
mod output_notes;
mod public_inputs;
mod public_statement;
mod transfer_preflight;
mod value_conservation;

pub use air_profile::{
    AIR_CONSTRAINT_CANONICAL_INTENT, AIR_CONSTRAINT_INPUT_NOTE_MEMBERSHIP,
    AIR_CONSTRAINT_INPUT_NULLIFIER, AIR_CONSTRAINT_NXSM_FIRST_ABSENCE,
    AIR_CONSTRAINT_NXSM_INTERMEDIATE_ROOT, AIR_CONSTRAINT_NXSM_POST_ROOT,
    AIR_CONSTRAINT_OUTPUT_NOTES, AIR_CONSTRAINT_PUBLIC_CROSS_BINDINGS, AIR_CONSTRAINT_UNIQUENESS,
    AIR_CONSTRAINT_VALUE_CONSERVATION, CANDIDATE_PRIVATE_TRANSFER_AIR_PROFILE_ENCODED_LENGTH,
    CANDIDATE_PRIVATE_TRANSFER_AIR_PROFILE_ID_DOMAIN, CandidatePrivateTransferAirProfileError,
    CandidatePrivateTransferAirProfileIdV1, CandidatePrivateTransferAirProfileV1,
};
pub use anchored_ownership::{
    CandidateAnchoredOwnershipError, CandidateAnchoredOwnershipPairPreflightV1,
    CandidateAnchoredOwnershipProofV1, CandidateAnchoredOwnershipWitnessV1,
    CandidateIntentAnchoredOwnershipPairPreflightV1, CandidateIntentAnchoredOwnershipPreflightV1,
    prove_candidate_anchored_ownership, revalidate_candidate_anchored_ownership_pair_preflight,
    revalidate_candidate_intent_anchored_ownership_pair_preflight,
    revalidate_candidate_intent_anchored_ownership_preflight,
    run_candidate_anchored_ownership_pair_preflight,
    run_candidate_intent_anchored_ownership_pair_preflight,
    run_candidate_intent_anchored_ownership_preflight, verify_candidate_anchored_ownership,
};
pub use nxsm_transition::{
    CANDIDATE_NXSM_NULLIFIER_TRANSITION_ENCODED_LENGTH,
    CANDIDATE_NXSM_NULLIFIER_TRANSITION_ID_DOMAIN, CandidateNxsmNullifierTransitionError,
    CandidateNxsmNullifierTransitionIdV1, CandidateNxsmNullifierTransitionV1,
};
pub use nxsm_witness::{
    CandidateNxsmNullifierTransitionWitnessError, CandidateNxsmNullifierTransitionWitnessV1,
};
pub use output_notes::{
    CandidateIntentOutputNotesPreflightV1, CandidateOutputNoteWitnessV1, CandidateOutputNotesError,
    CandidateOutputNotesPreflightV1, revalidate_candidate_intent_output_notes_preflight,
    revalidate_candidate_output_notes_preflight, run_candidate_intent_output_notes_preflight,
    run_candidate_output_notes_preflight,
};
pub use public_inputs::{
    CandidatePrivateTransferAirPublicInputsError, CandidatePrivateTransferAirPublicInputsV1,
};
pub use public_statement::{
    CANDIDATE_PRIVATE_TRANSFER_PROOF_PUBLIC_STATEMENT_ENCODED_LENGTH,
    CANDIDATE_PRIVATE_TRANSFER_PROOF_PUBLIC_STATEMENT_ID_DOMAIN,
    CandidatePrivateTransferProofPublicStatementError,
    CandidatePrivateTransferProofPublicStatementIdV1,
    CandidatePrivateTransferProofPublicStatementV1,
};
pub use transfer_preflight::{
    CandidatePacketBoundPrivateTransferStarkPreflightV1,
    CandidatePrivateTransferStarkPreflightError, CandidatePrivateTransferStarkPreflightResultsV1,
    CandidatePrivateTransferStarkPreflightV1,
    revalidate_candidate_packet_bound_private_transfer_stark_preflight,
    revalidate_candidate_private_transfer_stark_preflight,
    run_candidate_packet_bound_private_transfer_stark_preflight,
    run_candidate_private_transfer_stark_preflight,
};
pub use value_conservation::{
    CandidateValueConservationError, CandidateValueConservationPreflightV1,
    CandidateValueNoteRoleV1, run_candidate_value_conservation_preflight,
};

/// SHA-256 domain for the full candidate-deployment checksum.
pub const PRIVATE_TRANSFER_PROOF_DEPLOYMENT_CHECKSUM_DOMAIN: &[u8] =
    b"NOXIS/PRIVATE-TRANSFER-PROOF-DEPLOYMENT-CHECKSUM/V1\0";
/// SHA-256 domain for a candidate deployment identity.
pub const PRIVATE_TRANSFER_PROOF_DEPLOYMENT_CANDIDATE_ID_DOMAIN: &[u8] =
    b"NOXIS/PRIVATE-TRANSFER-PROOF-DEPLOYMENT-CANDIDATE-ID/V1\0";
/// Exact `NXPD v1` candidate byte length.
pub const PRIVATE_TRANSFER_PROOF_DEPLOYMENT_MANIFEST_LENGTH: usize = 19_598;

const MAGIC: [u8; 4] = *b"NXPD";
const VERSION: u16 = 1;
const CANDIDATE_KIND: u8 = 1;
const FLAGS: u8 = 0;
const RELATION_PROFILE: u16 = 1;
const PUBLIC_FRAME_VERSION: u16 = 1;
const INTENT_BYTES: u16 = 640;
const DIGEST_ELEMENTS: u8 = 16;
const PUBLIC_ELEMENTS: u16 = 230;
const FIELD_ENCODING: u8 = 1;
const POSEIDON_WIDTH: u8 = 24;
const RATE: u8 = 15;
const CAPACITY: u8 = 9;
const ALPHA: u8 = 7;
const FULL_ROUNDS: u8 = 8;
const PARTIAL_ROUNDS: u8 = 21;
const REQUIRED_FUNCTIONS: u8 = 0x3f;
const BACKEND_UNSELECTED: u8 = 0;
const HEADER_LENGTH: usize = 64;
const CHECKSUM_LENGTH: usize = 32;
#[cfg(test)]
const EXPECTED_MANIFEST_SHA256: [u8; 32] = [
    0xc2, 0xbe, 0xda, 0xaa, 0x24, 0xa6, 0xed, 0x12, 0x81, 0x8e, 0x73, 0x1e, 0xe0, 0x38, 0xbb, 0xaa,
    0xa8, 0xb2, 0xfb, 0x58, 0x62, 0x90, 0x7e, 0xd3, 0xa2, 0x97, 0x80, 0x8c, 0x49, 0xca, 0x73, 0xdf,
];
#[cfg(test)]
const EXPECTED_CANDIDATE_ID: [u8; 32] = [
    0xbb, 0x77, 0x05, 0xa3, 0xa8, 0x72, 0x34, 0x2c, 0x2b, 0x21, 0x7f, 0xc8, 0x7a, 0x7a, 0x60, 0xbb,
    0xc2, 0xe6, 0xec, 0xc9, 0x2a, 0x18, 0x7a, 0x6e, 0x53, 0x9d, 0x8a, 0xcf, 0xab, 0xea, 0xf2, 0xf0,
];

/// The sole canonical candidate deployment descriptor for the current AIR frame.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CandidatePrivateTransferProofDeploymentV1;

impl CandidatePrivateTransferProofDeploymentV1 {
    /// Returns the unselected candidate; it cannot enable a proof verifier.
    pub const fn new() -> Self {
        Self
    }

    /// Encodes the header, complete NXIC/NXIV ancestors and a domain-separated checksum.
    pub fn encode(self) -> Result<Vec<u8>, PrivateTransferProofDeploymentError> {
        let nxic = CandidatePoseidon2P24IntentCommitmentManifestV1::new().encode()?;
        let nxiv = P24IntentVectorCorpusV1::frozen_external_kat_corpus().encode()?;
        let mut bytes = Vec::with_capacity(PRIVATE_TRANSFER_PROOF_DEPLOYMENT_MANIFEST_LENGTH);
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.push(CANDIDATE_KIND);
        bytes.push(FLAGS);
        bytes.extend_from_slice(&RELATION_PROFILE.to_be_bytes());
        bytes.extend_from_slice(&PUBLIC_FRAME_VERSION.to_be_bytes());
        bytes.extend_from_slice(&INTENT_BYTES.to_be_bytes());
        bytes.extend_from_slice(&(P24_INTENT_COMMITMENT_INPUT_ELEMENTS as u16).to_be_bytes());
        bytes.push(DIGEST_ELEMENTS);
        bytes.extend_from_slice(&PUBLIC_ELEMENTS.to_be_bytes());
        bytes.push(PRIVATE_TRANSFER_V2_TREE_DEPTH);
        bytes.push(2);
        bytes.push(2);
        bytes.push(FIELD_ENCODING);
        bytes.extend_from_slice(&BABYBEAR_MODULUS.to_be_bytes());
        bytes.extend_from_slice(&[
            POSEIDON_WIDTH,
            RATE,
            CAPACITY,
            ALPHA,
            FULL_ROUNDS,
            PARTIAL_ROUNDS,
            REQUIRED_FUNCTIONS,
        ]);
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend_from_slice(&(P24_INTENT_COMMITMENT_MANIFEST_LENGTH as u16).to_be_bytes());
        bytes.extend_from_slice(&(P24_INTENT_VECTOR_LENGTH as u16).to_be_bytes());
        bytes.push(BACKEND_UNSELECTED);
        bytes.extend_from_slice(&[0; 23]);
        debug_assert_eq!(bytes.len(), HEADER_LENGTH);
        bytes.extend_from_slice(&nxic);
        bytes.extend_from_slice(&nxiv);
        bytes.extend_from_slice(&checksum(&bytes));
        debug_assert_eq!(
            bytes.len(),
            PRIVATE_TRANSFER_PROOF_DEPLOYMENT_MANIFEST_LENGTH
        );
        Ok(bytes)
    }

    /// Parses only byte-for-byte canonical candidate deployment bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, PrivateTransferProofDeploymentError> {
        if bytes.len() != PRIVATE_TRANSFER_PROOF_DEPLOYMENT_MANIFEST_LENGTH {
            return Err(PrivateTransferProofDeploymentError::InvalidLength {
                actual: bytes.len(),
                expected: PRIVATE_TRANSFER_PROOF_DEPLOYMENT_MANIFEST_LENGTH,
            });
        }
        if bytes[..4] != MAGIC {
            return Err(PrivateTransferProofDeploymentError::InvalidMagic);
        }
        if bytes[4..6] != VERSION.to_be_bytes() {
            return Err(PrivateTransferProofDeploymentError::UnsupportedVersion);
        }
        if bytes[6] != CANDIDATE_KIND || bytes[7] != FLAGS {
            return Err(PrivateTransferProofDeploymentError::NonCanonicalHeader);
        }
        let checksum_offset = bytes.len() - CHECKSUM_LENGTH;
        if bytes[checksum_offset..] != checksum(&bytes[..checksum_offset]) {
            return Err(PrivateTransferProofDeploymentError::ChecksumMismatch);
        }
        CandidatePoseidon2P24IntentCommitmentManifestV1::decode(
            &bytes[HEADER_LENGTH..HEADER_LENGTH + P24_INTENT_COMMITMENT_MANIFEST_LENGTH],
        )?;
        P24IntentVectorCorpusV1::decode(
            &bytes[HEADER_LENGTH + P24_INTENT_COMMITMENT_MANIFEST_LENGTH..checksum_offset],
        )?;
        if bytes != Self::new().encode()? {
            return Err(PrivateTransferProofDeploymentError::NonCanonicalManifest);
        }
        Ok(Self)
    }

    /// Separate candidate identity, intentionally not a `ProofVerifierId`.
    pub fn candidate_id(
        self,
    ) -> Result<CandidatePrivateTransferProofDeploymentIdV1, PrivateTransferProofDeploymentError>
    {
        let mut hasher = Sha256::new();
        hasher.update(PRIVATE_TRANSFER_PROOF_DEPLOYMENT_CANDIDATE_ID_DOMAIN);
        hasher.update(self.encode()?);
        Ok(CandidatePrivateTransferProofDeploymentIdV1(
            hasher.finalize().into(),
        ))
    }

    /// Candidate v1 has no selected proof backend and can never be activated.
    pub const fn require_selected_backend(
        self,
    ) -> Result<(), PrivateTransferProofDeploymentUseError> {
        let _ = self;
        Err(PrivateTransferProofDeploymentUseError::UnselectedBackend)
    }
}

fn checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PRIVATE_TRANSFER_PROOF_DEPLOYMENT_CHECKSUM_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Candidate identity that cannot be supplied to the active verifier API.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CandidatePrivateTransferProofDeploymentIdV1([u8; 32]);
impl CandidatePrivateTransferProofDeploymentIdV1 {
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}
impl fmt::Display for CandidatePrivateTransferProofDeploymentIdV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A candidate cannot be used as a proof backend or a service authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivateTransferProofDeploymentUseError {
    UnselectedBackend,
}
impl fmt::Display for PrivateTransferProofDeploymentUseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("private-transfer proof backend is unselected")
    }
}
impl std::error::Error for PrivateTransferProofDeploymentUseError {}

/// Errors while reading the frozen candidate artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrivateTransferProofDeploymentError {
    NXIC(Poseidon2P24IntentCommitmentCandidateError),
    NXIV(P24IntentVectorError),
    InvalidLength { actual: usize, expected: usize },
    InvalidMagic,
    UnsupportedVersion,
    NonCanonicalHeader,
    ChecksumMismatch,
    NonCanonicalManifest,
}
impl From<Poseidon2P24IntentCommitmentCandidateError> for PrivateTransferProofDeploymentError {
    fn from(value: Poseidon2P24IntentCommitmentCandidateError) -> Self {
        Self::NXIC(value)
    }
}
impl From<P24IntentVectorError> for PrivateTransferProofDeploymentError {
    fn from(value: P24IntentVectorError) -> Self {
        Self::NXIV(value)
    }
}
impl fmt::Display for PrivateTransferProofDeploymentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "NXPD v1 error: {self:?}")
    }
}
impl std::error::Error for PrivateTransferProofDeploymentError {}

#[cfg(test)]
mod tests {
    use super::*;
    use noxis_privacy_types::PrivateTransferIntentV2;
    #[test]
    fn frozen_candidate_binds_the_full_chain_and_rejects_activation() {
        let deployment = CandidatePrivateTransferProofDeploymentV1::new();
        let encoded = deployment.encode().unwrap();
        assert_eq!(
            encoded.len(),
            PRIVATE_TRANSFER_PROOF_DEPLOYMENT_MANIFEST_LENGTH
        );
        assert_eq!(
            Sha256::digest(&encoded).as_slice(),
            EXPECTED_MANIFEST_SHA256
        );
        assert_eq!(
            deployment.candidate_id().unwrap().as_bytes(),
            EXPECTED_CANDIDATE_ID
        );
        assert_eq!(
            PrivateTransferIntentV2::ENCODED_LENGTH,
            usize::from(INTENT_BYTES)
        );
        assert_eq!(
            P24_INTENT_COMMITMENT_INPUT_ELEMENTS + usize::from(DIGEST_ELEMENTS),
            usize::from(PUBLIC_ELEMENTS)
        );
        assert_eq!(
            CandidatePrivateTransferProofDeploymentV1::decode(&encoded),
            Ok(deployment)
        );
        assert_ne!(deployment.candidate_id().unwrap().as_bytes(), [0; 32]);
        assert_eq!(
            deployment.require_selected_backend(),
            Err(PrivateTransferProofDeploymentUseError::UnselectedBackend)
        );
    }
    #[test]
    fn parser_rejects_each_framing_ancestor_and_checksum_region() {
        let canonical = CandidatePrivateTransferProofDeploymentV1::new()
            .encode()
            .unwrap();
        for index in [
            0,
            4,
            6,
            8,
            12,
            17,
            23,
            33,
            36,
            40,
            HEADER_LENGTH,
            HEADER_LENGTH + P24_INTENT_COMMITMENT_MANIFEST_LENGTH,
            canonical.len() - 1,
        ] {
            let mut changed = canonical.clone();
            changed[index] ^= 1;
            assert!(CandidatePrivateTransferProofDeploymentV1::decode(&changed).is_err());
        }
    }
}
