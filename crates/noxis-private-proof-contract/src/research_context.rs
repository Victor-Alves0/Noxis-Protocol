//! One explicit validation-context identity for the pinned research bundle.
//!
//! This is a local candidate binding, not a selected `ProofVerifierId` or a
//! production cryptographic profile.

use noxis_stark_experiment::ResearchStarkVerifierProfileV1;
use noxis_types::ValidationContextId;
use sha2::{Digest, Sha256};

use crate::{CandidatePrivateTransferProofDeploymentV1, PrivateTransferProofDeploymentError};

/// SHA-256 domain for the local pinned-research validation-context identity.
pub const CANDIDATE_PRIVATE_RESEARCH_VALIDATION_CONTEXT_ID_DOMAIN: &[u8] =
    b"NOXIS/CANDIDATE-PRIVATE-RESEARCH-VALIDATION-CONTEXT/V1\0";
/// SHA-256 domain for the local canonical research-verifier descriptor ID.
pub const CANDIDATE_PRIVATE_RESEARCH_VERIFIER_DESCRIPTOR_ID_DOMAIN: &[u8] =
    b"NOXIS/CANDIDATE-PRIVATE-RESEARCH-VERIFIER-DESCRIPTOR-ID/V1\0";
/// Exact byte count of the no-magic local descriptor.
pub const CANDIDATE_PRIVATE_RESEARCH_VERIFIER_DESCRIPTOR_ENCODED_LENGTH: usize = 56;

/// Fixed, no-magic representation of the exact code-level profiles used by
/// the retained three-proof bundle. It is deliberately not a wire, storage or
/// consensus format; it exists so the context derivation has reviewable bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidatePrivateResearchVerifierDescriptorV1;

impl Default for CandidatePrivateResearchVerifierDescriptorV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl CandidatePrivateResearchVerifierDescriptorV1 {
    pub const fn new() -> Self {
        Self
    }

    pub fn encode(
        self,
    ) -> Result<
        [u8; CANDIDATE_PRIVATE_RESEARCH_VERIFIER_DESCRIPTOR_ENCODED_LENGTH],
        CandidatePrivateResearchContextError,
    > {
        let deployment = CandidatePrivateTransferProofDeploymentV1::new().candidate_id()?;
        let mut bytes = [0; CANDIDATE_PRIVATE_RESEARCH_VERIFIER_DESCRIPTOR_ENCODED_LENGTH];
        bytes[..2].copy_from_slice(&1_u16.to_be_bytes());
        bytes[2..34].copy_from_slice(&deployment.as_bytes());
        encode_profile(
            &mut bytes[34..45],
            1,
            ResearchStarkVerifierProfileV1::STANDARD_P24,
        );
        encode_profile(
            &mut bytes[45..56],
            2,
            ResearchStarkVerifierProfileV1::HIGH_DEGREE_P24,
        );
        Ok(bytes)
    }

    pub fn id(self) -> Result<[u8; 32], CandidatePrivateResearchContextError> {
        let mut hasher = Sha256::new();
        hasher.update(CANDIDATE_PRIVATE_RESEARCH_VERIFIER_DESCRIPTOR_ID_DOMAIN);
        hasher.update(self.encode()?);
        Ok(hasher.finalize().into())
    }

    /// Accepts only the byte-for-byte canonical local descriptor. This does
    /// not make the descriptor a network format; it gives callers a strict
    /// boundary when comparing independently recorded local profile bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, CandidatePrivateResearchContextError> {
        if bytes.len() != CANDIDATE_PRIVATE_RESEARCH_VERIFIER_DESCRIPTOR_ENCODED_LENGTH {
            return Err(CandidatePrivateResearchContextError::DescriptorLength {
                actual: bytes.len(),
                expected: CANDIDATE_PRIVATE_RESEARCH_VERIFIER_DESCRIPTOR_ENCODED_LENGTH,
            });
        }
        if bytes != Self::new().encode()? {
            return Err(CandidatePrivateResearchContextError::NonCanonicalDescriptor);
        }
        Ok(Self)
    }
}

fn encode_profile(bytes: &mut [u8], relation: u8, profile: ResearchStarkVerifierProfileV1) {
    debug_assert_eq!(bytes.len(), 11);
    bytes[0] = relation;
    bytes[1..3].copy_from_slice(&profile.version().to_be_bytes());
    bytes[3] = u8::try_from(profile.fri_log_blowup()).expect("fixed research profile");
    bytes[4] = u8::try_from(profile.fri_log_final_poly_len()).expect("fixed research profile");
    bytes[5] = u8::try_from(profile.fri_max_log_arity()).expect("fixed research profile");
    bytes[6..8].copy_from_slice(
        &u16::try_from(profile.fri_num_queries())
            .expect("fixed research profile")
            .to_be_bytes(),
    );
    bytes[8] =
        u8::try_from(profile.fri_commit_proof_of_work_bits()).expect("fixed research profile");
    bytes[9] =
        u8::try_from(profile.fri_query_proof_of_work_bits()).expect("fixed research profile");
    bytes[10] = u8::try_from(profile.num_random_codewords()).expect("fixed research profile");
}

/// Derives the only validation-context ID accepted by the `NXPP` byte-entry
/// research admission APIs. It binds the frozen deployment and both explicit
/// code-level FRI profiles used by the three retained proofs.
pub fn candidate_private_research_validation_context_id()
-> Result<ValidationContextId, CandidatePrivateResearchContextError> {
    let mut hasher = Sha256::new();
    hasher.update(CANDIDATE_PRIVATE_RESEARCH_VALIDATION_CONTEXT_ID_DOMAIN);
    hasher.update(CandidatePrivateResearchVerifierDescriptorV1::new().id()?);
    Ok(ValidationContextId::new(hasher.finalize().into()))
}

/// Rejects a state created under an unrelated validation context before proof
/// parsing or verification begins.
pub fn require_candidate_private_research_validation_context(
    actual: ValidationContextId,
) -> Result<(), CandidatePrivateResearchContextError> {
    let expected = candidate_private_research_validation_context_id()?;
    if actual != expected {
        return Err(CandidatePrivateResearchContextError::Mismatch { expected, actual });
    }
    Ok(())
}

#[derive(Debug)]
pub enum CandidatePrivateResearchContextError {
    Deployment(PrivateTransferProofDeploymentError),
    DescriptorLength {
        actual: usize,
        expected: usize,
    },
    NonCanonicalDescriptor,
    Mismatch {
        expected: ValidationContextId,
        actual: ValidationContextId,
    },
}
impl From<PrivateTransferProofDeploymentError> for CandidatePrivateResearchContextError {
    fn from(value: PrivateTransferProofDeploymentError) -> Self {
        Self::Deployment(value)
    }
}
impl std::fmt::Display for CandidatePrivateResearchContextError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "candidate private research-context error: {self:?}"
        )
    }
}
impl std::error::Error for CandidatePrivateResearchContextError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_context_is_stable_and_rejects_an_unrelated_context() {
        let descriptor = CandidatePrivateResearchVerifierDescriptorV1::new();
        let bytes = descriptor.encode().unwrap();
        assert_eq!(
            bytes.len(),
            CANDIDATE_PRIVATE_RESEARCH_VERIFIER_DESCRIPTOR_ENCODED_LENGTH
        );
        assert_eq!(bytes[..2], 1_u16.to_be_bytes());
        assert_ne!(descriptor.id().unwrap(), [0; 32]);
        assert_eq!(
            CandidatePrivateResearchVerifierDescriptorV1::decode(&bytes).unwrap(),
            descriptor
        );
        let mut changed = bytes;
        changed[0] ^= 1;
        assert!(matches!(
            CandidatePrivateResearchVerifierDescriptorV1::decode(&changed),
            Err(CandidatePrivateResearchContextError::NonCanonicalDescriptor)
        ));
        let context = candidate_private_research_validation_context_id().unwrap();
        assert_ne!(context.0, [0; 32]);
        require_candidate_private_research_validation_context(context).unwrap();
        assert!(matches!(
            require_candidate_private_research_validation_context(ValidationContextId::new(
                [7; 32]
            )),
            Err(CandidatePrivateResearchContextError::Mismatch { .. })
        ));
    }
}
