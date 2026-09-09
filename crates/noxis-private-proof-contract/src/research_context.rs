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

/// Derives the only validation-context ID accepted by the `NXPP` byte-entry
/// research admission APIs. It binds the frozen deployment and both explicit
/// code-level FRI profiles used by the three retained proofs.
pub fn candidate_private_research_validation_context_id()
-> Result<ValidationContextId, CandidatePrivateResearchContextError> {
    let deployment = CandidatePrivateTransferProofDeploymentV1::new().candidate_id()?;
    let mut hasher = Sha256::new();
    hasher.update(CANDIDATE_PRIVATE_RESEARCH_VALIDATION_CONTEXT_ID_DOMAIN);
    hasher.update(deployment.as_bytes());
    for profile in [
        ResearchStarkVerifierProfileV1::STANDARD_P24,
        ResearchStarkVerifierProfileV1::HIGH_DEGREE_P24,
    ] {
        hasher.update(profile.name().as_bytes());
        hasher.update((profile.version() as u64).to_be_bytes());
        hasher.update((profile.fri_log_blowup() as u64).to_be_bytes());
        hasher.update((profile.fri_log_final_poly_len() as u64).to_be_bytes());
        hasher.update((profile.fri_max_log_arity() as u64).to_be_bytes());
        hasher.update((profile.fri_num_queries() as u64).to_be_bytes());
        hasher.update((profile.fri_commit_proof_of_work_bits() as u64).to_be_bytes());
        hasher.update((profile.fri_query_proof_of_work_bits() as u64).to_be_bytes());
        hasher.update((profile.num_random_codewords() as u64).to_be_bytes());
    }
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
