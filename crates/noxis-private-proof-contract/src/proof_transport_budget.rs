//! Resource bounds for a future, candidate private-proof envelope.
//!
//! These constants are deliberately independent of `NXPT v1`: that older
//! packet has a 2 MiB opaque-proof field and cannot carry the currently
//! measured three-proof research bundle. This module is a receiver-side
//! allocation boundary, not a selected wire format, network rule, or proof
//! verifier profile.

use std::fmt;

/// Exact raw proof-byte total measured by the complete release research path
/// on 2026-09-02: intent/value plus two ownership proofs.
pub const MEASURED_PRIVATE_PROOF_BUNDLE_BYTES: usize = 4_968_511;

/// Candidate upper bound for the three raw pinned-research proof chunks.
///
/// Eight MiB leaves explicit room above the one measured bundle, but does not
/// establish a production DoS budget. A future decoder must enforce this
/// limit before allocating or decoding an individual proof chunk.
pub const CANDIDATE_PRIVATE_PROOF_TRANSPORT_MAX_PROOF_BYTES: usize = 8 * 1024 * 1024;

/// Explicit candidate allowance for canonical envelope framing and public
/// metadata, kept separate from the raw-proof budget.
pub const CANDIDATE_PRIVATE_PROOF_TRANSPORT_MAX_OVERHEAD_BYTES: usize = 64 * 1024;

/// Candidate total receiver-side allocation bound for a complete envelope.
pub const CANDIDATE_PRIVATE_PROOF_TRANSPORT_MAX_ENVELOPE_BYTES: usize =
    CANDIDATE_PRIVATE_PROOF_TRANSPORT_MAX_PROOF_BYTES
        + CANDIDATE_PRIVATE_PROOF_TRANSPORT_MAX_OVERHEAD_BYTES;

/// Remaining raw-proof capacity after the measured release bundle.
pub const CANDIDATE_PRIVATE_PROOF_TRANSPORT_MEASURED_HEADROOM_BYTES: usize =
    CANDIDATE_PRIVATE_PROOF_TRANSPORT_MAX_PROOF_BYTES - MEASURED_PRIVATE_PROOF_BUNDLE_BYTES;

const _: () = assert!(
    MEASURED_PRIVATE_PROOF_BUNDLE_BYTES < CANDIDATE_PRIVATE_PROOF_TRANSPORT_MAX_PROOF_BYTES
);

/// Stateless fail-closed checks for a future candidate proof envelope.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CandidatePrivateProofTransportBudgetV1;

impl CandidatePrivateProofTransportBudgetV1 {
    /// Rejects a raw-proof aggregate before a decoder reserves proof storage.
    pub const fn ensure_proof_bytes(
        proof_bytes: usize,
    ) -> Result<(), CandidatePrivateProofTransportBudgetError> {
        if proof_bytes > CANDIDATE_PRIVATE_PROOF_TRANSPORT_MAX_PROOF_BYTES {
            return Err(
                CandidatePrivateProofTransportBudgetError::ProofBytesExceedLimit {
                    actual: proof_bytes,
                    maximum: CANDIDATE_PRIVATE_PROOF_TRANSPORT_MAX_PROOF_BYTES,
                },
            );
        }
        Ok(())
    }

    /// Rejects framing/metadata that would consume more than the explicit
    /// non-proof allowance. It intentionally says nothing about proof CPU.
    pub const fn ensure_overhead_bytes(
        overhead_bytes: usize,
    ) -> Result<(), CandidatePrivateProofTransportBudgetError> {
        if overhead_bytes > CANDIDATE_PRIVATE_PROOF_TRANSPORT_MAX_OVERHEAD_BYTES {
            return Err(
                CandidatePrivateProofTransportBudgetError::OverheadBytesExceedLimit {
                    actual: overhead_bytes,
                    maximum: CANDIDATE_PRIVATE_PROOF_TRANSPORT_MAX_OVERHEAD_BYTES,
                },
            );
        }
        Ok(())
    }

    /// Checks both independent budgets and their canonical total before any
    /// envelope parser copies variable-length fields.
    pub fn ensure_envelope_components(
        proof_bytes: usize,
        overhead_bytes: usize,
    ) -> Result<usize, CandidatePrivateProofTransportBudgetError> {
        Self::ensure_proof_bytes(proof_bytes)?;
        Self::ensure_overhead_bytes(overhead_bytes)?;
        let total = match proof_bytes.checked_add(overhead_bytes) {
            Some(total) => total,
            None => return Err(CandidatePrivateProofTransportBudgetError::TotalBytesOverflow),
        };
        if total > CANDIDATE_PRIVATE_PROOF_TRANSPORT_MAX_ENVELOPE_BYTES {
            return Err(
                CandidatePrivateProofTransportBudgetError::EnvelopeBytesExceedLimit {
                    actual: total,
                    maximum: CANDIDATE_PRIVATE_PROOF_TRANSPORT_MAX_ENVELOPE_BYTES,
                },
            );
        }
        Ok(total)
    }
}

/// Fail-closed resource-budget errors for candidate private-proof transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidatePrivateProofTransportBudgetError {
    ProofBytesExceedLimit { actual: usize, maximum: usize },
    OverheadBytesExceedLimit { actual: usize, maximum: usize },
    EnvelopeBytesExceedLimit { actual: usize, maximum: usize },
    TotalBytesOverflow,
}

impl fmt::Display for CandidatePrivateProofTransportBudgetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "candidate private-proof transport budget error: {self:?}"
        )
    }
}

impl std::error::Error for CandidatePrivateProofTransportBudgetError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measured_complete_bundle_fits_with_explicit_positive_headroom() {
        assert_eq!(
            CANDIDATE_PRIVATE_PROOF_TRANSPORT_MEASURED_HEADROOM_BYTES,
            3_420_097
        );
        assert_eq!(
            CandidatePrivateProofTransportBudgetV1::ensure_proof_bytes(
                MEASURED_PRIVATE_PROOF_BUNDLE_BYTES
            ),
            Ok(())
        );
    }

    #[test]
    fn proof_and_overhead_limits_are_independent_and_inclusive() {
        assert_eq!(
            CandidatePrivateProofTransportBudgetV1::ensure_envelope_components(
                CANDIDATE_PRIVATE_PROOF_TRANSPORT_MAX_PROOF_BYTES,
                CANDIDATE_PRIVATE_PROOF_TRANSPORT_MAX_OVERHEAD_BYTES,
            ),
            Ok(CANDIDATE_PRIVATE_PROOF_TRANSPORT_MAX_ENVELOPE_BYTES)
        );
        assert_eq!(
            CandidatePrivateProofTransportBudgetV1::ensure_proof_bytes(
                CANDIDATE_PRIVATE_PROOF_TRANSPORT_MAX_PROOF_BYTES + 1
            ),
            Err(
                CandidatePrivateProofTransportBudgetError::ProofBytesExceedLimit {
                    actual: CANDIDATE_PRIVATE_PROOF_TRANSPORT_MAX_PROOF_BYTES + 1,
                    maximum: CANDIDATE_PRIVATE_PROOF_TRANSPORT_MAX_PROOF_BYTES,
                }
            )
        );
        assert_eq!(
            CandidatePrivateProofTransportBudgetV1::ensure_overhead_bytes(
                CANDIDATE_PRIVATE_PROOF_TRANSPORT_MAX_OVERHEAD_BYTES + 1
            ),
            Err(
                CandidatePrivateProofTransportBudgetError::OverheadBytesExceedLimit {
                    actual: CANDIDATE_PRIVATE_PROOF_TRANSPORT_MAX_OVERHEAD_BYTES + 1,
                    maximum: CANDIDATE_PRIVATE_PROOF_TRANSPORT_MAX_OVERHEAD_BYTES,
                }
            )
        );
    }
}
