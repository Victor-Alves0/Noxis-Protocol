//! Candidate domain parameters for hashing one canonical recipient envelope.
//!
//! This is deliberately a small child descriptor instead of another wire
//! format. It gives the experimental reference evaluator an independently
//! derived P24 capacity IV and an exact maximum frame size, but does not select
//! a protocol hash, a transaction rule, or a proof relation.

use std::fmt;

use noxis_privacy_types::BABYBEAR_MODULUS;
use sha2::{Digest, Sha256};

use crate::{CandidatePoseidon2P24NoteDomainsManifestV1, Poseidon2P24NoteDomainsCandidateError};

/// SHA-256 domain for the independent envelope-digest candidate identity.
pub const P24_ENVELOPE_DIGEST_CANDIDATE_ID_DOMAIN: &[u8] =
    b"NOXIS/POSEIDON2-ENVELOPE-DIGEST-CANDIDATE-ID/V1\0";
/// Label used in the P24 capacity-IV derivation.
pub const P24_ENVELOPE_DIGEST_LABEL: &[u8] =
    b"NOXIS/POSEIDON2-PRIVACY/V1/RECIPIENT-ENVELOPE-DIGEST\0";
/// Maximum canonical `NXRE v1` byte length under its current payload limit.
pub const P24_ENVELOPE_DIGEST_MAX_NXRE_BYTES: usize = 3_242;
/// Fixed prefix: frame version, output slot, commitment and envelope length.
pub const P24_ENVELOPE_DIGEST_FRAME_PREFIX_BYTES: usize = 69;
/// Maximum complete source frame accepted by the candidate hash.
pub const P24_ENVELOPE_DIGEST_MAX_INPUT_BYTES: usize =
    P24_ENVELOPE_DIGEST_FRAME_PREFIX_BYTES + P24_ENVELOPE_DIGEST_MAX_NXRE_BYTES;
/// Number of `BytePack3LE` source elements at the maximum frame size.
pub const P24_ENVELOPE_DIGEST_MAX_INPUT_ELEMENTS: usize =
    P24_ENVELOPE_DIGEST_MAX_INPUT_BYTES.div_ceil(3);

const IV_KDF_PREFIX: &[u8] = b"NOXIS/POSEIDON2-ENVELOPE-DIGEST-IV/V1\0";
const CANDIDATE_DESCRIPTOR: &[u8] = b"P24|BytePack3LE|zero-final-group|squeeze-16|frame-v1|slot-u8|commitment-babybear-le32x16|nxre-u16be-length|max-3311";
const IV_ELEMENTS: usize = 9;

/// The one P24 domain reserved for a recipient-envelope digest candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Poseidon2P24EnvelopeDigestDomainV1 {
    /// Hashes `frame_version || output_slot || commitment || nxre_length || nxre`.
    RecipientEnvelope,
}

impl Poseidon2P24EnvelopeDigestDomainV1 {
    /// The smallest legal frame has an empty public prefix plus a valid minimum `NXRE`.
    pub const fn min_input_bytes(self) -> usize {
        1_279
    }

    /// The exact largest source frame permitted by this candidate.
    pub const fn max_input_bytes(self) -> usize {
        P24_ENVELOPE_DIGEST_MAX_INPUT_BYTES
    }

    /// The stable label whose derived IV separates this from every other P24 domain.
    pub const fn label(self) -> &'static [u8] {
        P24_ENVELOPE_DIGEST_LABEL
    }
}

/// Independently identified, unselected envelope-digest candidate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CandidatePoseidon2P24EnvelopeDigestV1;

impl CandidatePoseidon2P24EnvelopeDigestV1 {
    /// Returns the sole candidate configuration for this source-frame version.
    pub const fn new() -> Self {
        Self
    }

    /// Returns a separate identity committed to the complete parent candidate and framing rules.
    pub fn candidate_id(
        self,
    ) -> Result<CandidatePoseidon2P24EnvelopeDigestIdV1, Poseidon2P24EnvelopeDigestCandidateError>
    {
        let parent_id = CandidatePoseidon2P24NoteDomainsManifestV1::new().candidate_id()?;
        let mut hasher = Sha256::new();
        hasher.update(P24_ENVELOPE_DIGEST_CANDIDATE_ID_DOMAIN);
        hasher.update(parent_id.as_bytes());
        hasher.update(CANDIDATE_DESCRIPTOR);
        hasher.update(P24_ENVELOPE_DIGEST_LABEL);
        hasher.update((P24_ENVELOPE_DIGEST_MAX_INPUT_BYTES as u16).to_be_bytes());
        Ok(CandidatePoseidon2P24EnvelopeDigestIdV1(
            hasher.finalize().into(),
        ))
    }

    /// Re-derives the fixed capacity IV without an embedded mutable parameter file.
    pub fn iv(
        self,
        domain: Poseidon2P24EnvelopeDigestDomainV1,
    ) -> Result<[u32; IV_ELEMENTS], Poseidon2P24EnvelopeDigestCandidateError> {
        let parent_id = CandidatePoseidon2P24NoteDomainsManifestV1::new().candidate_id()?;
        let mut output = [0_u32; IV_ELEMENTS];
        let mut accepted = 0;
        let mut counter = 0_u32;
        while accepted < output.len() {
            let mut hasher = Sha256::new();
            hasher.update(IV_KDF_PREFIX);
            hasher.update(parent_id.as_bytes());
            hasher.update(domain.label());
            hasher.update(counter.to_be_bytes());
            for chunk in hasher.finalize().chunks_exact(4) {
                let candidate = u32::from_be_bytes(chunk.try_into().expect("SHA-256 word width"));
                if candidate < BABYBEAR_MODULUS {
                    output[accepted] = candidate;
                    accepted += 1;
                    if accepted == output.len() {
                        break;
                    }
                }
            }
            counter = counter
                .checked_add(1)
                .expect("IV rejection sampler exhausted counter");
        }
        Ok(output)
    }
}

/// Candidate identity that must not be used as a recognized network parameter.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CandidatePoseidon2P24EnvelopeDigestIdV1([u8; 32]);

impl CandidatePoseidon2P24EnvelopeDigestIdV1 {
    /// Canonical candidate identity bytes.
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Display for CandidatePoseidon2P24EnvelopeDigestIdV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Fail-closed errors from the envelope-digest candidate descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Poseidon2P24EnvelopeDigestCandidateError {
    Parent(Poseidon2P24NoteDomainsCandidateError),
}

impl From<Poseidon2P24NoteDomainsCandidateError> for Poseidon2P24EnvelopeDigestCandidateError {
    fn from(value: Poseidon2P24NoteDomainsCandidateError) -> Self {
        Self::Parent(value)
    }
}

impl fmt::Display for Poseidon2P24EnvelopeDigestCandidateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parent(error) => write!(formatter, "invalid NXPH parent candidate: {error}"),
        }
    }
}

impl std::error::Error for Poseidon2P24EnvelopeDigestCandidateError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_identity_and_iv_are_deterministic_and_domain_separated() {
        let candidate = CandidatePoseidon2P24EnvelopeDigestV1::new();
        assert_eq!(
            candidate.candidate_id().unwrap(),
            candidate.candidate_id().unwrap()
        );
        let iv = candidate
            .iv(Poseidon2P24EnvelopeDigestDomainV1::RecipientEnvelope)
            .unwrap();
        assert!(iv.into_iter().all(|element| element < BABYBEAR_MODULUS));
        assert_eq!(
            Poseidon2P24EnvelopeDigestDomainV1::RecipientEnvelope.min_input_bytes(),
            1_279
        );
        assert_eq!(
            Poseidon2P24EnvelopeDigestDomainV1::RecipientEnvelope.max_input_bytes(),
            3_311
        );
    }
}
