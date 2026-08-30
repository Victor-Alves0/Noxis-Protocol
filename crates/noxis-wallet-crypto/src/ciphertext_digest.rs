//! Canonical candidate binding of one `NXRE` envelope to one public output.
//!
//! The input frame is deliberately assembled here, next to the only `NXRE`
//! encoder. It is a research candidate: callers may place the resulting value
//! in a v2 intent, but no ledger or proof verifier accepts it yet.

use std::fmt;

use noxis_poseidon2_privacy_reference::{
    Poseidon2P24PrivacyReference, Poseidon2P24PrivacyReferenceError,
};
use noxis_privacy_types::{CiphertextDigestV2, NoteCommitmentV2, PrivacyTypesError};
use noxis_tree_params::{
    P24_ENVELOPE_DIGEST_FRAME_PREFIX_BYTES, P24_ENVELOPE_DIGEST_MAX_INPUT_BYTES,
};

use crate::{HybridRecipientEnvelope, PaymentAddressCodecError, encode_hybrid_recipient_envelope};

/// Version carried in every candidate envelope-digest source frame.
pub const CANDIDATE_CIPHERTEXT_DIGEST_FRAME_VERSION: u16 = 1;

/// One fixed output position in the initial 2×2 private-transfer candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidatePrivateOutputSlotV1 {
    First,
    Second,
}

impl CandidatePrivateOutputSlotV1 {
    const fn as_u8(self) -> u8 {
        match self {
            Self::First => 0,
            Self::Second => 1,
        }
    }
}

/// Derives the candidate `CiphertextDigestV2` from one public commitment and
/// the exact canonical `NXRE` encoding.
///
/// The source frame is
/// `version:u16be || slot:u8 || commitment:64 || nxre_length:u16be || nxre`.
/// Its explicit length makes BytePack3LE's final zero padding unambiguous.
pub fn candidate_ciphertext_digest_v1(
    slot: CandidatePrivateOutputSlotV1,
    commitment: NoteCommitmentV2,
    envelope: &HybridRecipientEnvelope,
) -> Result<CiphertextDigestV2, CandidateCiphertextDigestError> {
    let envelope = encode_hybrid_recipient_envelope(envelope)?;
    let envelope_length = u16::try_from(envelope.len())
        .map_err(|_| CandidateCiphertextDigestError::EnvelopeTooLong)?;
    let mut frame = Vec::with_capacity(P24_ENVELOPE_DIGEST_FRAME_PREFIX_BYTES + envelope.len());
    frame.extend_from_slice(&CANDIDATE_CIPHERTEXT_DIGEST_FRAME_VERSION.to_be_bytes());
    frame.push(slot.as_u8());
    frame.extend_from_slice(&commitment.as_bytes());
    frame.extend_from_slice(&envelope_length.to_be_bytes());
    frame.extend_from_slice(&envelope);
    debug_assert_eq!(
        frame.len(),
        P24_ENVELOPE_DIGEST_FRAME_PREFIX_BYTES + envelope.len()
    );
    debug_assert!(frame.len() <= P24_ENVELOPE_DIGEST_MAX_INPUT_BYTES);

    let reference = Poseidon2P24PrivacyReference::load_candidate()?;
    Ok(CiphertextDigestV2::from_elements(
        reference.hash_recipient_envelope_digest_frame(&frame)?,
    )?)
}

/// Fail-closed errors while calculating the candidate ciphertext digest.
#[derive(Debug)]
pub enum CandidateCiphertextDigestError {
    EnvelopeCodec(PaymentAddressCodecError),
    EnvelopeTooLong,
    PrivacyReference(Poseidon2P24PrivacyReferenceError),
    PrivacyTypes(PrivacyTypesError),
}

impl From<PaymentAddressCodecError> for CandidateCiphertextDigestError {
    fn from(value: PaymentAddressCodecError) -> Self {
        Self::EnvelopeCodec(value)
    }
}

impl From<Poseidon2P24PrivacyReferenceError> for CandidateCiphertextDigestError {
    fn from(value: Poseidon2P24PrivacyReferenceError) -> Self {
        Self::PrivacyReference(value)
    }
}

impl From<PrivacyTypesError> for CandidateCiphertextDigestError {
    fn from(value: PrivacyTypesError) -> Self {
        Self::PrivacyTypes(value)
    }
}

impl fmt::Display for CandidateCiphertextDigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "candidate ciphertext digest error: {self:?}")
    }
}

impl std::error::Error for CandidateCiphertextDigestError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        HybridPaymentAddressEntry, RecipientEnvelopeContext, decode_hybrid_recipient_envelope,
    };

    #[test]
    fn digest_binds_the_exact_canonical_envelope_commitment_and_slot() {
        let owner = HybridPaymentAddressEntry::generate(3);
        let context = RecipientEnvelopeContext::new(b"noxis-envelope-digest-research", 3).unwrap();
        let envelope = owner
            .address()
            .encrypt_incoming(&context, &[5; 178])
            .unwrap();
        let commitment = NoteCommitmentV2::from_elements([7; 16]).unwrap();
        let first = candidate_ciphertext_digest_v1(
            CandidatePrivateOutputSlotV1::First,
            commitment,
            &envelope,
        )
        .unwrap();
        let decoded =
            decode_hybrid_recipient_envelope(&encode_hybrid_recipient_envelope(&envelope).unwrap())
                .unwrap();
        assert_eq!(
            first,
            candidate_ciphertext_digest_v1(
                CandidatePrivateOutputSlotV1::First,
                commitment,
                &decoded,
            )
            .unwrap()
        );
        assert_ne!(
            first,
            candidate_ciphertext_digest_v1(
                CandidatePrivateOutputSlotV1::Second,
                commitment,
                &envelope,
            )
            .unwrap()
        );
        assert_ne!(
            first,
            candidate_ciphertext_digest_v1(
                CandidatePrivateOutputSlotV1::First,
                NoteCommitmentV2::from_elements([8; 16]).unwrap(),
                &envelope,
            )
            .unwrap()
        );
        let distinct_envelope = owner
            .address()
            .encrypt_incoming(&context, &[5; 178])
            .unwrap();
        assert_ne!(
            first,
            candidate_ciphertext_digest_v1(
                CandidatePrivateOutputSlotV1::First,
                commitment,
                &distinct_envelope,
            )
            .unwrap()
        );
    }
}
