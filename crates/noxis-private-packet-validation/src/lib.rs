//! Candidate boundary that validates `NXPT` recipient-envelope digests.
//!
//! `noxis-codec` owns structural `NXPT` decoding and `noxis-wallet-crypto`
//! owns strict `NXRE` parsing plus the candidate P24 digest. This crate joins
//! those two already-canonical boundaries without turning either into a
//! ledger rule, proof verifier, wallet, or network service.

use std::fmt;

use noxis_codec::{CodecError, PrivateTransferPacketV2, decode_private_transfer};
use noxis_privacy_types::CiphertextDigestV2;
use noxis_wallet_crypto::{
    CandidateCiphertextDigestError, CandidatePrivateOutputSlotV1, PaymentAddressCodecError,
    candidate_ciphertext_digest_v1, decode_hybrid_recipient_envelope,
    encode_hybrid_recipient_envelope,
};

/// A packet whose two envelope bytes were parsed as exact `NXRE v1` values and
/// whose candidate digests matched both intent output slots.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidatePrivateTransferPacketEnvelopeValidationV1 {
    packet: PrivateTransferPacketV2,
    ciphertext_digests: [CiphertextDigestV2; 2],
}

impl CandidatePrivateTransferPacketEnvelopeValidationV1 {
    /// The structurally decoded packet that passed the candidate envelope check.
    pub const fn packet(&self) -> &PrivateTransferPacketV2 {
        &self.packet
    }

    /// The recomputed public digest for the requested canonical output slot.
    pub const fn ciphertext_digests(&self) -> &[CiphertextDigestV2; 2] {
        &self.ciphertext_digests
    }
}

/// Structurally decodes exactly one `NXPT` packet and then validates its two
/// candidate recipient-envelope digest bindings.
pub fn decode_and_validate_candidate_private_transfer_packet_envelopes(
    bytes: &[u8],
) -> Result<
    CandidatePrivateTransferPacketEnvelopeValidationV1,
    CandidatePrivatePacketEnvelopeValidationError,
> {
    validate_candidate_private_transfer_packet_envelopes(decode_private_transfer(bytes)?)
}

/// Validates the two exact `NXRE` envelope bytes already framed in an `NXPT` packet.
///
/// This verifies neither the opaque proof nor note ownership, nullifier
/// absence, value conservation, AEAD decryption, state transition or ledger
/// authorization. It is intentionally prior to all of those checks.
pub fn validate_candidate_private_transfer_packet_envelopes(
    packet: PrivateTransferPacketV2,
) -> Result<
    CandidatePrivateTransferPacketEnvelopeValidationV1,
    CandidatePrivatePacketEnvelopeValidationError,
> {
    let outputs = packet.intent().outputs();
    let envelope_bytes = packet.recipient_envelopes();
    let first_envelope = decode_canonical_envelope(0, &envelope_bytes[0])?;
    let second_envelope = decode_canonical_envelope(1, &envelope_bytes[1])?;
    let ciphertext_digests = [
        candidate_ciphertext_digest_v1(
            CandidatePrivateOutputSlotV1::First,
            outputs[0].commitment(),
            &first_envelope,
        )
        .map_err(
            |error| CandidatePrivatePacketEnvelopeValidationError::Digest { slot: 0, error },
        )?,
        candidate_ciphertext_digest_v1(
            CandidatePrivateOutputSlotV1::Second,
            outputs[1].commitment(),
            &second_envelope,
        )
        .map_err(
            |error| CandidatePrivatePacketEnvelopeValidationError::Digest { slot: 1, error },
        )?,
    ];
    for (slot, (actual, output)) in ciphertext_digests.iter().zip(outputs).enumerate() {
        if *actual != output.ciphertext_digest() {
            return Err(
                CandidatePrivatePacketEnvelopeValidationError::DigestMismatch { slot: slot as u8 },
            );
        }
    }
    Ok(CandidatePrivateTransferPacketEnvelopeValidationV1 {
        packet,
        ciphertext_digests,
    })
}

fn decode_canonical_envelope(
    slot: u8,
    bytes: &[u8],
) -> Result<
    noxis_wallet_crypto::HybridRecipientEnvelope,
    CandidatePrivatePacketEnvelopeValidationError,
> {
    let envelope = decode_hybrid_recipient_envelope(bytes).map_err(|error| {
        CandidatePrivatePacketEnvelopeValidationError::EnvelopeCodec { slot, error }
    })?;
    let reencoded = encode_hybrid_recipient_envelope(&envelope).map_err(|error| {
        CandidatePrivatePacketEnvelopeValidationError::EnvelopeCodec { slot, error }
    })?;
    if reencoded != bytes {
        return Err(CandidatePrivatePacketEnvelopeValidationError::NonCanonicalEnvelope { slot });
    }
    Ok(envelope)
}

/// Fail-closed errors from the candidate `NXPT` envelope-validation boundary.
#[derive(Debug)]
pub enum CandidatePrivatePacketEnvelopeValidationError {
    Codec(CodecError),
    EnvelopeCodec {
        slot: u8,
        error: PaymentAddressCodecError,
    },
    NonCanonicalEnvelope {
        slot: u8,
    },
    Digest {
        slot: u8,
        error: CandidateCiphertextDigestError,
    },
    DigestMismatch {
        slot: u8,
    },
}

impl From<CodecError> for CandidatePrivatePacketEnvelopeValidationError {
    fn from(value: CodecError) -> Self {
        Self::Codec(value)
    }
}

impl fmt::Display for CandidatePrivatePacketEnvelopeValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => {
                write!(formatter, "candidate private packet codec error: {error}")
            }
            Self::EnvelopeCodec { slot, error } => {
                write!(
                    formatter,
                    "candidate private packet envelope {slot} is invalid: {error}"
                )
            }
            Self::NonCanonicalEnvelope { slot } => {
                write!(
                    formatter,
                    "candidate private packet envelope {slot} is not canonical"
                )
            }
            Self::Digest { slot, error } => {
                write!(
                    formatter,
                    "candidate private packet digest {slot} failed: {error}"
                )
            }
            Self::DigestMismatch { slot } => {
                write!(
                    formatter,
                    "candidate private packet envelope digest mismatches output slot {slot}"
                )
            }
        }
    }
}

impl std::error::Error for CandidatePrivatePacketEnvelopeValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Codec(error) => Some(error),
            Self::EnvelopeCodec { error, .. } => Some(error),
            Self::NonCanonicalEnvelope { .. } => None,
            Self::Digest { error, .. } => Some(error),
            Self::DigestMismatch { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noxis_codec::{PrivateTransferPacketV2, encode_private_transfer};
    use noxis_privacy_types::{
        CircuitId, MerkleRootV2, NoteCommitmentV2, NullifierV2, PrivateTransferIntentV2,
        PrivateTransferOutputV2, TreeParametersId, TreeParametersV2,
    };
    use noxis_types::{AssetId, GenesisId, StateId, ValidationContextId};
    use noxis_wallet_crypto::{
        HybridPaymentAddressEntry, RecipientEnvelopeContext, encode_hybrid_recipient_envelope,
    };

    fn packet() -> PrivateTransferPacketV2 {
        let context = RecipientEnvelopeContext::new(b"noxis-private-packet-research", 1).unwrap();
        let first_owner = HybridPaymentAddressEntry::generate(1);
        let second_owner = HybridPaymentAddressEntry::generate(1);
        let first = first_owner
            .address()
            .encrypt_incoming(&context, &[11; 178])
            .unwrap();
        let second = second_owner
            .address()
            .encrypt_incoming(&context, &[12; 178])
            .unwrap();
        let first_bytes = encode_hybrid_recipient_envelope(&first).unwrap();
        let second_bytes = encode_hybrid_recipient_envelope(&second).unwrap();
        let first_commitment = NoteCommitmentV2::from_elements([2; 16]).unwrap();
        let second_commitment = NoteCommitmentV2::from_elements([3; 16]).unwrap();
        let outputs = [
            PrivateTransferOutputV2::new(
                first_commitment,
                candidate_ciphertext_digest_v1(
                    CandidatePrivateOutputSlotV1::First,
                    first_commitment,
                    &first,
                )
                .unwrap(),
            ),
            PrivateTransferOutputV2::new(
                second_commitment,
                candidate_ciphertext_digest_v1(
                    CandidatePrivateOutputSlotV1::Second,
                    second_commitment,
                    &second,
                )
                .unwrap(),
            ),
        ];
        let intent = PrivateTransferIntentV2::new(
            CircuitId::new([4; 32]),
            GenesisId::new([5; 32]),
            ValidationContextId::new([6; 32]),
            StateId::new([7; 32]),
            TreeParametersV2::new(TreeParametersId::new([8; 32])),
            MerkleRootV2::from_elements([9; 16]).unwrap(),
            AssetId::new([10; 32]),
            [
                NullifierV2::from_elements([11; 16]).unwrap(),
                NullifierV2::from_elements([12; 16]).unwrap(),
            ],
            outputs,
        )
        .unwrap();
        PrivateTransferPacketV2::new(intent, [first_bytes, second_bytes], vec![13]).unwrap()
    }

    #[test]
    fn accepts_two_exact_nxre_envelopes_bound_to_the_intent() {
        let packet = packet();
        let validated =
            validate_candidate_private_transfer_packet_envelopes(packet.clone()).unwrap();
        assert_eq!(validated.packet(), &packet);
        assert_eq!(
            decode_and_validate_candidate_private_transfer_packet_envelopes(
                &encode_private_transfer(&packet).unwrap()
            )
            .unwrap()
            .packet(),
            &packet
        );
    }

    #[test]
    fn rejects_an_envelope_swapped_between_output_slots() {
        let packet = packet();
        let mut envelopes = packet.recipient_envelopes().clone();
        envelopes.swap(0, 1);
        let swapped = PrivateTransferPacketV2::new(
            packet.intent().clone(),
            envelopes,
            packet.proof().to_vec(),
        )
        .unwrap();
        assert!(matches!(
            validate_candidate_private_transfer_packet_envelopes(swapped),
            Err(CandidatePrivatePacketEnvelopeValidationError::DigestMismatch { slot: 0 })
        ));
    }

    #[test]
    fn rejects_opaque_packet_bytes_that_are_not_strict_nxre() {
        let packet = packet();
        let invalid = PrivateTransferPacketV2::new(
            packet.intent().clone(),
            [vec![0; 1_024], packet.recipient_envelopes()[1].clone()],
            packet.proof().to_vec(),
        )
        .unwrap();
        assert!(matches!(
            validate_candidate_private_transfer_packet_envelopes(invalid),
            Err(CandidatePrivatePacketEnvelopeValidationError::EnvelopeCodec { slot: 0, .. })
        ));
    }
}
