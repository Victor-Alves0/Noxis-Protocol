//! Local recipient handling for one encrypted candidate private note.
//!
//! The outer transport stays the existing strict `NXRE` hybrid envelope. This
//! module accepts a decrypted note only after recomputing `H_NOTE` and matching
//! the public output commitment. It does not bind a protocol ciphertext digest,
//! derive a spend key, persist a note, or authorize settlement.

use std::fmt;

use noxis_poseidon2_privacy_reference::{
    Poseidon2P24PrivacyReference, Poseidon2P24PrivacyReferenceError,
};
use noxis_privacy_types::{NoteCommitmentV2, PrivacyTypesError, RecipientCommitmentV2};
use noxis_types::AssetId;
use zeroize::Zeroize;

use crate::{
    CandidateCiphertextDigestError, CandidatePrivateOutputSlotV1, HybridPaymentAddress,
    HybridPaymentAddressEntry, HybridRecipientEnvelope, PaymentAddressError,
    RecipientEnvelopeContext, candidate_ciphertext_digest_v1,
};

/// Fixed candidate private-note preimage size from the v2 note-opening format.
pub const CANDIDATE_PRIVATE_NOTE_PREIMAGE_LENGTH: usize = 178;
const ASSET_OFFSET: usize = 2;
const ASSET_LENGTH: usize = 32;
const VALUE_OFFSET: usize = ASSET_OFFSET + ASSET_LENGTH;
const VALUE_LENGTH: usize = 16;
const RECIPIENT_COMMITMENT_OFFSET: usize = VALUE_OFFSET + VALUE_LENGTH;
const RECIPIENT_COMMITMENT_LENGTH: usize = 64;

/// One public output commitment paired with its encrypted `NXRE` recipient
/// envelope. It has no independent wire encoding: the surrounding transaction
/// owns the commitment slot and the existing `NXRE` codec owns envelope bytes.
pub struct CandidatePrivateNoteEnvelopeV1 {
    commitment: NoteCommitmentV2,
    envelope: HybridRecipientEnvelope,
}

impl CandidatePrivateNoteEnvelopeV1 {
    /// Reassociates a decoded recipient envelope with its public output
    /// commitment before a wallet scans it.
    pub const fn from_parts(
        commitment: NoteCommitmentV2,
        envelope: HybridRecipientEnvelope,
    ) -> Self {
        Self {
            commitment,
            envelope,
        }
    }

    /// The public note commitment expected from the encrypted note payload.
    pub const fn commitment(&self) -> NoteCommitmentV2 {
        self.commitment
    }

    /// The strictly decoded hybrid recipient envelope to hand to the owner.
    pub const fn envelope(&self) -> &HybridRecipientEnvelope {
        &self.envelope
    }

    /// Derives the candidate public digest that commits to this exact envelope,
    /// this public note commitment and one fixed 2×2 output slot.
    pub fn candidate_ciphertext_digest(
        &self,
        slot: CandidatePrivateOutputSlotV1,
    ) -> Result<noxis_privacy_types::CiphertextDigestV2, CandidateCiphertextDigestError> {
        candidate_ciphertext_digest_v1(slot, self.commitment, &self.envelope)
    }
}

/// A decrypted candidate note retained only in local process memory.
pub struct ReceivedCandidatePrivateNoteV1 {
    note_preimage: [u8; CANDIDATE_PRIVATE_NOTE_PREIMAGE_LENGTH],
    commitment: NoteCommitmentV2,
}

impl ReceivedCandidatePrivateNoteV1 {
    /// Public commitment whose equality was checked after authenticated decrypt.
    pub const fn commitment(&self) -> NoteCommitmentV2 {
        self.commitment
    }

    /// Reads the candidate note's private asset identifier after a successful
    /// authenticated commitment check.
    pub fn asset_id(&self) -> AssetId {
        AssetId::new(
            self.note_preimage[ASSET_OFFSET..ASSET_OFFSET + ASSET_LENGTH]
                .try_into()
                .expect("fixed asset slice"),
        )
    }

    /// Reads the candidate note's private big-endian `u128` value.
    pub fn value(&self) -> u128 {
        u128::from_be_bytes(
            self.note_preimage[VALUE_OFFSET..VALUE_OFFSET + VALUE_LENGTH]
                .try_into()
                .expect("fixed value slice"),
        )
    }

    /// Reads the canonical `H_ADDR` recipient commitment from the decrypted
    /// candidate note. A noncanonical field vector is rejected rather than
    /// interpreted as a recipient identity.
    pub fn recipient_commitment(&self) -> Result<RecipientCommitmentV2, CandidatePrivateNoteError> {
        Ok(RecipientCommitmentV2::new(
            self.note_preimage[RECIPIENT_COMMITMENT_OFFSET
                ..RECIPIENT_COMMITMENT_OFFSET + RECIPIENT_COMMITMENT_LENGTH]
                .try_into()
                .expect("fixed recipient commitment slice"),
        )?)
    }
}

impl Drop for ReceivedCandidatePrivateNoteV1 {
    fn drop(&mut self) {
        self.note_preimage.zeroize();
    }
}

/// Encrypts one exact 178-byte candidate note to a public diversified payment
/// address and computes the public commitment that a recipient must later
/// confirm after decrypting.
pub fn encrypt_candidate_private_note(
    address: &HybridPaymentAddress,
    context: &RecipientEnvelopeContext,
    note_preimage: [u8; CANDIDATE_PRIVATE_NOTE_PREIMAGE_LENGTH],
) -> Result<CandidatePrivateNoteEnvelopeV1, CandidatePrivateNoteError> {
    let reference = Poseidon2P24PrivacyReference::load_candidate()?;
    let commitment = NoteCommitmentV2::from_elements(reference.hash_note(&note_preimage)?)?;
    let envelope = address.encrypt_incoming(context, &note_preimage)?;
    Ok(CandidatePrivateNoteEnvelopeV1::from_parts(
        commitment, envelope,
    ))
}

/// Encrypts a candidate note only after its embedded `H_ADDR` recipient
/// commitment matches an authenticated public descriptor.
pub fn encrypt_candidate_private_note_to_descriptor(
    descriptor: &crate::CandidatePrivateRecipientDescriptorV1,
    context: &RecipientEnvelopeContext,
    note_preimage: [u8; CANDIDATE_PRIVATE_NOTE_PREIMAGE_LENGTH],
) -> Result<CandidatePrivateNoteEnvelopeV1, CandidatePrivateNoteError> {
    if !descriptor.verify() {
        return Err(CandidatePrivateNoteError::InvalidRecipientDescriptor);
    }
    let recipient_commitment = RecipientCommitmentV2::new(
        note_preimage[RECIPIENT_COMMITMENT_OFFSET
            ..RECIPIENT_COMMITMENT_OFFSET + RECIPIENT_COMMITMENT_LENGTH]
            .try_into()
            .expect("fixed recipient commitment slice"),
    )?;
    if recipient_commitment != descriptor.recipient_commitment() {
        return Err(CandidatePrivateNoteError::RecipientCommitmentMismatch);
    }
    encrypt_candidate_private_note(descriptor.payment_address(), context, note_preimage)
}

/// Authenticates, decrypts and validates one candidate note for its owner.
///
/// A successful AEAD decrypt is insufficient: `H_NOTE(plaintext)` must also
/// match the public output commitment. This prevents a valid envelope for a
/// different note from being accepted as this output.
pub fn decrypt_candidate_private_note(
    owner: &HybridPaymentAddressEntry,
    context: &RecipientEnvelopeContext,
    output: &CandidatePrivateNoteEnvelopeV1,
) -> Result<ReceivedCandidatePrivateNoteV1, CandidatePrivateNoteError> {
    decrypt_candidate_private_note_for_owner(
        |envelope| owner.decrypt_incoming(context, envelope),
        output,
    )
}

/// Decrypts one candidate note for a local recipient keyset and requires its
/// embedded `H_ADDR` commitment to be the keyset's own commitment.
pub fn decrypt_candidate_private_note_for_recipient(
    owner: &crate::CandidatePrivateRecipientKeysetV1,
    context: &RecipientEnvelopeContext,
    output: &CandidatePrivateNoteEnvelopeV1,
) -> Result<ReceivedCandidatePrivateNoteV1, CandidatePrivateNoteError> {
    decrypt_candidate_private_note_for_expected_recipient(
        |envelope| {
            owner
                .incoming_view_key()
                .decrypt_incoming(context, envelope)
        },
        owner.recipient_commitment(),
        output,
    )
}

/// Decrypts one candidate note using only local incoming view authority. The
/// view key can authenticate/decrypt and verify `H_NOTE`/`H_ADDR`, but contains
/// no nullifier material and cannot become a spend capability through this API.
pub fn decrypt_candidate_private_note_for_incoming_view_key(
    owner: &crate::CandidateIncomingViewKeyV1,
    context: &RecipientEnvelopeContext,
    output: &CandidatePrivateNoteEnvelopeV1,
) -> Result<ReceivedCandidatePrivateNoteV1, CandidatePrivateNoteError> {
    decrypt_candidate_private_note_for_expected_recipient(
        |envelope| owner.decrypt_incoming(context, envelope),
        owner.recipient_commitment(),
        output,
    )
}

fn decrypt_candidate_private_note_for_expected_recipient(
    decrypt: impl FnOnce(&HybridRecipientEnvelope) -> Result<Vec<u8>, PaymentAddressError>,
    expected_recipient_commitment: RecipientCommitmentV2,
    output: &CandidatePrivateNoteEnvelopeV1,
) -> Result<ReceivedCandidatePrivateNoteV1, CandidatePrivateNoteError> {
    let received = decrypt_candidate_private_note_for_owner(decrypt, output)?;
    if received.recipient_commitment()? != expected_recipient_commitment {
        return Err(CandidatePrivateNoteError::RecipientCommitmentMismatch);
    }
    Ok(received)
}

fn decrypt_candidate_private_note_for_owner(
    decrypt: impl FnOnce(&HybridRecipientEnvelope) -> Result<Vec<u8>, PaymentAddressError>,
    output: &CandidatePrivateNoteEnvelopeV1,
) -> Result<ReceivedCandidatePrivateNoteV1, CandidatePrivateNoteError> {
    let mut plaintext = decrypt(output.envelope())?;
    if plaintext.len() != CANDIDATE_PRIVATE_NOTE_PREIMAGE_LENGTH {
        plaintext.zeroize();
        return Err(CandidatePrivateNoteError::InvalidPlaintextLength);
    }
    let note_preimage: [u8; CANDIDATE_PRIVATE_NOTE_PREIMAGE_LENGTH] = plaintext
        .as_slice()
        .try_into()
        .expect("length already checked");
    plaintext.zeroize();
    let reference = Poseidon2P24PrivacyReference::load_candidate()?;
    let actual = NoteCommitmentV2::from_elements(reference.hash_note(&note_preimage)?)?;
    if actual != output.commitment {
        return Err(CandidatePrivateNoteError::CommitmentMismatch);
    }
    Ok(ReceivedCandidatePrivateNoteV1 {
        note_preimage,
        commitment: actual,
    })
}

/// Fail-closed errors while handling an encrypted local candidate note.
#[derive(Debug)]
pub enum CandidatePrivateNoteError {
    PaymentAddress(PaymentAddressError),
    PrivacyReference(Poseidon2P24PrivacyReferenceError),
    PrivacyTypes(PrivacyTypesError),
    InvalidPlaintextLength,
    CommitmentMismatch,
    InvalidRecipientDescriptor,
    RecipientCommitmentMismatch,
}

impl From<PaymentAddressError> for CandidatePrivateNoteError {
    fn from(value: PaymentAddressError) -> Self {
        Self::PaymentAddress(value)
    }
}
impl From<Poseidon2P24PrivacyReferenceError> for CandidatePrivateNoteError {
    fn from(value: Poseidon2P24PrivacyReferenceError) -> Self {
        Self::PrivacyReference(value)
    }
}
impl From<PrivacyTypesError> for CandidatePrivateNoteError {
    fn from(value: PrivacyTypesError) -> Self {
        Self::PrivacyTypes(value)
    }
}
impl fmt::Display for CandidatePrivateNoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "candidate private note error: {self:?}")
    }
}
impl std::error::Error for CandidatePrivateNoteError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CandidatePrivateOutputSlotV1, CandidatePrivateRecipientKeysetV1,
        decode_hybrid_recipient_envelope, encode_hybrid_recipient_envelope,
    };

    fn note(asset: [u8; 32], value: u128) -> [u8; CANDIDATE_PRIVATE_NOTE_PREIMAGE_LENGTH] {
        let mut note = core::array::from_fn(|index| (index as u8).wrapping_mul(17).wrapping_add(3));
        note[..2].copy_from_slice(&1_u16.to_be_bytes());
        note[ASSET_OFFSET..ASSET_OFFSET + ASSET_LENGTH].copy_from_slice(&asset);
        note[VALUE_OFFSET..VALUE_OFFSET + VALUE_LENGTH].copy_from_slice(&value.to_be_bytes());
        note
    }

    #[test]
    fn recipient_decrypts_and_rechecks_the_candidate_note_commitment() {
        let owner = HybridPaymentAddressEntry::generate(7);
        let context = RecipientEnvelopeContext::new(b"noxis-private-note-research", 7).unwrap();
        let expected_note = note([9; 32], 42);
        let output =
            encrypt_candidate_private_note(owner.address(), &context, expected_note).unwrap();
        let commitment = output.commitment();
        let ciphertext_digest = output
            .candidate_ciphertext_digest(CandidatePrivateOutputSlotV1::First)
            .unwrap();
        let decoded = decode_hybrid_recipient_envelope(
            &encode_hybrid_recipient_envelope(output.envelope()).unwrap(),
        )
        .unwrap();
        let rebuilt = CandidatePrivateNoteEnvelopeV1::from_parts(commitment, decoded);
        assert_eq!(
            ciphertext_digest,
            rebuilt
                .candidate_ciphertext_digest(CandidatePrivateOutputSlotV1::First)
                .unwrap()
        );
        let received = decrypt_candidate_private_note(&owner, &context, &rebuilt).unwrap();
        assert_eq!(received.commitment(), commitment);
        assert_eq!(received.asset_id(), AssetId::new([9; 32]));
        assert_eq!(received.value(), 42);
    }

    #[test]
    fn recipient_rejects_a_valid_envelope_paired_with_another_commitment() {
        let owner = HybridPaymentAddressEntry::generate(8);
        let context = RecipientEnvelopeContext::new(b"noxis-private-note-research", 8).unwrap();
        let output =
            encrypt_candidate_private_note(owner.address(), &context, note([9; 32], 42)).unwrap();
        let wrong = NoteCommitmentV2::from_elements([77; 16]).unwrap();
        assert!(matches!(
            decrypt_candidate_private_note(
                &owner,
                &context,
                &CandidatePrivateNoteEnvelopeV1::from_parts(wrong, output.envelope),
            ),
            Err(CandidatePrivateNoteError::CommitmentMismatch)
        ));
    }

    #[test]
    fn recipient_descriptor_binds_the_embedded_h_addr_commitment_for_send_and_receive() {
        let owner = CandidatePrivateRecipientKeysetV1::generate(9).unwrap();
        let descriptor = owner.public_descriptor();
        let context =
            RecipientEnvelopeContext::new(b"noxis-private-recipient-research", 9).unwrap();
        let mut expected_note = note([9; 32], 42);
        expected_note[RECIPIENT_COMMITMENT_OFFSET
            ..RECIPIENT_COMMITMENT_OFFSET + RECIPIENT_COMMITMENT_LENGTH]
            .copy_from_slice(&descriptor.recipient_commitment().as_bytes());
        let output =
            encrypt_candidate_private_note_to_descriptor(&descriptor, &context, expected_note)
                .unwrap();
        let received =
            decrypt_candidate_private_note_for_recipient(&owner, &context, &output).unwrap();
        assert_eq!(
            received.recipient_commitment().unwrap(),
            descriptor.recipient_commitment()
        );

        let another = CandidatePrivateRecipientKeysetV1::generate(9).unwrap();
        assert!(matches!(
            encrypt_candidate_private_note_to_descriptor(
                &another.public_descriptor(),
                &context,
                expected_note,
            ),
            Err(CandidatePrivateNoteError::RecipientCommitmentMismatch)
        ));
    }

    #[test]
    fn recipient_keyset_rejects_a_note_for_another_h_addr_commitment() {
        let owner = CandidatePrivateRecipientKeysetV1::generate(10).unwrap();
        let another = CandidatePrivateRecipientKeysetV1::generate(10).unwrap();
        let context =
            RecipientEnvelopeContext::new(b"noxis-private-recipient-research", 10).unwrap();
        let mut wrong_note = note([9; 32], 42);
        wrong_note[RECIPIENT_COMMITMENT_OFFSET
            ..RECIPIENT_COMMITMENT_OFFSET + RECIPIENT_COMMITMENT_LENGTH]
            .copy_from_slice(&another.recipient_commitment().as_bytes());
        let output = encrypt_candidate_private_note(
            owner.public_descriptor().payment_address(),
            &context,
            wrong_note,
        )
        .unwrap();
        assert!(matches!(
            decrypt_candidate_private_note_for_recipient(&owner, &context, &output),
            Err(CandidatePrivateNoteError::RecipientCommitmentMismatch)
        ));
    }

    #[test]
    fn incoming_view_key_scans_its_note_after_full_keyset_is_consumed() {
        let recipient = CandidatePrivateRecipientKeysetV1::generate(11).unwrap();
        let descriptor = recipient.public_descriptor();
        let context =
            RecipientEnvelopeContext::new(b"noxis-private-recipient-research", 11).unwrap();
        let mut expected_note = note([9; 32], 42);
        expected_note[RECIPIENT_COMMITMENT_OFFSET
            ..RECIPIENT_COMMITMENT_OFFSET + RECIPIENT_COMMITMENT_LENGTH]
            .copy_from_slice(&descriptor.recipient_commitment().as_bytes());
        let output =
            encrypt_candidate_private_note_to_descriptor(&descriptor, &context, expected_note)
                .unwrap();

        let view_key = recipient.into_incoming_view_key();
        let received =
            decrypt_candidate_private_note_for_incoming_view_key(&view_key, &context, &output)
                .unwrap();

        assert_eq!(
            received.recipient_commitment().unwrap(),
            view_key.recipient_commitment()
        );
        assert_eq!(
            view_key.payment_address().address_id(),
            descriptor.payment_address().address_id()
        );
    }
}
