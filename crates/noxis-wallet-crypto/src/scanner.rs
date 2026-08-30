//! Bounded local scanning with incoming-view authority only.
//!
//! This module has no persistence, balance, nullifier, spend or network API.
//! It merely lets a local process distinguish notes it can authenticate and
//! validate from unrelated encrypted outputs in one caller-provided batch.

use std::fmt;

use crate::{
    CandidateIncomingViewKeyV1, CandidatePrivateNoteEnvelopeV1, CandidatePrivateNoteError,
    ReceivedCandidatePrivateNoteV1, RecipientEnvelopeContext,
    decrypt_candidate_private_note_for_incoming_view_key,
};

/// One caller-provided public output and the context needed to scan it. The
/// index of an item in the batch is local bookkeeping only; it is not a block,
/// transaction or consensus position.
pub struct CandidateIncomingNoteScanItemV1<'a> {
    context: &'a RecipientEnvelopeContext,
    output: &'a CandidatePrivateNoteEnvelopeV1,
}

impl<'a> CandidateIncomingNoteScanItemV1<'a> {
    pub const fn new(
        context: &'a RecipientEnvelopeContext,
        output: &'a CandidatePrivateNoteEnvelopeV1,
    ) -> Self {
        Self { context, output }
    }
}

/// One note accepted by the local incoming-view scanner. It carries no
/// nullifier, spend material or persistent identifier.
pub struct CandidateScannedIncomingNoteV1 {
    batch_index: usize,
    note: ReceivedCandidatePrivateNoteV1,
}

impl CandidateScannedIncomingNoteV1 {
    pub const fn batch_index(&self) -> usize {
        self.batch_index
    }

    pub const fn note(&self) -> &ReceivedCandidatePrivateNoteV1 {
        &self.note
    }

    pub fn into_note(self) -> ReceivedCandidatePrivateNoteV1 {
        self.note
    }
}

/// Results of scanning one bounded caller-provided batch. `ignored` combines
/// unrelated and unauthenticated envelopes deliberately, so the scanner does
/// not turn malformed ciphertext into a recipient-membership oracle.
pub struct CandidateIncomingNoteScanResultV1 {
    received: Vec<CandidateScannedIncomingNoteV1>,
    ignored: usize,
}

impl CandidateIncomingNoteScanResultV1 {
    pub fn received(&self) -> &[CandidateScannedIncomingNoteV1] {
        &self.received
    }

    pub fn into_received(self) -> Vec<CandidateScannedIncomingNoteV1> {
        self.received
    }

    pub const fn ignored(&self) -> usize {
        self.ignored
    }
}

/// Scans a bounded in-memory batch using only incoming-view authority.
///
/// Envelope authentication failures are expected for outputs belonging to
/// other recipients and are counted as ignored. Any failure after successful
/// envelope handling — such as an invalid note commitment or an `H_ADDR`
/// mismatch — fails closed rather than being hidden as an unrelated output.
pub fn scan_candidate_incoming_notes(
    view_key: &CandidateIncomingViewKeyV1,
    items: &[CandidateIncomingNoteScanItemV1<'_>],
) -> Result<CandidateIncomingNoteScanResultV1, CandidateIncomingNoteScanError> {
    let mut received = Vec::new();
    let mut ignored = 0_usize;
    for (batch_index, item) in items.iter().enumerate() {
        match decrypt_candidate_private_note_for_incoming_view_key(
            view_key,
            item.context,
            item.output,
        ) {
            Ok(note) => received.push(CandidateScannedIncomingNoteV1 { batch_index, note }),
            Err(CandidatePrivateNoteError::PaymentAddress(_)) => ignored += 1,
            Err(source) => {
                return Err(CandidateIncomingNoteScanError::InvalidOwnedOutput {
                    batch_index,
                    source,
                });
            }
        }
    }
    Ok(CandidateIncomingNoteScanResultV1 { received, ignored })
}

/// The incoming-view scanner reached an output that authenticated but failed a
/// candidate-note invariant. The error does not include note plaintext.
#[derive(Debug)]
pub enum CandidateIncomingNoteScanError {
    InvalidOwnedOutput {
        batch_index: usize,
        source: CandidatePrivateNoteError,
    },
}

impl fmt::Display for CandidateIncomingNoteScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOwnedOutput {
                batch_index,
                source,
            } => write!(
                formatter,
                "candidate incoming-note batch item {batch_index} violated a note invariant: {source}"
            ),
        }
    }
}

impl std::error::Error for CandidateIncomingNoteScanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidOwnedOutput { source, .. } => Some(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use noxis_privacy_types::NoteCommitmentV2;
    use noxis_types::AssetId;

    use crate::{
        CANDIDATE_PRIVATE_NOTE_PREIMAGE_LENGTH, CandidatePrivateNoteEnvelopeV1,
        CandidatePrivateRecipientKeysetV1, RecipientEnvelopeContext,
        decrypt_candidate_private_note_for_incoming_view_key,
        encrypt_candidate_private_note_to_descriptor,
    };

    use super::{
        CandidateIncomingNoteScanError, CandidateIncomingNoteScanItemV1,
        scan_candidate_incoming_notes,
    };

    fn note(
        recipient_commitment: [u8; 64],
        asset: [u8; 32],
        value: u128,
    ) -> [u8; CANDIDATE_PRIVATE_NOTE_PREIMAGE_LENGTH] {
        let mut note = [0_u8; CANDIDATE_PRIVATE_NOTE_PREIMAGE_LENGTH];
        note[..2].copy_from_slice(&1_u16.to_be_bytes());
        note[2..34].copy_from_slice(&asset);
        note[34..50].copy_from_slice(&value.to_be_bytes());
        note[50..114].copy_from_slice(&recipient_commitment);
        for (index, byte) in note[114..].iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(19).wrapping_add(5);
        }
        note
    }

    #[test]
    fn incoming_view_key_scans_its_notes_and_ignores_unrelated_envelopes() {
        let recipient = CandidatePrivateRecipientKeysetV1::generate(12).unwrap();
        let descriptor = recipient.public_descriptor();
        let unrelated = CandidatePrivateRecipientKeysetV1::generate(12).unwrap();
        let unrelated_descriptor = unrelated.public_descriptor();
        let context = RecipientEnvelopeContext::new(b"noxis-local-scan-research", 12).unwrap();
        let first = encrypt_candidate_private_note_to_descriptor(
            &descriptor,
            &context,
            note(descriptor.recipient_commitment().as_bytes(), [7; 32], 42),
        )
        .unwrap();
        let ignored = encrypt_candidate_private_note_to_descriptor(
            &unrelated_descriptor,
            &context,
            note(
                unrelated_descriptor.recipient_commitment().as_bytes(),
                [8; 32],
                99,
            ),
        )
        .unwrap();
        let second = encrypt_candidate_private_note_to_descriptor(
            &descriptor,
            &context,
            note(descriptor.recipient_commitment().as_bytes(), [9; 32], 123),
        )
        .unwrap();

        let view_key = recipient.into_incoming_view_key();
        let result = scan_candidate_incoming_notes(
            &view_key,
            &[
                CandidateIncomingNoteScanItemV1::new(&context, &first),
                CandidateIncomingNoteScanItemV1::new(&context, &ignored),
                CandidateIncomingNoteScanItemV1::new(&context, &second),
            ],
        )
        .unwrap();

        assert_eq!(result.ignored(), 1);
        assert_eq!(result.received().len(), 2);
        assert_eq!(result.received()[0].batch_index(), 0);
        assert_eq!(result.received()[1].batch_index(), 2);
        assert_eq!(
            result.received()[0].note().asset_id(),
            AssetId::new([7; 32])
        );
        assert_eq!(result.received()[1].note().value(), 123);
        assert_eq!(
            result.received()[0].note().recipient_commitment().unwrap(),
            view_key.recipient_commitment()
        );
    }

    #[test]
    fn scanner_fails_closed_for_an_authenticated_output_with_bad_commitment() {
        let recipient = CandidatePrivateRecipientKeysetV1::generate(13).unwrap();
        let descriptor = recipient.public_descriptor();
        let context = RecipientEnvelopeContext::new(b"noxis-local-scan-research", 13).unwrap();
        let valid = encrypt_candidate_private_note_to_descriptor(
            &descriptor,
            &context,
            note(descriptor.recipient_commitment().as_bytes(), [7; 32], 42),
        )
        .unwrap();
        let malformed = CandidatePrivateNoteEnvelopeV1::from_parts(
            NoteCommitmentV2::from_elements([77; 16]).unwrap(),
            crate::decode_hybrid_recipient_envelope(
                &crate::encode_hybrid_recipient_envelope(valid.envelope()).unwrap(),
            )
            .unwrap(),
        );
        let view_key = recipient.into_incoming_view_key();
        assert!(matches!(
            scan_candidate_incoming_notes(
                &view_key,
                &[CandidateIncomingNoteScanItemV1::new(&context, &malformed)],
            ),
            Err(CandidateIncomingNoteScanError::InvalidOwnedOutput { batch_index: 0, .. })
        ));
        assert!(
            decrypt_candidate_private_note_for_incoming_view_key(&view_key, &context, &malformed,)
                .is_err()
        );
    }
}
