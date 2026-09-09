//! Version-two `NXPL` journal for one private submission and its successor state.
//!
//! A frame is deliberately the sole durable authority for both pieces of local
//! evidence. It stores no `NXPP` bytes, proof, key, ciphertext or witness.
//! Those bytes are verified before a caller reaches this component.

use std::{
    fmt,
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use noxis_privacy_types::{NoteCommitmentV2, NullifierV2, PrivacyTypesError};
use noxis_private_state::{
    CandidatePrivateLedgerStateV1, CandidatePrivateStateRecordError,
    PRIVATE_STATE_RECORD_MAX_BYTES, decode_candidate_private_ledger_state,
    encode_candidate_private_ledger_state,
};
use noxis_types::{AssetId, StateId};

use crate::crc32;

/// `NXPL` keeps its physical identity; version two is the composite-frame
/// variant and is not accepted by the v1 reader.
pub const PRIVATE_SUBMISSION_JOURNAL_MAGIC: [u8; 4] = *b"NXPL";
/// Only supported composite private-submission journal frame version.
pub const PRIVATE_SUBMISSION_JOURNAL_VERSION: u16 = 2;
/// Bytes before the variable payload.
pub const PRIVATE_SUBMISSION_JOURNAL_HEADER_LENGTH: usize = 10;
/// CRC-32 byte width after a payload.
pub const PRIVATE_SUBMISSION_JOURNAL_CHECKSUM_LENGTH: usize = 4;
/// Fixed v2 fields before the enclosed `NXPR` record.
pub const PRIVATE_SUBMISSION_JOURNAL_PAYLOAD_PREFIX_LENGTH: usize = 396;
/// Maximum complete v2 payload accepted before allocation.
pub const PRIVATE_SUBMISSION_JOURNAL_MAX_PAYLOAD_LENGTH: u32 =
    (PRIVATE_SUBMISSION_JOURNAL_PAYLOAD_PREFIX_LENGTH + PRIVATE_STATE_RECORD_MAX_BYTES) as u32;

const SEQUENCE_OFFSET: usize = 0;
const PREVIOUS_STATE_ID_OFFSET: usize = SEQUENCE_OFFSET + 8;
const RESULTING_STATE_ID_OFFSET: usize = PREVIOUS_STATE_ID_OFFSET + 32;
const ENVELOPE_ID_OFFSET: usize = RESULTING_STATE_ID_OFFSET + 32;
const ASSET_ID_OFFSET: usize = ENVELOPE_ID_OFFSET + 32;
const INPUT_NULLIFIER_0_OFFSET: usize = ASSET_ID_OFFSET + 32;
const INPUT_NULLIFIER_1_OFFSET: usize = INPUT_NULLIFIER_0_OFFSET + NullifierV2::LENGTH;
const OUTPUT_COMMITMENT_0_OFFSET: usize = INPUT_NULLIFIER_1_OFFSET + NullifierV2::LENGTH;
const OUTPUT_COMMITMENT_1_OFFSET: usize = OUTPUT_COMMITMENT_0_OFFSET + NoteCommitmentV2::LENGTH;
const NXPR_LENGTH_OFFSET: usize = OUTPUT_COMMITMENT_1_OFFSET + NoteCommitmentV2::LENGTH;

/// Minimal local correlation metadata supplied only after envelope verification.
///
/// It intentionally has no decoder and is not a network transaction identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateSubmissionMetadataV1 {
    envelope_id: [u8; 32],
}

impl PrivateSubmissionMetadataV1 {
    /// Rejects the all-zero value, which has no useful local identity.
    pub fn new(envelope_id: [u8; 32]) -> Result<Self, PrivateSubmissionJournalError> {
        if envelope_id == [0; 32] {
            return Err(PrivateSubmissionJournalError::ZeroEnvelopeId);
        }
        Ok(Self { envelope_id })
    }

    pub const fn envelope_id(self) -> [u8; 32] {
        self.envelope_id
    }
}

/// One fully decoded v2 transition at its physical journal offset.
#[derive(Clone, Debug)]
pub struct StoredPrivateSubmissionV2 {
    pub offset: u64,
    pub sequence: u64,
    pub previous_state_id: StateId,
    pub resulting_state_id: StateId,
    pub metadata: PrivateSubmissionMetadataV1,
    pub asset_id: AssetId,
    pub input_nullifiers: [NullifierV2; 2],
    pub output_commitments: [NoteCommitmentV2; 2],
    pub state: CandidatePrivateLedgerStateV1,
}

impl StoredPrivateSubmissionV2 {
    pub const fn state_id(&self) -> StateId {
        self.state.anchor().state_id()
    }
}

enum FrameScan {
    Complete(Vec<StoredPrivateSubmissionV2>),
    IncompleteTail {
        entries: Vec<StoredPrivateSubmissionV2>,
        valid_prefix_length: u64,
        section: &'static str,
    },
}

/// A structurally plausible partial final frame, suitable only for explicit
/// re-scan-and-truncate recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateSubmissionJournalIncompleteTail {
    valid_prefix_length: u64,
    section: &'static str,
}

/// Result of a non-mutating scan. Entries are framed and locally linked; use
/// [`PrivateSubmissionJournalV2::recover_from`] to validate their state deltas
/// against an authenticated base.
#[derive(Clone, Debug)]
pub struct PrivateSubmissionJournalRecoveryScan {
    pub entries: Vec<StoredPrivateSubmissionV2>,
    pub incomplete_tail: Option<PrivateSubmissionJournalIncompleteTail>,
}

impl PrivateSubmissionJournalRecoveryScan {
    pub fn latest(&self) -> Option<&StoredPrivateSubmissionV2> {
        self.entries.last()
    }
}

/// Single-writer composite `NXPL v2` journal.
pub struct PrivateSubmissionJournalV2 {
    path: PathBuf,
    file: File,
}

impl PrivateSubmissionJournalV2 {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PrivateSubmissionJournalError> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|source| PrivateSubmissionJournalError::Io {
                operation: "open private-submission journal",
                path: path.clone(),
                source,
            })?;
        Ok(Self { path, file })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Validates and synchronizes exactly one receipt plus successor state.
    pub fn append_submission(
        &mut self,
        predecessor: &CandidatePrivateLedgerStateV1,
        successor: &CandidatePrivateLedgerStateV1,
        metadata: PrivateSubmissionMetadataV1,
        asset_id: AssetId,
        input_nullifiers: [NullifierV2; 2],
        output_commitments: [NoteCommitmentV2; 2],
    ) -> Result<u64, PrivateSubmissionJournalError> {
        validate_transition(
            predecessor,
            successor,
            metadata,
            asset_id,
            input_nullifiers,
            output_commitments,
        )?;
        let scan = self.scan_recoverable_tail()?;
        if scan.incomplete_tail.is_some() {
            return Err(PrivateSubmissionJournalError::IncompleteTailPresent);
        }
        let predecessor_id = predecessor.anchor().state_id();
        let sequence = match scan.latest() {
            Some(latest) => {
                if latest.state_id() != predecessor_id {
                    return Err(PrivateSubmissionJournalError::PredecessorMismatch {
                        sequence: latest.sequence.saturating_add(1),
                        expected: latest.state_id(),
                        actual: predecessor_id,
                    });
                }
                latest
                    .sequence
                    .checked_add(1)
                    .ok_or(PrivateSubmissionJournalError::SequenceOverflow)?
            }
            None => 1,
        };
        let nxpr = encode_candidate_private_ledger_state(successor)
            .map_err(PrivateSubmissionJournalError::Record)?;
        let frame = encode_frame(&encode_payload(
            sequence,
            predecessor_id,
            successor.anchor().state_id(),
            metadata,
            asset_id,
            input_nullifiers,
            output_commitments,
            &nxpr,
        )?)?;
        self.file
            .seek(SeekFrom::End(0))
            .map_err(|source| self.io("seek private-submission journal end", source))?;
        self.file
            .write_all(&frame)
            .map_err(|source| self.io("append private-submission journal frame", source))?;
        self.file
            .flush()
            .map_err(|source| self.io("flush private-submission journal frame", source))?;
        self.file
            .sync_data()
            .map_err(|source| self.io("sync private-submission journal frame", source))?;
        Ok(sequence)
    }

    pub fn scan_recoverable_tail(
        &mut self,
    ) -> Result<PrivateSubmissionJournalRecoveryScan, PrivateSubmissionJournalError> {
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|source| self.io("seek private-submission journal start", source))?;
        let scan = match scan_frames(&mut self.file, &self.path)? {
            FrameScan::Complete(entries) => PrivateSubmissionJournalRecoveryScan {
                entries,
                incomplete_tail: None,
            },
            FrameScan::IncompleteTail {
                entries,
                valid_prefix_length,
                section,
            } => PrivateSubmissionJournalRecoveryScan {
                entries,
                incomplete_tail: Some(PrivateSubmissionJournalIncompleteTail {
                    valid_prefix_length,
                    section,
                }),
            },
        };
        self.file
            .seek(SeekFrom::End(0))
            .map_err(|source| self.io("seek private-submission journal end", source))?;
        Ok(scan)
    }

    /// Validates base linkage and every persisted receipt/state delta.
    pub fn recover_from(
        &mut self,
        base: &CandidatePrivateLedgerStateV1,
    ) -> Result<PrivateSubmissionJournalRecoveryScan, PrivateSubmissionJournalError> {
        let scan = self.scan_recoverable_tail()?;
        let mut predecessor = base;
        for entry in &scan.entries {
            if entry.previous_state_id != predecessor.anchor().state_id() {
                return Err(PrivateSubmissionJournalError::PredecessorMismatch {
                    sequence: entry.sequence,
                    expected: predecessor.anchor().state_id(),
                    actual: entry.previous_state_id,
                });
            }
            if entry.resulting_state_id != entry.state_id() {
                return Err(PrivateSubmissionJournalError::ResultingStateMismatch {
                    encoded: entry.resulting_state_id,
                    rebuilt: entry.state_id(),
                });
            }
            validate_transition(
                predecessor,
                &entry.state,
                entry.metadata,
                entry.asset_id,
                entry.input_nullifiers,
                entry.output_commitments,
            )?;
            predecessor = &entry.state;
        }
        Ok(scan)
    }

    pub fn truncate_verified_incomplete_tail(
        &mut self,
        expected: PrivateSubmissionJournalIncompleteTail,
    ) -> Result<(), PrivateSubmissionJournalError> {
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|source| self.io("seek private-submission journal start", source))?;
        let actual = match scan_frames(&mut self.file, &self.path)? {
            FrameScan::Complete(_) => {
                return Err(PrivateSubmissionJournalError::RecoveryTailChanged);
            }
            FrameScan::IncompleteTail {
                valid_prefix_length,
                section,
                ..
            } => PrivateSubmissionJournalIncompleteTail {
                valid_prefix_length,
                section,
            },
        };
        if actual != expected {
            return Err(PrivateSubmissionJournalError::RecoveryTailChanged);
        }
        self.file
            .set_len(actual.valid_prefix_length)
            .map_err(|source| {
                self.io(
                    "truncate incomplete private-submission journal tail",
                    source,
                )
            })?;
        self.file
            .sync_all()
            .map_err(|source| self.io("sync recovered private-submission journal", source))?;
        self.file
            .seek(SeekFrom::End(0))
            .map_err(|source| self.io("seek private-submission journal end", source))?;
        Ok(())
    }

    fn io(&self, operation: &'static str, source: io::Error) -> PrivateSubmissionJournalError {
        PrivateSubmissionJournalError::Io {
            operation,
            path: self.path.clone(),
            source,
        }
    }
}

fn validate_transition(
    predecessor: &CandidatePrivateLedgerStateV1,
    successor: &CandidatePrivateLedgerStateV1,
    metadata: PrivateSubmissionMetadataV1,
    asset_id: AssetId,
    input_nullifiers: [NullifierV2; 2],
    output_commitments: [NoteCommitmentV2; 2],
) -> Result<(), PrivateSubmissionJournalError> {
    if metadata.envelope_id() == [0; 32] {
        return Err(PrivateSubmissionJournalError::ZeroEnvelopeId);
    }
    if predecessor.asset(asset_id).is_none() {
        return Err(PrivateSubmissionJournalError::UnknownAsset(asset_id));
    }
    if input_nullifiers[0].as_bytes() >= input_nullifiers[1].as_bytes() {
        return Err(PrivateSubmissionJournalError::NonCanonicalInputNullifierOrder);
    }
    if output_commitments[0].as_bytes() >= output_commitments[1].as_bytes() {
        return Err(PrivateSubmissionJournalError::NonCanonicalOutputCommitmentOrder);
    }
    let old_commitments = predecessor.snapshot().commitments();
    let new_commitments = successor.snapshot().commitments();
    let expected_commitment_count = old_commitments
        .len()
        .checked_add(2)
        .ok_or(PrivateSubmissionJournalError::CommitmentCountOverflow)?;
    if new_commitments.len() != expected_commitment_count {
        return Err(
            PrivateSubmissionJournalError::OutputCommitmentDeltaMismatch {
                previous: old_commitments.len(),
                successor: new_commitments.len(),
            },
        );
    }
    if new_commitments[old_commitments.len()..] != output_commitments {
        return Err(PrivateSubmissionJournalError::OutputCommitmentsMismatch);
    }
    let old_nullifiers = predecessor.snapshot().spent_nullifiers();
    let new_nullifiers = successor.snapshot().spent_nullifiers();
    let expected_nullifier_count = old_nullifiers
        .len()
        .checked_add(2)
        .ok_or(PrivateSubmissionJournalError::NullifierCountOverflow)?;
    if new_nullifiers.len() != expected_nullifier_count {
        return Err(PrivateSubmissionJournalError::InputNullifierDeltaMismatch {
            previous: old_nullifiers.len(),
            successor: new_nullifiers.len(),
        });
    }
    for nullifier in input_nullifiers {
        if predecessor.snapshot().is_spent(nullifier) {
            return Err(PrivateSubmissionJournalError::InputNullifierAlreadySpent);
        }
        if !successor.snapshot().is_spent(nullifier) {
            return Err(PrivateSubmissionJournalError::InputNullifierMissingFromSuccessor);
        }
    }
    let newly_spent = new_nullifiers
        .iter()
        .filter(|nullifier| !predecessor.snapshot().is_spent(**nullifier))
        .count();
    if newly_spent != 2 {
        return Err(PrivateSubmissionJournalError::InputNullifierDeltaMismatch {
            previous: old_nullifiers.len(),
            successor: new_nullifiers.len(),
        });
    }
    Ok(())
}

fn scan_frames(file: &mut File, path: &Path) -> Result<FrameScan, PrivateSubmissionJournalError> {
    let mut entries = Vec::new();
    let mut offset = 0_u64;
    let file_length = file
        .metadata()
        .map_err(|source| PrivateSubmissionJournalError::Io {
            operation: "read private-submission journal metadata",
            path: path.to_path_buf(),
            source,
        })?
        .len();
    while offset < file_length {
        let remaining = file_length - offset;
        if remaining < 4 {
            let mut partial_magic = vec![0; remaining as usize];
            read_exact(file, &mut partial_magic, path)?;
            if PRIVATE_SUBMISSION_JOURNAL_MAGIC.starts_with(&partial_magic) {
                return Ok(FrameScan::IncompleteTail {
                    entries,
                    valid_prefix_length: offset,
                    section: "frame magic",
                });
            }
            return Err(PrivateSubmissionJournalError::InvalidMagic { offset });
        }
        let mut magic = [0; 4];
        read_exact(file, &mut magic, path)?;
        if magic != PRIVATE_SUBMISSION_JOURNAL_MAGIC {
            return Err(PrivateSubmissionJournalError::InvalidMagic { offset });
        }
        if remaining < PRIVATE_SUBMISSION_JOURNAL_HEADER_LENGTH as u64 {
            return Ok(FrameScan::IncompleteTail {
                entries,
                valid_prefix_length: offset,
                section: "frame header",
            });
        }
        let mut header = [0; PRIVATE_SUBMISSION_JOURNAL_HEADER_LENGTH - 4];
        read_exact(file, &mut header, path)?;
        let version = u16::from_be_bytes([header[0], header[1]]);
        if version != PRIVATE_SUBMISSION_JOURNAL_VERSION {
            return Err(PrivateSubmissionJournalError::UnsupportedFrameVersion { offset, version });
        }
        let payload_length = u32::from_be_bytes([header[2], header[3], header[4], header[5]]);
        if payload_length > PRIVATE_SUBMISSION_JOURNAL_MAX_PAYLOAD_LENGTH {
            return Err(PrivateSubmissionJournalError::FrameTooLarge {
                offset,
                actual: payload_length,
                maximum: PRIVATE_SUBMISSION_JOURNAL_MAX_PAYLOAD_LENGTH,
            });
        }
        let frame_length = (PRIVATE_SUBMISSION_JOURNAL_HEADER_LENGTH as u64)
            .checked_add(payload_length as u64)
            .and_then(|value| value.checked_add(PRIVATE_SUBMISSION_JOURNAL_CHECKSUM_LENGTH as u64))
            .ok_or(PrivateSubmissionJournalError::OffsetOverflow)?;
        if remaining < frame_length {
            return Ok(FrameScan::IncompleteTail {
                entries,
                valid_prefix_length: offset,
                section: if remaining
                    < PRIVATE_SUBMISSION_JOURNAL_HEADER_LENGTH as u64 + payload_length as u64
                {
                    "frame payload"
                } else {
                    "frame checksum"
                },
            });
        }
        let mut payload = vec![0; payload_length as usize];
        read_exact(file, &mut payload, path)?;
        let mut checksum = [0; PRIVATE_SUBMISSION_JOURNAL_CHECKSUM_LENGTH];
        read_exact(file, &mut checksum, path)?;
        let expected_checksum = u32::from_be_bytes(checksum);
        let actual_checksum = crc32(&payload);
        if expected_checksum != actual_checksum {
            return Err(PrivateSubmissionJournalError::ChecksumMismatch {
                offset,
                expected: expected_checksum,
                actual: actual_checksum,
            });
        }
        let mut entry = decode_payload(&payload)?;
        entry.offset = offset;
        if let Some(previous) = entries.last() {
            let expected_sequence = previous
                .sequence
                .checked_add(1)
                .ok_or(PrivateSubmissionJournalError::SequenceOverflow)?;
            if entry.sequence != expected_sequence {
                return Err(PrivateSubmissionJournalError::SequenceMismatch {
                    offset,
                    expected: expected_sequence,
                    actual: entry.sequence,
                });
            }
            if entry.previous_state_id != previous.state_id() {
                return Err(PrivateSubmissionJournalError::PredecessorMismatch {
                    sequence: entry.sequence,
                    expected: previous.state_id(),
                    actual: entry.previous_state_id,
                });
            }
        } else if entry.sequence != 1 {
            return Err(PrivateSubmissionJournalError::SequenceMismatch {
                offset,
                expected: 1,
                actual: entry.sequence,
            });
        }
        entries.push(entry);
        offset = offset
            .checked_add(frame_length)
            .ok_or(PrivateSubmissionJournalError::OffsetOverflow)?;
    }
    Ok(FrameScan::Complete(entries))
}

#[allow(clippy::too_many_arguments)]
fn encode_payload(
    sequence: u64,
    previous_state_id: StateId,
    resulting_state_id: StateId,
    metadata: PrivateSubmissionMetadataV1,
    asset_id: AssetId,
    input_nullifiers: [NullifierV2; 2],
    output_commitments: [NoteCommitmentV2; 2],
    nxpr: &[u8],
) -> Result<Vec<u8>, PrivateSubmissionJournalError> {
    let nxpr_length =
        u32::try_from(nxpr.len()).map_err(|_| PrivateSubmissionJournalError::FrameTooLarge {
            offset: 0,
            actual: u32::MAX,
            maximum: PRIVATE_SUBMISSION_JOURNAL_MAX_PAYLOAD_LENGTH,
        })?;
    let rebuilt = decode_candidate_private_ledger_state(nxpr)
        .map_err(PrivateSubmissionJournalError::Record)?;
    if rebuilt.anchor().state_id() != resulting_state_id {
        return Err(PrivateSubmissionJournalError::ResultingStateMismatch {
            encoded: resulting_state_id,
            rebuilt: rebuilt.anchor().state_id(),
        });
    }
    let mut payload =
        Vec::with_capacity(PRIVATE_SUBMISSION_JOURNAL_PAYLOAD_PREFIX_LENGTH + nxpr.len());
    payload.extend_from_slice(&sequence.to_be_bytes());
    payload.extend_from_slice(&previous_state_id.0);
    payload.extend_from_slice(&resulting_state_id.0);
    payload.extend_from_slice(&metadata.envelope_id());
    payload.extend_from_slice(&asset_id.0);
    for nullifier in input_nullifiers {
        payload.extend_from_slice(&nullifier.as_bytes());
    }
    for commitment in output_commitments {
        payload.extend_from_slice(&commitment.as_bytes());
    }
    payload.extend_from_slice(&nxpr_length.to_be_bytes());
    payload.extend_from_slice(nxpr);
    Ok(payload)
}

fn decode_payload(
    payload: &[u8],
) -> Result<StoredPrivateSubmissionV2, PrivateSubmissionJournalError> {
    if payload.len() < PRIVATE_SUBMISSION_JOURNAL_PAYLOAD_PREFIX_LENGTH {
        return Err(PrivateSubmissionJournalError::PayloadTruncated);
    }
    let sequence = u64::from_be_bytes(
        payload[SEQUENCE_OFFSET..PREVIOUS_STATE_ID_OFFSET]
            .try_into()
            .expect("fixed range"),
    );
    let previous_state_id = StateId::new(
        payload[PREVIOUS_STATE_ID_OFFSET..RESULTING_STATE_ID_OFFSET]
            .try_into()
            .expect("fixed range"),
    );
    let resulting_state_id = StateId::new(
        payload[RESULTING_STATE_ID_OFFSET..ENVELOPE_ID_OFFSET]
            .try_into()
            .expect("fixed range"),
    );
    let metadata = PrivateSubmissionMetadataV1::new(
        payload[ENVELOPE_ID_OFFSET..ASSET_ID_OFFSET]
            .try_into()
            .expect("fixed range"),
    )?;
    let asset_id = AssetId::new(
        payload[ASSET_ID_OFFSET..INPUT_NULLIFIER_0_OFFSET]
            .try_into()
            .expect("fixed range"),
    );
    let input_nullifiers = [
        NullifierV2::new(
            payload[INPUT_NULLIFIER_0_OFFSET..INPUT_NULLIFIER_1_OFFSET]
                .try_into()
                .expect("fixed range"),
        )
        .map_err(PrivateSubmissionJournalError::Privacy)?,
        NullifierV2::new(
            payload[INPUT_NULLIFIER_1_OFFSET..OUTPUT_COMMITMENT_0_OFFSET]
                .try_into()
                .expect("fixed range"),
        )
        .map_err(PrivateSubmissionJournalError::Privacy)?,
    ];
    let output_commitments = [
        NoteCommitmentV2::new(
            payload[OUTPUT_COMMITMENT_0_OFFSET..OUTPUT_COMMITMENT_1_OFFSET]
                .try_into()
                .expect("fixed range"),
        )
        .map_err(PrivateSubmissionJournalError::Privacy)?,
        NoteCommitmentV2::new(
            payload[OUTPUT_COMMITMENT_1_OFFSET..NXPR_LENGTH_OFFSET]
                .try_into()
                .expect("fixed range"),
        )
        .map_err(PrivateSubmissionJournalError::Privacy)?,
    ];
    let nxpr_length = u32::from_be_bytes(
        payload[NXPR_LENGTH_OFFSET..PRIVATE_SUBMISSION_JOURNAL_PAYLOAD_PREFIX_LENGTH]
            .try_into()
            .expect("fixed range"),
    ) as usize;
    if nxpr_length > PRIVATE_STATE_RECORD_MAX_BYTES {
        return Err(PrivateSubmissionJournalError::NestedRecordTooLarge(
            nxpr_length,
        ));
    }
    let nxpr = &payload[PRIVATE_SUBMISSION_JOURNAL_PAYLOAD_PREFIX_LENGTH..];
    if nxpr.len() != nxpr_length {
        return Err(PrivateSubmissionJournalError::NestedRecordLength {
            declared: nxpr_length,
            actual: nxpr.len(),
        });
    }
    let state = decode_candidate_private_ledger_state(nxpr)
        .map_err(PrivateSubmissionJournalError::Record)?;
    if state.anchor().state_id() != resulting_state_id {
        return Err(PrivateSubmissionJournalError::ResultingStateMismatch {
            encoded: resulting_state_id,
            rebuilt: state.anchor().state_id(),
        });
    }
    Ok(StoredPrivateSubmissionV2 {
        offset: 0,
        sequence,
        previous_state_id,
        resulting_state_id,
        metadata,
        asset_id,
        input_nullifiers,
        output_commitments,
        state,
    })
}

fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, PrivateSubmissionJournalError> {
    let payload_length =
        u32::try_from(payload.len()).map_err(|_| PrivateSubmissionJournalError::FrameTooLarge {
            offset: 0,
            actual: u32::MAX,
            maximum: PRIVATE_SUBMISSION_JOURNAL_MAX_PAYLOAD_LENGTH,
        })?;
    if payload_length > PRIVATE_SUBMISSION_JOURNAL_MAX_PAYLOAD_LENGTH {
        return Err(PrivateSubmissionJournalError::FrameTooLarge {
            offset: 0,
            actual: payload_length,
            maximum: PRIVATE_SUBMISSION_JOURNAL_MAX_PAYLOAD_LENGTH,
        });
    }
    let mut frame = Vec::with_capacity(
        PRIVATE_SUBMISSION_JOURNAL_HEADER_LENGTH
            + payload.len()
            + PRIVATE_SUBMISSION_JOURNAL_CHECKSUM_LENGTH,
    );
    frame.extend_from_slice(&PRIVATE_SUBMISSION_JOURNAL_MAGIC);
    frame.extend_from_slice(&PRIVATE_SUBMISSION_JOURNAL_VERSION.to_be_bytes());
    frame.extend_from_slice(&payload_length.to_be_bytes());
    frame.extend_from_slice(payload);
    frame.extend_from_slice(&crc32(payload).to_be_bytes());
    Ok(frame)
}

fn read_exact(
    file: &mut File,
    bytes: &mut [u8],
    path: &Path,
) -> Result<(), PrivateSubmissionJournalError> {
    file.read_exact(bytes)
        .map_err(|source| PrivateSubmissionJournalError::Io {
            operation: "read private-submission journal frame",
            path: path.to_path_buf(),
            source,
        })
}

/// Fail-closed v2 journal errors. No variant authorizes using a partial prefix.
#[derive(Debug)]
pub enum PrivateSubmissionJournalError {
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    Record(CandidatePrivateStateRecordError),
    Privacy(PrivacyTypesError),
    InvalidMagic {
        offset: u64,
    },
    UnsupportedFrameVersion {
        offset: u64,
        version: u16,
    },
    FrameTooLarge {
        offset: u64,
        actual: u32,
        maximum: u32,
    },
    ChecksumMismatch {
        offset: u64,
        expected: u32,
        actual: u32,
    },
    PayloadTruncated,
    NestedRecordTooLarge(usize),
    NestedRecordLength {
        declared: usize,
        actual: usize,
    },
    ResultingStateMismatch {
        encoded: StateId,
        rebuilt: StateId,
    },
    SequenceMismatch {
        offset: u64,
        expected: u64,
        actual: u64,
    },
    PredecessorMismatch {
        sequence: u64,
        expected: StateId,
        actual: StateId,
    },
    SequenceOverflow,
    OffsetOverflow,
    IncompleteTailPresent,
    RecoveryTailChanged,
    ZeroEnvelopeId,
    UnknownAsset(AssetId),
    NonCanonicalInputNullifierOrder,
    NonCanonicalOutputCommitmentOrder,
    CommitmentCountOverflow,
    NullifierCountOverflow,
    OutputCommitmentDeltaMismatch {
        previous: usize,
        successor: usize,
    },
    OutputCommitmentsMismatch,
    InputNullifierDeltaMismatch {
        previous: usize,
        successor: usize,
    },
    InputNullifierAlreadySpent,
    InputNullifierMissingFromSuccessor,
}

impl fmt::Display for PrivateSubmissionJournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "candidate private-submission journal error: {self:?}"
        )
    }
}
impl std::error::Error for PrivateSubmissionJournalError {}
