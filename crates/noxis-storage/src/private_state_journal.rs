//! Append-only journal for canonical candidate private-state snapshots.
//!
//! `NXPL v1` owns physical framing, post-state snapshot decoding and local
//! predecessor continuity. It deliberately does not claim to preserve or
//! re-verify the opaque proof authorizations which led to a state. That needs
//! a selected, serializable proof packet and a consensus-owned transition log.

use std::{
    fmt,
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use noxis_private_state::{
    CandidatePrivateLedgerStateV1, CandidatePrivateStateRecordError,
    PRIVATE_STATE_RECORD_MAX_BYTES, decode_candidate_private_ledger_state,
    encode_candidate_private_ledger_state,
};
use noxis_types::StateId;

use crate::crc32;

/// Magic bytes identifying one candidate private-state journal frame.
pub const PRIVATE_STATE_JOURNAL_MAGIC: [u8; 4] = *b"NXPL";
/// The only supported candidate private-state journal frame version.
pub const PRIVATE_STATE_JOURNAL_VERSION: u16 = 1;
/// Fixed bytes before the variable journal payload.
pub const PRIVATE_STATE_JOURNAL_HEADER_LENGTH: usize = 10;
/// Fixed CRC-32 bytes after a journal payload.
pub const PRIVATE_STATE_JOURNAL_CHECKSUM_LENGTH: usize = 4;
/// Fixed fields in a journal payload before its nested canonical `NXPR`.
pub const PRIVATE_STATE_JOURNAL_PAYLOAD_PREFIX_LENGTH: usize = 8 + 32 + 32 + 4;
/// Largest accepted complete `NXPL v1` payload.
pub const PRIVATE_STATE_JOURNAL_MAX_PAYLOAD_LENGTH: u32 =
    (PRIVATE_STATE_JOURNAL_PAYLOAD_PREFIX_LENGTH + PRIVATE_STATE_RECORD_MAX_BYTES) as u32;

/// One decoded private-state journal entry at its byte offset.
#[derive(Clone, Debug)]
pub struct StoredPrivateState {
    /// Physical offset of the containing `NXPL` frame.
    pub offset: u64,
    /// Strictly increasing, one-based local journal sequence.
    pub sequence: u64,
    /// The state ID that the writer says preceded this post-state.
    pub previous_state_id: StateId,
    /// Fully rebuilt post-state from the enclosed canonical `NXPR` record.
    pub state: CandidatePrivateLedgerStateV1,
}

impl StoredPrivateState {
    /// State ID recomputed by the strict nested `NXPR` decoder.
    pub const fn state_id(&self) -> StateId {
        self.state.anchor().state_id()
    }
}

enum FrameScan {
    Complete(Vec<StoredPrivateState>),
    IncompleteTail {
        entries: Vec<StoredPrivateState>,
        valid_prefix_length: u64,
        section: &'static str,
    },
}

/// A final structurally plausible partial frame discovered during scanning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateStateJournalIncompleteTail {
    valid_prefix_length: u64,
    section: &'static str,
}

/// Result of a non-mutating `NXPL` scan.
#[derive(Clone, Debug)]
pub struct PrivateStateJournalRecoveryScan {
    /// Every complete, decoded and locally continuous entry before a tail.
    pub entries: Vec<StoredPrivateState>,
    /// A final partial frame. It is never silently discarded.
    pub incomplete_tail: Option<PrivateStateJournalIncompleteTail>,
}

impl PrivateStateJournalRecoveryScan {
    /// Returns the final complete post-state, if the journal has one.
    pub fn latest(&self) -> Option<&StoredPrivateState> {
        self.entries.last()
    }
}

/// A single-writer append-only candidate private-state journal.
///
/// The caller must use a separate writer-exclusion mechanism. The current
/// `PrivateStateStoreV1` snapshot lock is intentionally not reused here until
/// journal/cache recovery is integrated as one atomic storage design.
pub struct PrivateStateJournalV1 {
    path: PathBuf,
    file: File,
}

impl PrivateStateJournalV1 {
    /// Opens a journal, creating an empty file if it does not yet exist.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PrivateStateJournalError> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|source| PrivateStateJournalError::Io {
                operation: "open private-state journal",
                path: path.clone(),
                source,
            })?;
        Ok(Self { path, file })
    }

    /// Returns the journal location.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends one fully rebuilt post-state after checking the full durable
    /// prefix and its expected predecessor. Returns the assigned sequence.
    ///
    /// A first entry is sequence one; its predecessor is recorded but cannot
    /// be authenticated without an externally retained base state. Use
    /// [`Self::recover_from`] when that base state is available.
    pub fn append_post_state(
        &mut self,
        previous_state_id: StateId,
        state: &CandidatePrivateLedgerStateV1,
    ) -> Result<u64, PrivateStateJournalError> {
        let scan = self.scan_recoverable_tail()?;
        if scan.incomplete_tail.is_some() {
            return Err(PrivateStateJournalError::IncompleteTailPresent);
        }
        let sequence = match scan.latest() {
            Some(latest) => {
                if latest.state_id() != previous_state_id {
                    return Err(PrivateStateJournalError::PredecessorMismatch {
                        sequence: latest.sequence.saturating_add(1),
                        expected: latest.state_id(),
                        actual: previous_state_id,
                    });
                }
                latest
                    .sequence
                    .checked_add(1)
                    .ok_or(PrivateStateJournalError::SequenceOverflow)?
            }
            None => 1,
        };
        let nxpr = encode_candidate_private_ledger_state(state)
            .map_err(PrivateStateJournalError::Record)?;
        let rebuilt = decode_candidate_private_ledger_state(&nxpr)
            .map_err(PrivateStateJournalError::Record)?;
        if rebuilt.anchor().state_id() != state.anchor().state_id() {
            return Err(PrivateStateJournalError::NestedStateMismatch);
        }
        let payload = encode_payload(sequence, previous_state_id, &nxpr)?;
        let frame = encode_frame(&payload)?;
        self.file
            .seek(SeekFrom::End(0))
            .map_err(|source| self.io("seek private-state journal end", source))?;
        self.file
            .write_all(&frame)
            .map_err(|source| self.io("append private-state journal frame", source))?;
        self.file
            .flush()
            .map_err(|source| self.io("flush private-state journal frame", source))?;
        self.file
            .sync_data()
            .map_err(|source| self.io("sync private-state journal frame", source))?;
        Ok(sequence)
    }

    /// Scans without mutation and verifies all complete local frame links.
    pub fn scan_recoverable_tail(
        &mut self,
    ) -> Result<PrivateStateJournalRecoveryScan, PrivateStateJournalError> {
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|source| self.io("seek private-state journal start", source))?;
        let scan = match scan_frames(&mut self.file, &self.path)? {
            FrameScan::Complete(entries) => PrivateStateJournalRecoveryScan {
                entries,
                incomplete_tail: None,
            },
            FrameScan::IncompleteTail {
                entries,
                valid_prefix_length,
                section,
            } => PrivateStateJournalRecoveryScan {
                entries,
                incomplete_tail: Some(PrivateStateJournalIncompleteTail {
                    valid_prefix_length,
                    section,
                }),
            },
        };
        self.file
            .seek(SeekFrom::End(0))
            .map_err(|source| self.io("seek private-state journal end", source))?;
        Ok(scan)
    }

    /// Validates that the first frame follows `base_state_id` and returns the
    /// final post-state. This is the recovery entry point for a caller that
    /// retains an independently authenticated base state.
    pub fn recover_from(
        &mut self,
        base_state_id: StateId,
    ) -> Result<PrivateStateJournalRecoveryScan, PrivateStateJournalError> {
        let scan = self.scan_recoverable_tail()?;
        if let Some(first) = scan.entries.first()
            && first.previous_state_id != base_state_id
        {
            return Err(PrivateStateJournalError::BaseStateMismatch {
                expected: base_state_id,
                actual: first.previous_state_id,
            });
        }
        Ok(scan)
    }

    /// Removes exactly the partial final frame from a prior successful scan.
    /// The bytes are re-scanned before mutation, so a changed suffix is never
    /// truncated based on stale recovery information.
    pub fn truncate_verified_incomplete_tail(
        &mut self,
        expected: PrivateStateJournalIncompleteTail,
    ) -> Result<(), PrivateStateJournalError> {
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|source| self.io("seek private-state journal start", source))?;
        let actual = match scan_frames(&mut self.file, &self.path)? {
            FrameScan::Complete(_) => return Err(PrivateStateJournalError::RecoveryTailChanged),
            FrameScan::IncompleteTail {
                valid_prefix_length,
                section,
                ..
            } => PrivateStateJournalIncompleteTail {
                valid_prefix_length,
                section,
            },
        };
        if actual != expected {
            return Err(PrivateStateJournalError::RecoveryTailChanged);
        }
        self.file
            .set_len(actual.valid_prefix_length)
            .map_err(|source| self.io("truncate incomplete private-state journal tail", source))?;
        self.file
            .sync_all()
            .map_err(|source| self.io("sync recovered private-state journal", source))?;
        self.file
            .seek(SeekFrom::End(0))
            .map_err(|source| self.io("seek private-state journal end", source))?;
        Ok(())
    }

    fn io(&self, operation: &'static str, source: io::Error) -> PrivateStateJournalError {
        PrivateStateJournalError::Io {
            operation,
            path: self.path.clone(),
            source,
        }
    }
}

fn scan_frames(file: &mut File, path: &Path) -> Result<FrameScan, PrivateStateJournalError> {
    let mut entries = Vec::new();
    let mut offset = 0_u64;
    let file_length = file
        .metadata()
        .map_err(|source| PrivateStateJournalError::Io {
            operation: "read private-state journal metadata",
            path: path.to_path_buf(),
            source,
        })?
        .len();
    while offset < file_length {
        let remaining = file_length - offset;
        if remaining < 4 {
            let mut partial_magic = vec![0; remaining as usize];
            read_exact(file, &mut partial_magic, path)?;
            if PRIVATE_STATE_JOURNAL_MAGIC.starts_with(&partial_magic) {
                return Ok(FrameScan::IncompleteTail {
                    entries,
                    valid_prefix_length: offset,
                    section: "frame magic",
                });
            }
            return Err(PrivateStateJournalError::InvalidMagic { offset });
        }
        let mut magic = [0; 4];
        read_exact(file, &mut magic, path)?;
        if magic != PRIVATE_STATE_JOURNAL_MAGIC {
            return Err(PrivateStateJournalError::InvalidMagic { offset });
        }
        if remaining < PRIVATE_STATE_JOURNAL_HEADER_LENGTH as u64 {
            return Ok(FrameScan::IncompleteTail {
                entries,
                valid_prefix_length: offset,
                section: "frame header",
            });
        }
        let mut header_remainder = [0; PRIVATE_STATE_JOURNAL_HEADER_LENGTH - 4];
        read_exact(file, &mut header_remainder, path)?;
        let version = u16::from_be_bytes([header_remainder[0], header_remainder[1]]);
        if version != PRIVATE_STATE_JOURNAL_VERSION {
            return Err(PrivateStateJournalError::UnsupportedFrameVersion { offset, version });
        }
        let payload_length = u32::from_be_bytes([
            header_remainder[2],
            header_remainder[3],
            header_remainder[4],
            header_remainder[5],
        ]);
        if payload_length > PRIVATE_STATE_JOURNAL_MAX_PAYLOAD_LENGTH {
            return Err(PrivateStateJournalError::FrameTooLarge {
                offset,
                actual: payload_length,
                maximum: PRIVATE_STATE_JOURNAL_MAX_PAYLOAD_LENGTH,
            });
        }
        let frame_length = (PRIVATE_STATE_JOURNAL_HEADER_LENGTH as u64)
            .checked_add(payload_length as u64)
            .and_then(|length| length.checked_add(PRIVATE_STATE_JOURNAL_CHECKSUM_LENGTH as u64))
            .ok_or(PrivateStateJournalError::OffsetOverflow)?;
        if remaining < frame_length {
            return Ok(FrameScan::IncompleteTail {
                entries,
                valid_prefix_length: offset,
                section: if remaining
                    < PRIVATE_STATE_JOURNAL_HEADER_LENGTH as u64 + payload_length as u64
                {
                    "frame payload"
                } else {
                    "frame checksum"
                },
            });
        }
        let mut payload = vec![0; payload_length as usize];
        read_exact(file, &mut payload, path)?;
        let mut checksum = [0; PRIVATE_STATE_JOURNAL_CHECKSUM_LENGTH];
        read_exact(file, &mut checksum, path)?;
        let expected_checksum = u32::from_be_bytes(checksum);
        let actual_checksum = crc32(&payload);
        if expected_checksum != actual_checksum {
            return Err(PrivateStateJournalError::ChecksumMismatch {
                offset,
                expected: expected_checksum,
                actual: actual_checksum,
            });
        }
        let (sequence, previous_state_id, state) = decode_payload(&payload)?;
        let entry = StoredPrivateState {
            offset,
            sequence,
            previous_state_id,
            state,
        };
        if let Some(previous) = entries.last() {
            let expected_sequence = previous
                .sequence
                .checked_add(1)
                .ok_or(PrivateStateJournalError::SequenceOverflow)?;
            if entry.sequence != expected_sequence {
                return Err(PrivateStateJournalError::SequenceMismatch {
                    offset,
                    expected: expected_sequence,
                    actual: entry.sequence,
                });
            }
            if entry.previous_state_id != previous.state_id() {
                return Err(PrivateStateJournalError::PredecessorMismatch {
                    sequence: entry.sequence,
                    expected: previous.state_id(),
                    actual: entry.previous_state_id,
                });
            }
        } else if entry.sequence != 1 {
            return Err(PrivateStateJournalError::SequenceMismatch {
                offset,
                expected: 1,
                actual: entry.sequence,
            });
        }
        entries.push(entry);
        offset = offset
            .checked_add(frame_length)
            .ok_or(PrivateStateJournalError::OffsetOverflow)?;
    }
    Ok(FrameScan::Complete(entries))
}

fn encode_payload(
    sequence: u64,
    previous_state_id: StateId,
    nxpr: &[u8],
) -> Result<Vec<u8>, PrivateStateJournalError> {
    let nxpr_length =
        u32::try_from(nxpr.len()).map_err(|_| PrivateStateJournalError::FrameTooLarge {
            offset: 0,
            actual: u32::MAX,
            maximum: PRIVATE_STATE_JOURNAL_MAX_PAYLOAD_LENGTH,
        })?;
    let mut payload = Vec::with_capacity(PRIVATE_STATE_JOURNAL_PAYLOAD_PREFIX_LENGTH + nxpr.len());
    payload.extend_from_slice(&sequence.to_be_bytes());
    payload.extend_from_slice(&previous_state_id.0);
    // `StateId` is encoded in the NXPR header, but is also explicit here so
    // continuity can be checked without trusting that nested byte position.
    let state =
        decode_candidate_private_ledger_state(nxpr).map_err(PrivateStateJournalError::Record)?;
    payload.extend_from_slice(&state.anchor().state_id().0);
    payload.extend_from_slice(&nxpr_length.to_be_bytes());
    payload.extend_from_slice(nxpr);
    Ok(payload)
}

fn decode_payload(
    payload: &[u8],
) -> Result<(u64, StateId, CandidatePrivateLedgerStateV1), PrivateStateJournalError> {
    if payload.len() < PRIVATE_STATE_JOURNAL_PAYLOAD_PREFIX_LENGTH {
        return Err(PrivateStateJournalError::PayloadTruncated);
    }
    let sequence = u64::from_be_bytes(payload[0..8].try_into().expect("fixed range"));
    let previous_state_id = StateId::new(payload[8..40].try_into().expect("fixed range"));
    let resulting_state_id = StateId::new(payload[40..72].try_into().expect("fixed range"));
    let nxpr_length = u32::from_be_bytes(payload[72..76].try_into().expect("fixed range")) as usize;
    if nxpr_length > PRIVATE_STATE_RECORD_MAX_BYTES {
        return Err(PrivateStateJournalError::NestedRecordTooLarge(nxpr_length));
    }
    let nxpr = payload
        .get(PRIVATE_STATE_JOURNAL_PAYLOAD_PREFIX_LENGTH..)
        .ok_or(PrivateStateJournalError::PayloadTruncated)?;
    if nxpr.len() != nxpr_length {
        return Err(PrivateStateJournalError::NestedRecordLength {
            declared: nxpr_length,
            actual: nxpr.len(),
        });
    }
    let state =
        decode_candidate_private_ledger_state(nxpr).map_err(PrivateStateJournalError::Record)?;
    if state.anchor().state_id() != resulting_state_id {
        return Err(PrivateStateJournalError::ResultingStateMismatch {
            encoded: resulting_state_id,
            rebuilt: state.anchor().state_id(),
        });
    }
    Ok((sequence, previous_state_id, state))
}

fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, PrivateStateJournalError> {
    let payload_length =
        u32::try_from(payload.len()).map_err(|_| PrivateStateJournalError::FrameTooLarge {
            offset: 0,
            actual: u32::MAX,
            maximum: PRIVATE_STATE_JOURNAL_MAX_PAYLOAD_LENGTH,
        })?;
    if payload_length > PRIVATE_STATE_JOURNAL_MAX_PAYLOAD_LENGTH {
        return Err(PrivateStateJournalError::FrameTooLarge {
            offset: 0,
            actual: payload_length,
            maximum: PRIVATE_STATE_JOURNAL_MAX_PAYLOAD_LENGTH,
        });
    }
    let mut frame = Vec::with_capacity(
        PRIVATE_STATE_JOURNAL_HEADER_LENGTH + payload.len() + PRIVATE_STATE_JOURNAL_CHECKSUM_LENGTH,
    );
    frame.extend_from_slice(&PRIVATE_STATE_JOURNAL_MAGIC);
    frame.extend_from_slice(&PRIVATE_STATE_JOURNAL_VERSION.to_be_bytes());
    frame.extend_from_slice(&payload_length.to_be_bytes());
    frame.extend_from_slice(payload);
    frame.extend_from_slice(&crc32(payload).to_be_bytes());
    Ok(frame)
}

fn read_exact(
    file: &mut File,
    bytes: &mut [u8],
    path: &Path,
) -> Result<(), PrivateStateJournalError> {
    file.read_exact(bytes)
        .map_err(|source| PrivateStateJournalError::Io {
            operation: "read private-state journal frame",
            path: path.to_path_buf(),
            source,
        })
}

/// Fail-closed errors for `NXPL v1` persistence and recovery.
#[derive(Debug)]
pub enum PrivateStateJournalError {
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
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
    NestedRecordLength {
        declared: usize,
        actual: usize,
    },
    NestedRecordTooLarge(usize),
    Record(CandidatePrivateStateRecordError),
    ResultingStateMismatch {
        encoded: StateId,
        rebuilt: StateId,
    },
    NestedStateMismatch,
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
    BaseStateMismatch {
        expected: StateId,
        actual: StateId,
    },
    SequenceOverflow,
    OffsetOverflow,
    IncompleteTailPresent,
    RecoveryTailChanged,
}

impl fmt::Display for PrivateStateJournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "candidate private-state journal error: {self:?}")
    }
}
impl std::error::Error for PrivateStateJournalError {}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::{
            OnceLock,
            atomic::{AtomicU64, Ordering},
        },
        time::{SystemTime, UNIX_EPOCH},
    };

    use noxis_nullifier_tree_state::NullifierSparseTreeStateV1;
    use noxis_poseidon2_reference::Poseidon2P24Reference;
    use noxis_privacy_types::{
        CiphertextDigestV2, CircuitId, NoteCommitmentV2, NullifierV2, PrivateTransferIntentV2,
        PrivateTransferOutputV2, TreeParametersId, TreeParametersV2,
    };
    use noxis_tree_params::CandidatePoseidon2P24ManifestV2;
    use noxis_types::{AssetDefinition, AssetId, AssetKind, GenesisId, ValidationContextId};

    use super::*;
    use noxis_private_state::{
        CandidatePrivateStateSnapshotV1, CandidatePrivateTransferAuthorizationError,
        CandidatePrivateTransferAuthorizer, CandidatePrivateTransferRequestV1,
    };

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    static STATE_FIXTURE: OnceLock<(CandidatePrivateLedgerStateV1, CandidatePrivateLedgerStateV1)> =
        OnceLock::new();
    const ASSET: AssetId = AssetId::new([5; 32]);

    struct AcceptAll;
    impl CandidatePrivateTransferAuthorizer<()> for AcceptAll {
        fn verify(
            &self,
            _: &(),
            _: &noxis_private_state::PrivateStateAnchorV2,
            _: &NullifierSparseTreeStateV1,
            _: &PrivateTransferIntentV2,
        ) -> Result<(), CandidatePrivateTransferAuthorizationError> {
            Ok(())
        }
    }
    fn commitment(value: u32) -> NoteCommitmentV2 {
        NoteCommitmentV2::from_elements([value; 16]).unwrap()
    }
    fn nullifier(value: u32) -> NullifierV2 {
        NullifierV2::from_elements([value; 16]).unwrap()
    }
    fn path() -> PathBuf {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("noxis-private-journal-{nonce}-{sequence}"))
            .join("state.nxpl")
    }
    fn state() -> CandidatePrivateLedgerStateV1 {
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        let snapshot = CandidatePrivateStateSnapshotV1::new(
            vec![commitment(1), commitment(2)],
            vec![],
            &reference,
        )
        .unwrap();
        let parameters = TreeParametersV2::new(TreeParametersId::new(
            CandidatePoseidon2P24ManifestV2::new()
                .candidate_id()
                .unwrap()
                .as_bytes(),
        ));
        let mut state = CandidatePrivateLedgerStateV1::new(
            GenesisId::new([1; 32]),
            ValidationContextId::new([2; 32]),
            parameters,
            snapshot,
            NullifierSparseTreeStateV1::new_candidate().unwrap(),
        )
        .unwrap();
        state
            .register_asset(AssetDefinition::new(ASSET, "NOX", AssetKind::Synthetic).unwrap())
            .unwrap();
        state
    }
    fn successor(
        state: &CandidatePrivateLedgerStateV1,
        nonce: u32,
    ) -> CandidatePrivateLedgerStateV1 {
        let intent = PrivateTransferIntentV2::new(
            CircuitId::new([4; 32]),
            state.anchor().genesis_id(),
            state.anchor().validation_context_id(),
            state.anchor().state_id(),
            state.anchor().note_tree_parameters(),
            state.anchor().note_root(),
            ASSET,
            [nullifier(nonce), nullifier(nonce + 1)],
            [
                PrivateTransferOutputV2::new(
                    commitment(nonce + 2),
                    CiphertextDigestV2::from_elements([20 + nonce; 16]).unwrap(),
                ),
                PrivateTransferOutputV2::new(
                    commitment(nonce + 3),
                    CiphertextDigestV2::from_elements([21 + nonce; 16]).unwrap(),
                ),
            ],
        )
        .unwrap();
        let mut successor = state.clone();
        successor
            .apply_transfer(
                &CandidatePrivateTransferRequestV1::new(intent, ()),
                &AcceptAll,
            )
            .unwrap();
        successor
    }
    fn states() -> &'static (CandidatePrivateLedgerStateV1, CandidatePrivateLedgerStateV1) {
        STATE_FIXTURE.get_or_init(|| {
            let initial = state();
            let successor = successor(&initial, 10);
            (initial, successor)
        })
    }
    const fn base_state_id() -> StateId {
        StateId::new([99; 32])
    }

    #[test]
    fn appends_recovers_and_enforces_private_state_chain() {
        let path = path();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let (initial, first) = states();
        let mut journal = PrivateStateJournalV1::open(&path).unwrap();
        assert_eq!(
            journal.append_post_state(base_state_id(), initial).unwrap(),
            1
        );
        assert_eq!(
            journal
                .append_post_state(initial.anchor().state_id(), first)
                .unwrap(),
            2
        );
        let recovered = journal.recover_from(base_state_id()).unwrap();
        assert_eq!(recovered.entries.len(), 2);
        assert_eq!(
            recovered.latest().unwrap().state_id(),
            first.anchor().state_id()
        );
        assert!(
            recovered
                .latest()
                .unwrap()
                .state
                .nullifier_tree()
                .is_spent(nullifier(10))
        );
        drop(journal);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn refuses_wrong_predecessor_and_wrong_base() {
        let path = path();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let (initial, first) = states();
        let mut journal = PrivateStateJournalV1::open(&path).unwrap();
        journal.append_post_state(base_state_id(), initial).unwrap();
        assert!(matches!(
            journal.append_post_state(base_state_id(), first),
            Err(PrivateStateJournalError::PredecessorMismatch { .. })
        ));
        assert!(matches!(
            journal.recover_from(StateId::new([98; 32])),
            Err(PrivateStateJournalError::BaseStateMismatch { .. })
        ));
        drop(journal);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn recovered_chain_rejects_a_validly_framed_broken_link() {
        let path = path();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let (initial, first) = states();
        let mut journal = PrivateStateJournalV1::open(&path).unwrap();
        journal.append_post_state(base_state_id(), initial).unwrap();
        let nxpr = encode_candidate_private_ledger_state(first).unwrap();
        let frame = encode_frame(&encode_payload(2, base_state_id(), &nxpr).unwrap()).unwrap();
        journal.file.write_all(&frame).unwrap();
        journal.file.sync_all().unwrap();
        assert!(matches!(
            journal.scan_recoverable_tail(),
            Err(PrivateStateJournalError::PredecessorMismatch { sequence: 2, .. })
        ));
        drop(journal);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn incomplete_final_frame_requires_explicit_verified_truncation() {
        let path = path();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let (initial, first) = states();
        let mut journal = PrivateStateJournalV1::open(&path).unwrap();
        journal.append_post_state(base_state_id(), initial).unwrap();
        journal.file.write_all(b"NXP").unwrap();
        journal.file.sync_all().unwrap();
        let scan = journal.recover_from(base_state_id()).unwrap();
        let tail = scan.incomplete_tail.unwrap();
        assert_eq!(scan.entries.len(), 1);
        assert!(matches!(
            journal.append_post_state(initial.anchor().state_id(), first),
            Err(PrivateStateJournalError::IncompleteTailPresent)
        ));
        journal.truncate_verified_incomplete_tail(tail).unwrap();
        assert!(
            journal
                .scan_recoverable_tail()
                .unwrap()
                .incomplete_tail
                .is_none()
        );
        drop(journal);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn checksum_and_nested_state_tampering_fail_closed() {
        let path = path();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let (initial, _) = states();
        let mut journal = PrivateStateJournalV1::open(&path).unwrap();
        journal.append_post_state(base_state_id(), initial).unwrap();
        drop(journal);
        let mut bytes = fs::read(&path).unwrap();
        let middle = bytes.len() / 2;
        bytes[middle] ^= 1;
        fs::write(&path, bytes).unwrap();
        let mut reopened = PrivateStateJournalV1::open(&path).unwrap();
        assert!(matches!(
            reopened.scan_recoverable_tail(),
            Err(PrivateStateJournalError::ChecksumMismatch { .. })
        ));
        drop(reopened);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
