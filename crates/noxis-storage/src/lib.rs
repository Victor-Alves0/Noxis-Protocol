//! Durable append-only state-record storage.
//!
//! [`PersistentLedger`] uses the `NXRF` frame codec in [`record_log`] to
//! persist and replay complete `NXRC` state-transition records. It validates a
//! genesis-bound chain anchor, replays the ledger transition function, and
//! confirms each resulting state identifier before becoming writable.
//!
//! The `NXLG` transaction-only component below is retained solely as a legacy
//! reader/migration source. It is not accepted by `PersistentLedger` because
//! it has no state links.
//!
//! An `NXLG` frame stores a canonical Noxis transaction payload:
//!
//! ```text
//! magic (4 bytes) | format version (u16, big-endian) | payload length (u32, big-endian)
//! | canonical transaction bytes (payload length bytes) | CRC-32 (u32, big-endian)
//! ```
//!
//! `append_transaction_bytes` writes a complete frame, flushes the userspace buffer,
//! and calls `sync_data` before reporting success. Filesystems do not promise
//! that an interrupted append is physically atomic; instead, opening a log
//! fails closed when it finds a partial or corrupt frame. Callers must not
//! accept a partially recovered prefix as a valid ledger history.
//!
//! `NXCP` artifacts may be published and checked against a complete replay,
//! but are not trusted to skip any unauthenticated history prefix. Formal
//! filesystem fault injection and a full storage-platform crash guarantee
//! remain outside the currently implemented durability scope.

use std::{
    collections::{BTreeMap, btree_map::Entry},
    fmt,
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

pub mod block_journal;
pub mod checkpoint_store;
mod persistent_execution;
pub mod private_state_store;
pub mod record_log;

pub use persistent_execution::{
    DurableBlockReceipt, PersistentExecution, PersistentExecutionError,
};
pub use private_state_store::{PrivateStateStoreError, PrivateStateStoreV1};

use noxis_checkpoint::{Checkpoint, CheckpointError};
use noxis_codec::{CodecError, decode_transaction, encode_transaction, transaction_intent_id};
use noxis_crypto::{ProofVerifier, ValidationContext};
use noxis_ledger::{
    LedgerError, LedgerState, MintPolicy, Transaction, TransactionValidationContext,
};
use noxis_record_chain::{RecordChain, RecordError, RecordHash, TransactionRecord};
use noxis_types::{
    ChainAnchor, GenesisId, MintPolicyId, ProofVerifierId, StateId, TransactionIntentId,
    ValidationContextId,
};

use crate::{
    checkpoint_store::{CheckpointReceipt, CheckpointStore, CheckpointStoreError},
    record_log::{RecordLogError, StateRecordLog},
};

/// Magic bytes identifying a Noxis transaction-log frame.
pub const FRAME_MAGIC: [u8; 4] = *b"NXLG";
/// Frame layout version supported by this crate.
pub const FRAME_VERSION: u16 = 1;
/// Number of bytes before a frame payload.
pub const FRAME_HEADER_LENGTH: usize = 10;
/// Number of checksum bytes after a frame payload.
pub const FRAME_CHECKSUM_LENGTH: usize = 4;
/// Upper bound that prevents a corrupt length field from allocating unbounded memory.
pub const MAX_FRAME_PAYLOAD_LENGTH: u32 = 32 * 1024 * 1024;

/// A verified entry recovered from a transaction log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredTransaction {
    /// Byte offset of this frame in the log file.
    pub offset: u64,
    /// Canonical bytes as produced by `noxis_codec::encode_transaction`.
    pub bytes: Vec<u8>,
}

enum FrameScan {
    Complete(Vec<StoredTransaction>),
    IncompleteTail {
        valid_prefix_length: u64,
        section: &'static str,
    },
}

/// A single-writer append-only transaction log.
pub struct TransactionLog {
    path: PathBuf,
    file: File,
}

impl TransactionLog {
    /// Opens an existing log (or creates an empty one) after validating every frame.
    ///
    /// No repair is attempted. A malformed, checksum-invalid, or truncated log is
    /// rejected so that callers cannot silently operate on an incomplete history.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = path.as_ref().to_path_buf();
        let mut file = open_log_file(&path)?;

        validate_file(&mut file)?;
        file.seek(SeekFrom::End(0))
            .map_err(|source| StorageError::Io {
                operation: "seek transaction log end",
                source,
            })?;

        Ok(Self { path, file })
    }

    /// Opens a log and removes only a demonstrably incomplete final frame.
    ///
    /// This is intentionally explicit: [`Self::open`] preserves every byte for
    /// investigation and fails closed. This recovery mode only removes a final
    /// partial frame whose prefix is structurally plausible; corruption in a
    /// complete frame, or an invalid byte suffix, still causes an error.
    pub fn open_recovering_incomplete_tail(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = path.as_ref().to_path_buf();
        let mut file = open_log_file(&path)?;
        match scan_frames(&mut file)? {
            FrameScan::Complete(_) => {}
            FrameScan::IncompleteTail {
                valid_prefix_length,
                ..
            } => {
                file.set_len(valid_prefix_length)
                    .map_err(|source| StorageError::Io {
                        operation: "remove incomplete transaction-log tail",
                        source,
                    })?;
                file.sync_all().map_err(|source| StorageError::Io {
                    operation: "sync recovered transaction log",
                    source,
                })?;
                validate_file(&mut file)?;
            }
        }
        file.seek(SeekFrom::End(0))
            .map_err(|source| StorageError::Io {
                operation: "seek transaction log end",
                source,
            })?;
        Ok(Self { path, file })
    }

    /// Returns the log path used by this writer.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends canonical transaction bytes as a frame and makes the successful write durable.
    ///
    /// The returned offset identifies the beginning of the new frame. A returned
    /// `Ok` means `sync_data` completed; an I/O failure leaves the log unusable
    /// until it is re-opened and fully validated.
    pub fn append_transaction_bytes(
        &mut self,
        transaction_bytes: &[u8],
    ) -> Result<u64, StorageError> {
        let transaction = decode_transaction(transaction_bytes).map_err(StorageError::Codec)?;
        let payload = encode_transaction(&transaction).map_err(StorageError::Codec)?;
        if payload != transaction_bytes {
            return Err(StorageError::NonCanonicalTransaction);
        }
        let frame = encode_frame(&payload)?;
        let offset = self
            .file
            .seek(SeekFrom::End(0))
            .map_err(|source| StorageError::Io {
                operation: "seek transaction log end",
                source,
            })?;

        self.file
            .write_all(&frame)
            .map_err(|source| StorageError::Io {
                operation: "append transaction frame",
                source,
            })?;
        self.file.flush().map_err(|source| StorageError::Io {
            operation: "flush transaction frame",
            source,
        })?;
        self.file.sync_data().map_err(|source| StorageError::Io {
            operation: "sync transaction frame",
            source,
        })?;
        Ok(offset)
    }

    /// Recovers all validated frames and decodes their canonical transactions.
    pub fn read_transactions(&mut self) -> Result<Vec<StoredTransaction>, StorageError> {
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|source| StorageError::Io {
                operation: "seek transaction log start",
                source,
            })?;
        let entries = read_frames(&mut self.file)?;
        self.file
            .seek(SeekFrom::End(0))
            .map_err(|source| StorageError::Io {
                operation: "seek transaction log end",
                source,
            })?;
        Ok(entries)
    }
}

/// A single-process durable ledger coordinator.
///
/// It validates a candidate state first, durably appends its canonical
/// transaction, then publishes the candidate state in memory. After a failed
/// append the instance refuses further writes; callers must reopen and replay
/// the log before trying again. This prevents one process from silently
/// continuing after an uncertain disk write.
pub struct PersistentLedger {
    state: LedgerState,
    anchor: ChainAnchor,
    validation_context: ValidationContext,
    record_log: StateRecordLog,
    chain: RecordChain,
    terminal_record_hash: Option<RecordHash>,
    recovered_checkpoint_sequence: Option<u64>,
    writes_available: bool,
}

/// The durable facts established by one accepted local state transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistentCommitReceipt {
    /// Position of the record, with genesis at sequence zero.
    pub sequence: u64,
    /// Non-self-referential identity of the stored transaction intent.
    pub transaction_intent_id: TransactionIntentId,
    /// Hash committing to the full stored transition record.
    pub record_hash: RecordHash,
    /// Deterministic local state identity after the transition.
    pub state_id: StateId,
    /// Physical frame position, useful only for local diagnostics.
    pub log_offset: u64,
}

/// Public, local status of a recovered durable state chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistentLedgerStatus {
    /// Genesis/deployment identity that bounds this local history.
    pub genesis_id: GenesisId,
    /// Public identity of the verifier and mint policy required for recovery.
    pub validation_context_id: ValidationContextId,
    /// Sequence of the recovered current state; genesis is zero.
    pub sequence: u64,
    /// Most recent checkpoint independently checked during this strict replay.
    /// It is diagnostic only and never replaces the authoritative `NXRF` log.
    pub recovered_checkpoint_sequence: Option<u64>,
    /// Deterministic local identity of the recovered current state.
    pub state_id: StateId,
}

impl PersistentLedger {
    /// Rebuilds ledger state by replaying an ordered, state-linked record log.
    ///
    /// `initial_state` is the configured genesis state, including registered
    /// assets and fixed Merkle-tree depth. The verifier and mint policy must be
    /// deterministic for historic transactions; a policy that changes its
    /// answer over time makes safe recovery impossible. `anchor` must be the
    /// canonical `(GenesisId, genesis StateId)` pair for `initial_state`.
    pub fn open(
        path: impl AsRef<Path>,
        initial_state: LedgerState,
        anchor: ChainAnchor,
        validation_context: ValidationContext,
        verifier: &dyn ProofVerifier,
        mint_policy: &dyn MintPolicy,
    ) -> Result<Self, PersistentLedgerError> {
        Self::open_internal(
            path,
            initial_state,
            anchor,
            validation_context,
            verifier,
            mint_policy,
            None,
        )
    }

    /// Opens a ledger and additionally verifies any eligible `NXCP` files.
    ///
    /// Checkpoints do not shorten this recovery path: every complete state
    /// record is still replayed and validated from genesis before a checkpoint
    /// can be reported as verified.
    pub fn open_with_checkpoints(
        path: impl AsRef<Path>,
        checkpoint_directory: impl Into<PathBuf>,
        initial_state: LedgerState,
        anchor: ChainAnchor,
        validation_context: ValidationContext,
        verifier: &dyn ProofVerifier,
        mint_policy: &dyn MintPolicy,
    ) -> Result<Self, PersistentLedgerError> {
        let checkpoint_store = CheckpointStore::new(checkpoint_directory)
            .map_err(PersistentLedgerError::CheckpointStore)?;
        Self::open_internal(
            path,
            initial_state,
            anchor,
            validation_context,
            verifier,
            mint_policy,
            Some(checkpoint_store),
        )
    }

    fn open_internal(
        path: impl AsRef<Path>,
        initial_state: LedgerState,
        anchor: ChainAnchor,
        validation_context: ValidationContext,
        verifier: &dyn ProofVerifier,
        mint_policy: &dyn MintPolicy,
        checkpoint_store: Option<CheckpointStore>,
    ) -> Result<Self, PersistentLedgerError> {
        validation_context
            .validate()
            .map_err(PersistentLedgerError::InvalidValidationContext)?;
        if validation_context.id() != anchor.validation_context_id
            || validation_context.proof_verifier_id() != anchor.proof_verifier_id
            || validation_context.mint_policy_id() != anchor.mint_policy_id
        {
            return Err(PersistentLedgerError::InvalidChainAnchorContext {
                anchor: anchor.validation_context_id,
                supplied: validation_context.id(),
            });
        }
        ensure_validation_components(anchor, verifier, mint_policy)?;
        let computed_genesis_state_id = initial_state.state_id(anchor.genesis_id);
        if computed_genesis_state_id != anchor.genesis_state_id {
            return Err(PersistentLedgerError::InvalidChainAnchor {
                configured: anchor.genesis_state_id,
                computed: computed_genesis_state_id,
            });
        }
        let mut record_log =
            StateRecordLog::open_for_recovery(path).map_err(PersistentLedgerError::RecordLog)?;
        let recovery_scan = record_log
            .scan_recoverable_tail()
            .map_err(PersistentLedgerError::RecordLog)?;
        let checkpoint_candidates = checkpoint_store
            .as_ref()
            .map(CheckpointStore::load_candidates)
            .transpose()
            .map_err(PersistentLedgerError::CheckpointStore)?;
        let mut checkpoint_candidates = checkpoint_candidates_by_sequence(checkpoint_candidates)?;
        let mut state = initial_state;
        let mut chain = RecordChain::new(anchor.genesis_state_id);
        let mut terminal_record_hash = None;
        let mut recovered_checkpoint_sequence = None;
        for stored in &recovery_scan.records {
            let record = &stored.record;
            chain
                .apply(record)
                .map_err(PersistentLedgerError::RecordChain)?;
            let transaction = decode_transaction(record.transaction_bytes())
                .map_err(PersistentLedgerError::Codec)?;
            ensure_transaction_suite(validation_context, transaction.suite)?;
            let transition_context = TransactionValidationContext::new(
                anchor.genesis_id,
                anchor.validation_context_id,
                record.transaction_intent_id(),
                record.previous_state_id(),
            );
            let mut next_state = state.clone();
            next_state
                .apply(&transaction, verifier, mint_policy, transition_context)
                .map_err(PersistentLedgerError::Ledger)?;
            let computed_state_id = next_state.state_id(anchor.genesis_id);
            if record.resulting_state_id() != computed_state_id {
                return Err(PersistentLedgerError::ResultingStateIdMismatch {
                    record: record.resulting_state_id(),
                    computed: computed_state_id,
                });
            }
            terminal_record_hash = Some(record.record_hash());
            if let Some(checkpoint) = checkpoint_candidates.remove(&record.sequence())
                && let Some(restored) =
                    restore_verified_checkpoint_at_record(&checkpoint, record, &next_state, anchor)
            {
                state = restored;
                recovered_checkpoint_sequence = Some(record.sequence());
                continue;
            }
            state = next_state;
        }
        if let Some(incomplete_tail) = recovery_scan.incomplete_tail {
            record_log
                .truncate_verified_incomplete_tail(incomplete_tail)
                .map_err(PersistentLedgerError::RecordLog)?;
        }
        Ok(Self {
            state,
            anchor,
            validation_context,
            record_log,
            chain,
            terminal_record_hash,
            recovered_checkpoint_sequence,
            writes_available: true,
        })
    }

    pub fn state(&self) -> &LedgerState {
        &self.state
    }

    /// Returns the recovered sequence and local state identity.
    pub const fn status(&self) -> PersistentLedgerStatus {
        PersistentLedgerStatus {
            genesis_id: self.anchor.genesis_id,
            validation_context_id: self.anchor.validation_context_id,
            sequence: self.chain.current_sequence(),
            recovered_checkpoint_sequence: self.recovered_checkpoint_sequence,
            state_id: self.chain.current_state_id(),
        }
    }

    /// Captures and atomically publishes the current state after its terminal
    /// `NXRC` record is already durable. The record log remains authoritative.
    pub fn publish_checkpoint(
        &mut self,
        checkpoint_directory: impl Into<PathBuf>,
    ) -> Result<CheckpointReceipt, PersistentLedgerError> {
        let terminal_record_hash = self
            .terminal_record_hash
            .ok_or(PersistentLedgerError::CheckpointAtGenesis)?;
        let checkpoint = Checkpoint::from_snapshot(
            self.anchor,
            self.chain.current_sequence(),
            terminal_record_hash,
            self.state.snapshot(),
        )
        .map_err(PersistentLedgerError::Checkpoint)?;
        let store = CheckpointStore::new(checkpoint_directory)
            .map_err(PersistentLedgerError::CheckpointStore)?;
        store
            .publish(&checkpoint)
            .map_err(PersistentLedgerError::CheckpointStore)
    }

    /// Validates, durably records, and then publishes exactly one transition.
    pub fn apply(
        &mut self,
        transaction: &Transaction,
        verifier: &dyn ProofVerifier,
        mint_policy: &dyn MintPolicy,
    ) -> Result<PersistentCommitReceipt, PersistentLedgerError> {
        if !self.writes_available {
            return Err(PersistentLedgerError::WriteUnavailable);
        }
        ensure_validation_components(self.anchor, verifier, mint_policy)?;
        ensure_transaction_suite(self.validation_context, transaction.suite)?;

        let transaction_bytes =
            encode_transaction(transaction).map_err(PersistentLedgerError::Codec)?;
        let transaction_intent_id =
            transaction_intent_id(transaction).map_err(PersistentLedgerError::Codec)?;
        let transition_context = TransactionValidationContext::new(
            self.anchor.genesis_id,
            self.anchor.validation_context_id,
            transaction_intent_id,
            self.chain.current_state_id(),
        );
        let mut candidate = self.state.clone();
        candidate
            .apply(transaction, verifier, mint_policy, transition_context)
            .map_err(PersistentLedgerError::Ledger)?;
        let record = TransactionRecord::new(
            self.chain.next_sequence(),
            self.chain.current_state_id(),
            transaction_bytes,
            candidate.state_id(self.anchor.genesis_id),
        )
        .map_err(PersistentLedgerError::RecordChain)?;
        let mut candidate_chain = self.chain;
        candidate_chain
            .apply(&record)
            .map_err(PersistentLedgerError::RecordChain)?;

        match self.record_log.append_record(&record) {
            Ok(offset) => {
                self.state = candidate;
                self.chain = candidate_chain;
                self.terminal_record_hash = Some(record.record_hash());
                Ok(PersistentCommitReceipt {
                    sequence: record.sequence(),
                    transaction_intent_id: record.transaction_intent_id(),
                    record_hash: record.record_hash(),
                    state_id: record.resulting_state_id(),
                    log_offset: offset,
                })
            }
            Err(error) => {
                self.writes_available = false;
                Err(PersistentLedgerError::RecordLog(error))
            }
        }
    }
}

fn checkpoint_candidates_by_sequence(
    candidates: Option<Vec<CheckpointReceipt>>,
) -> Result<BTreeMap<u64, CheckpointReceipt>, PersistentLedgerError> {
    let mut by_sequence = BTreeMap::new();
    for candidate in candidates.unwrap_or_default() {
        match by_sequence.entry(candidate.checkpoint.sequence()) {
            Entry::Vacant(entry) => {
                entry.insert(candidate);
            }
            Entry::Occupied(entry) if entry.get().checkpoint == candidate.checkpoint => {}
            Entry::Occupied(entry) => {
                return Err(PersistentLedgerError::AmbiguousCheckpoints {
                    sequence: candidate.checkpoint.sequence(),
                    first: entry.get().path.clone(),
                    second: candidate.path,
                });
            }
        }
    }
    Ok(by_sequence)
}

fn restore_verified_checkpoint_at_record(
    checkpoint: &CheckpointReceipt,
    record: &TransactionRecord,
    replayed_state: &LedgerState,
    anchor: ChainAnchor,
) -> Option<LedgerState> {
    if checkpoint.checkpoint.sequence() != record.sequence()
        || checkpoint.checkpoint.terminal_record_hash() != record.record_hash()
        || checkpoint.checkpoint.state_id() != record.resulting_state_id()
    {
        return None;
    }
    let Ok(restored_state) = checkpoint.checkpoint.restore_state(anchor) else {
        return None;
    };
    (restored_state.snapshot() == replayed_state.snapshot()).then_some(restored_state)
}

fn ensure_validation_components(
    anchor: ChainAnchor,
    verifier: &dyn ProofVerifier,
    mint_policy: &dyn MintPolicy,
) -> Result<(), PersistentLedgerError> {
    let verifier_id = verifier.proof_verifier_id();
    let mint_policy_id = mint_policy.mint_policy_id();
    if verifier_id != anchor.proof_verifier_id || mint_policy_id != anchor.mint_policy_id {
        return Err(PersistentLedgerError::ValidationContextMismatch(Box::new(
            ValidationContextMismatch {
                expected: anchor.validation_context_id,
                expected_proof_verifier: anchor.proof_verifier_id,
                actual_proof_verifier: verifier_id,
                expected_mint_policy: anchor.mint_policy_id,
                actual_mint_policy: mint_policy_id,
            },
        )));
    }
    Ok(())
}

fn ensure_transaction_suite(
    validation_context: ValidationContext,
    transaction_suite: noxis_crypto::CryptoSuite,
) -> Result<(), PersistentLedgerError> {
    let expected = validation_context.crypto_suite();
    if transaction_suite == expected {
        Ok(())
    } else {
        Err(PersistentLedgerError::TransactionCryptoSuiteMismatch {
            expected,
            actual: transaction_suite,
        })
    }
}

#[derive(Debug)]
pub enum PersistentLedgerError {
    Storage(StorageError),
    RecordLog(RecordLogError),
    RecordChain(RecordError),
    Codec(CodecError),
    Ledger(LedgerError),
    Checkpoint(CheckpointError),
    CheckpointStore(CheckpointStoreError),
    InvalidValidationContext(noxis_crypto::ValidationContextError),
    CheckpointAtGenesis,
    AmbiguousCheckpoints {
        sequence: u64,
        first: PathBuf,
        second: PathBuf,
    },
    InvalidChainAnchor {
        configured: StateId,
        computed: StateId,
    },
    InvalidChainAnchorContext {
        anchor: ValidationContextId,
        supplied: ValidationContextId,
    },
    ValidationContextMismatch(Box<ValidationContextMismatch>),
    TransactionCryptoSuiteMismatch {
        expected: noxis_crypto::CryptoSuite,
        actual: noxis_crypto::CryptoSuite,
    },
    ResultingStateIdMismatch {
        record: StateId,
        computed: StateId,
    },
    WriteUnavailable,
}

/// Detailed component identities for a rejected validation context.
///
/// It is boxed by [`PersistentLedgerError`] so successful and ordinary error
/// paths do not carry five 32-byte identifiers by value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationContextMismatch {
    expected: ValidationContextId,
    expected_proof_verifier: ProofVerifierId,
    actual_proof_verifier: ProofVerifierId,
    expected_mint_policy: MintPolicyId,
    actual_mint_policy: MintPolicyId,
}

impl fmt::Display for PersistentLedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(formatter, "durable log error: {error}"),
            Self::RecordLog(error) => write!(formatter, "durable state-record log error: {error}"),
            Self::RecordChain(error) => write!(formatter, "state-record chain error: {error}"),
            Self::Codec(error) => write!(formatter, "transaction codec error: {error}"),
            Self::Ledger(error) => write!(formatter, "ledger transition error: {error}"),
            Self::Checkpoint(error) => write!(formatter, "checkpoint error: {error}"),
            Self::CheckpointStore(error) => write!(formatter, "checkpoint storage error: {error}"),
            Self::InvalidValidationContext(error) => {
                write!(formatter, "invalid configured validation context: {error}")
            }
            Self::CheckpointAtGenesis => formatter.write_str(
                "cannot publish a checkpoint before a durable terminal state record exists",
            ),
            Self::AmbiguousCheckpoints { sequence, .. } => {
                write!(formatter, "multiple distinct checkpoints claim sequence {sequence}")
            }
            Self::InvalidChainAnchor { .. } => formatter.write_str(
                "configured genesis state ID does not match the supplied genesis state",
            ),
            Self::InvalidChainAnchorContext { .. } => formatter.write_str(
                "configured chain anchor does not match the supplied validation context",
            ),
            Self::ValidationContextMismatch(_) => formatter.write_str(
                "configured validation context does not match the proof verifier or mint policy",
            ),
            Self::TransactionCryptoSuiteMismatch { .. } => formatter.write_str(
                "transaction cryptographic suite does not match the genesis validation context",
            ),
            Self::ResultingStateIdMismatch { .. } => formatter.write_str(
                "state-record result identifier does not match the replayed ledger state",
            ),
            Self::WriteUnavailable => formatter.write_str(
                "writes are unavailable after an uncertain append; reopen and replay before continuing",
            ),
        }
    }
}

impl std::error::Error for PersistentLedgerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(error) => Some(error),
            Self::RecordLog(error) => Some(error),
            Self::RecordChain(error) => Some(error),
            Self::Codec(error) => Some(error),
            Self::Ledger(error) => Some(error),
            Self::Checkpoint(error) => Some(error),
            Self::CheckpointStore(error) => Some(error),
            Self::InvalidValidationContext(error) => Some(error),
            Self::InvalidChainAnchor { .. }
            | Self::InvalidChainAnchorContext { .. }
            | Self::ValidationContextMismatch(_)
            | Self::TransactionCryptoSuiteMismatch { .. }
            | Self::CheckpointAtGenesis
            | Self::AmbiguousCheckpoints { .. }
            | Self::ResultingStateIdMismatch { .. }
            | Self::WriteUnavailable => None,
        }
    }
}

fn validate_file(file: &mut File) -> Result<(), StorageError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|source| StorageError::Io {
            operation: "seek transaction log start",
            source,
        })?;
    match scan_frames(file)? {
        FrameScan::Complete(_) => Ok(()),
        FrameScan::IncompleteTail {
            valid_prefix_length,
            section,
            ..
        } => Err(StorageError::TruncatedFrame {
            offset: valid_prefix_length,
            section,
        }),
    }
}

fn read_frames(file: &mut File) -> Result<Vec<StoredTransaction>, StorageError> {
    match scan_frames(file)? {
        FrameScan::Complete(entries) => Ok(entries),
        FrameScan::IncompleteTail {
            valid_prefix_length,
            section,
            ..
        } => Err(StorageError::TruncatedFrame {
            offset: valid_prefix_length,
            section,
        }),
    }
}

fn scan_frames(file: &mut File) -> Result<FrameScan, StorageError> {
    let mut entries = Vec::new();
    let mut offset = 0_u64;
    let file_length = file
        .metadata()
        .map_err(|source| StorageError::Io {
            operation: "read transaction log metadata",
            source,
        })?
        .len();

    while offset < file_length {
        let remaining = file_length - offset;
        if remaining < 4 {
            let mut partial_magic = vec![0_u8; remaining as usize];
            read_exact_storage(file, &mut partial_magic)?;
            if FRAME_MAGIC.starts_with(&partial_magic) {
                return Ok(FrameScan::IncompleteTail {
                    valid_prefix_length: offset,
                    section: "frame magic",
                });
            }
            return Err(StorageError::InvalidMagic { offset });
        }

        let mut magic = [0_u8; 4];
        read_exact_storage(file, &mut magic)?;
        if magic != FRAME_MAGIC {
            return Err(StorageError::InvalidMagic { offset });
        }
        if remaining < FRAME_HEADER_LENGTH as u64 {
            return Ok(FrameScan::IncompleteTail {
                valid_prefix_length: offset,
                section: "frame header",
            });
        }

        let mut header_remainder = [0_u8; FRAME_HEADER_LENGTH - 4];
        read_exact_storage(file, &mut header_remainder)?;
        let version = u16::from_be_bytes([header_remainder[0], header_remainder[1]]);
        if version != FRAME_VERSION {
            return Err(StorageError::UnsupportedFrameVersion { offset, version });
        }
        let payload_length = u32::from_be_bytes([
            header_remainder[2],
            header_remainder[3],
            header_remainder[4],
            header_remainder[5],
        ]);
        if payload_length > MAX_FRAME_PAYLOAD_LENGTH {
            return Err(StorageError::FrameTooLarge {
                offset,
                actual: payload_length,
                maximum: MAX_FRAME_PAYLOAD_LENGTH,
            });
        }
        let frame_length = (FRAME_HEADER_LENGTH as u64)
            .checked_add(payload_length as u64)
            .and_then(|value| value.checked_add(FRAME_CHECKSUM_LENGTH as u64))
            .ok_or(StorageError::LogOffsetOverflow)?;
        if remaining < frame_length {
            return Ok(FrameScan::IncompleteTail {
                valid_prefix_length: offset,
                section: if remaining < FRAME_HEADER_LENGTH as u64 + payload_length as u64 {
                    "frame payload"
                } else {
                    "frame checksum"
                },
            });
        }

        let mut payload = vec![0_u8; payload_length as usize];
        read_exact_storage(file, &mut payload)?;
        let mut checksum_bytes = [0_u8; FRAME_CHECKSUM_LENGTH];
        read_exact_storage(file, &mut checksum_bytes)?;
        let expected_checksum = u32::from_be_bytes(checksum_bytes);
        let actual_checksum = crc32(&payload);
        if actual_checksum != expected_checksum {
            return Err(StorageError::ChecksumMismatch {
                offset,
                expected: expected_checksum,
                actual: actual_checksum,
            });
        }

        // Decoding here ensures the log never reports unactionable bytes as a valid entry.
        decode_transaction(&payload)
            .map_err(|source| StorageError::InvalidTransaction { offset, source })?;
        entries.push(StoredTransaction {
            offset,
            bytes: payload,
        });
        offset = offset
            .checked_add(frame_length)
            .ok_or(StorageError::LogOffsetOverflow)?;
    }
    Ok(FrameScan::Complete(entries))
}

fn open_log_file(path: &Path) -> Result<File, StorageError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|source| StorageError::Io {
            operation: "open transaction log",
            source,
        })
}

fn read_exact_storage(file: &mut File, bytes: &mut [u8]) -> Result<(), StorageError> {
    file.read_exact(bytes).map_err(|source| StorageError::Io {
        operation: "read transaction frame",
        source,
    })
}

fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, StorageError> {
    let payload_length = u32::try_from(payload.len()).map_err(|_| StorageError::FrameTooLarge {
        offset: 0,
        actual: u32::MAX,
        maximum: MAX_FRAME_PAYLOAD_LENGTH,
    })?;
    if payload_length > MAX_FRAME_PAYLOAD_LENGTH {
        return Err(StorageError::FrameTooLarge {
            offset: 0,
            actual: payload_length,
            maximum: MAX_FRAME_PAYLOAD_LENGTH,
        });
    }

    let mut frame = Vec::with_capacity(FRAME_HEADER_LENGTH + payload.len() + FRAME_CHECKSUM_LENGTH);
    frame.extend_from_slice(&FRAME_MAGIC);
    frame.extend_from_slice(&FRAME_VERSION.to_be_bytes());
    frame.extend_from_slice(&payload_length.to_be_bytes());
    frame.extend_from_slice(payload);
    frame.extend_from_slice(&crc32(payload).to_be_bytes());
    Ok(frame)
}

/// IEEE CRC-32 used to detect accidental corruption of a log frame.
///
/// CRC-32 is deliberately not treated as an authenticity primitive. Transaction
/// validity, signatures, and proofs remain the responsibility of the protocol.
pub(crate) fn crc32(bytes: &[u8]) -> u32 {
    let mut value = 0xffff_ffff_u32;
    for byte in bytes {
        value ^= u32::from(*byte);
        for _ in 0..8 {
            value = if value & 1 == 1 {
                (value >> 1) ^ 0xedb8_8320
            } else {
                value >> 1
            };
        }
    }
    !value
}

/// An exact reason a transaction log cannot be safely opened or written.
#[derive(Debug)]
pub enum StorageError {
    Io {
        operation: &'static str,
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
    TruncatedFrame {
        offset: u64,
        section: &'static str,
    },
    ChecksumMismatch {
        offset: u64,
        expected: u32,
        actual: u32,
    },
    InvalidTransaction {
        offset: u64,
        source: CodecError,
    },
    NonCanonicalTransaction,
    LogOffsetOverflow,
    Codec(CodecError),
}

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, source } => write!(formatter, "{operation}: {source}"),
            Self::InvalidMagic { offset } => {
                write!(formatter, "invalid frame magic at offset {offset}")
            }
            Self::UnsupportedFrameVersion { offset, version } => {
                write!(
                    formatter,
                    "unsupported frame version {version} at offset {offset}"
                )
            }
            Self::FrameTooLarge {
                offset,
                actual,
                maximum,
            } => write!(
                formatter,
                "frame at offset {offset} has length {actual}, above limit {maximum}"
            ),
            Self::TruncatedFrame { offset, section } => {
                write!(
                    formatter,
                    "truncated {section} for frame at offset {offset}"
                )
            }
            Self::ChecksumMismatch {
                offset,
                expected,
                actual,
            } => write!(
                formatter,
                "checksum mismatch at offset {offset}: expected {expected:08x}, got {actual:08x}"
            ),
            Self::InvalidTransaction { offset, source } => {
                write!(
                    formatter,
                    "invalid transaction payload at offset {offset}: {source}"
                )
            }
            Self::NonCanonicalTransaction => {
                formatter.write_str("transaction bytes are not in Noxis canonical form")
            }
            Self::LogOffsetOverflow => formatter.write_str("transaction log offset overflow"),
            Self::Codec(source) => write!(formatter, "cannot encode transaction: {source}"),
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::InvalidTransaction { source, .. } | Self::Codec(source) => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use noxis_crypto::{AlgorithmId, CryptoSuite, Proof, ValidationContext};
    use noxis_ledger::{
        DenyAllMints, LedgerError, LedgerState, MintAuthorizationError, MintPolicy, MintStatement,
        Operation, Transaction, Transfer,
    };
    use noxis_types::{
        AssetDefinition, AssetId, AssetKind, Commitment, MintPolicyId, Nullifier, ProofVerifierId,
        TransactionId,
    };

    use super::*;

    static TEMP_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEMP_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "noxis-storage-test-{}-{nanos}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn log_path(&self) -> PathBuf {
            self.0.join("transactions.nxlg")
        }

        fn checkpoint_directory(&self) -> PathBuf {
            self.0.join("checkpoints")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn transaction(id: u8) -> Transaction {
        transaction_with(id, 3, 4)
    }

    fn transaction_with(id: u8, nullifier: u8, commitment: u8) -> Transaction {
        Transaction {
            id: TransactionId::new([id; 32]),
            suite: CryptoSuite::RESEARCH_V1,
            operation: Operation::Transfer(Transfer {
                asset_id: AssetId::new([2; 32]),
                input_nullifiers: vec![Nullifier::new([nullifier; 32])],
                output_commitments: vec![Commitment::new([commitment; 32])],
                proof: Proof {
                    suite_version: CryptoSuite::RESEARCH_V1.version,
                    bytes: vec![5, id],
                },
            }),
        }
    }

    fn mint_transaction() -> Transaction {
        Transaction {
            id: TransactionId::new([9; 32]),
            suite: CryptoSuite::RESEARCH_V1,
            operation: Operation::Mint(noxis_ledger::Mint {
                asset_id: AssetId::new([2; 32]),
                amount: noxis_types::Amount::new(100).unwrap(),
                output_commitments: vec![Commitment::new([4; 32])],
                authorization: b"test-authorized".to_vec(),
            }),
        }
    }

    fn different_valid_suite() -> CryptoSuite {
        CryptoSuite {
            identity_signature: AlgorithmId::Ed25519,
            ..CryptoSuite::RESEARCH_V1
        }
    }

    struct TestVerifier;

    impl ProofVerifier for TestVerifier {
        fn proof_verifier_id(&self) -> ProofVerifierId {
            ProofVerifierId::new([1; 32])
        }

        fn verify_transfer(
            &self,
            _statement: &noxis_crypto::TransferStatement,
            _proof: &Proof,
        ) -> Result<(), noxis_crypto::VerificationError> {
            Ok(())
        }
    }

    struct BindingVerifier {
        expected_genesis_id: GenesisId,
        expected_validation_context_id: ValidationContextId,
        expected_transaction_intent_id: TransactionIntentId,
        expected_state_id: StateId,
    }

    impl ProofVerifier for BindingVerifier {
        fn proof_verifier_id(&self) -> ProofVerifierId {
            ProofVerifierId::new([1; 32])
        }

        fn verify_transfer(
            &self,
            statement: &noxis_crypto::TransferStatement,
            _proof: &Proof,
        ) -> Result<(), noxis_crypto::VerificationError> {
            assert_eq!(statement.genesis_id, self.expected_genesis_id);
            assert_eq!(
                statement.validation_context_id,
                self.expected_validation_context_id
            );
            assert_eq!(
                statement.transaction_intent_id,
                self.expected_transaction_intent_id
            );
            assert_eq!(statement.state_id, self.expected_state_id);
            Ok(())
        }
    }

    struct BindingMintPolicy {
        expected_genesis_id: GenesisId,
        expected_validation_context_id: ValidationContextId,
        expected_transaction_intent_id: TransactionIntentId,
        expected_state_id: StateId,
    }

    impl MintPolicy for BindingMintPolicy {
        fn mint_policy_id(&self) -> MintPolicyId {
            MintPolicyId::new([0; 32])
        }

        fn authorize(
            &self,
            statement: &MintStatement,
            authorization: &[u8],
        ) -> Result<(), MintAuthorizationError> {
            assert_eq!(statement.genesis_id, self.expected_genesis_id);
            assert_eq!(
                statement.validation_context_id,
                self.expected_validation_context_id
            );
            assert_eq!(
                statement.transaction_intent_id,
                self.expected_transaction_intent_id
            );
            assert_eq!(statement.state_id, self.expected_state_id);
            assert_eq!(statement.asset_id, AssetId::new([2; 32]));
            assert_eq!(statement.amount, noxis_types::Amount::new(100).unwrap());
            assert_eq!(statement.output_commitments, vec![Commitment::new([4; 32])]);
            assert_eq!(statement.issued_supply_before, None);
            assert_eq!(statement.state_anchor.tree_depth, 8);
            assert_eq!(authorization, b"test-authorized");
            Ok(())
        }
    }

    struct DifferentVerifier;

    impl ProofVerifier for DifferentVerifier {
        fn proof_verifier_id(&self) -> ProofVerifierId {
            ProofVerifierId::new([7; 32])
        }

        fn verify_transfer(
            &self,
            _statement: &noxis_crypto::TransferStatement,
            _proof: &Proof,
        ) -> Result<(), noxis_crypto::VerificationError> {
            Ok(())
        }
    }

    struct DifferentDenyAllMints;

    impl MintPolicy for DifferentDenyAllMints {
        fn mint_policy_id(&self) -> MintPolicyId {
            MintPolicyId::new([8; 32])
        }

        fn authorize(
            &self,
            _statement: &MintStatement,
            _authorization: &[u8],
        ) -> Result<(), MintAuthorizationError> {
            Err(MintAuthorizationError::Denied)
        }
    }

    fn genesis() -> LedgerState {
        let mut state = LedgerState::new(8).unwrap();
        state
            .register_asset(
                AssetDefinition::new(AssetId::new([2; 32]), "USDX", AssetKind::Synthetic).unwrap(),
            )
            .unwrap();
        state
    }

    fn test_anchor(initial_state: &LedgerState) -> ChainAnchor {
        let genesis_id = GenesisId::new([71; 32]);
        let validation_context = test_validation_context();
        ChainAnchor::new(
            genesis_id,
            validation_context.id(),
            ProofVerifierId::new([1; 32]),
            MintPolicyId::new([0; 32]),
            initial_state.state_id(genesis_id),
        )
    }

    fn test_validation_context() -> ValidationContext {
        ValidationContext::new(
            CryptoSuite::RESEARCH_V1,
            ProofVerifierId::new([1; 32]),
            MintPolicyId::new([0; 32]),
        )
    }

    fn open_persistent(path: &Path) -> Result<PersistentLedger, PersistentLedgerError> {
        let initial_state = genesis();
        let anchor = test_anchor(&initial_state);
        PersistentLedger::open(
            path,
            initial_state,
            anchor,
            test_validation_context(),
            &TestVerifier,
            &DenyAllMints,
        )
    }

    fn open_persistent_with_checkpoints(
        path: &Path,
        checkpoint_directory: PathBuf,
    ) -> Result<PersistentLedger, PersistentLedgerError> {
        let initial_state = genesis();
        let anchor = test_anchor(&initial_state);
        PersistentLedger::open_with_checkpoints(
            path,
            checkpoint_directory,
            initial_state,
            anchor,
            test_validation_context(),
            &TestVerifier,
            &DenyAllMints,
        )
    }

    #[test]
    fn validation_context_mismatch_refuses_to_create_or_recover_a_log() {
        let directory = TestDirectory::new();
        let path = directory.log_path();
        let initial_state = genesis();
        let anchor = test_anchor(&initial_state);

        assert!(matches!(
            PersistentLedger::open(
                &path,
                initial_state,
                anchor,
                test_validation_context(),
                &DifferentVerifier,
                &DenyAllMints
            ),
            Err(PersistentLedgerError::ValidationContextMismatch(_))
        ));
        assert!(!path.exists());

        let initial_state = genesis();
        let anchor = test_anchor(&initial_state);
        assert!(matches!(
            PersistentLedger::open(
                &path,
                initial_state,
                anchor,
                test_validation_context(),
                &TestVerifier,
                &DifferentDenyAllMints
            ),
            Err(PersistentLedgerError::ValidationContextMismatch(_))
        ));
        assert!(!path.exists());
    }

    #[test]
    fn persistent_ledger_refuses_a_different_validation_component_after_opening() {
        let directory = TestDirectory::new();
        let path = directory.log_path();
        let mut ledger = open_persistent(&path).unwrap();
        let original_length = fs::metadata(&path).unwrap().len();

        assert!(matches!(
            ledger.apply(&transaction(1), &DifferentVerifier, &DenyAllMints),
            Err(PersistentLedgerError::ValidationContextMismatch(_))
        ));
        assert_eq!(ledger.status().sequence, 0);
        assert_eq!(fs::metadata(&path).unwrap().len(), original_length);
    }

    #[test]
    fn persistent_ledger_binds_genesis_context_and_intent_into_each_proof_statement() {
        let directory = TestDirectory::new();
        let path = directory.log_path();
        let initial_state = genesis();
        let anchor = test_anchor(&initial_state);
        let transaction = transaction(1);
        let verifier = BindingVerifier {
            expected_genesis_id: anchor.genesis_id,
            expected_validation_context_id: anchor.validation_context_id,
            expected_transaction_intent_id: transaction_intent_id(&transaction).unwrap(),
            expected_state_id: anchor.genesis_state_id,
        };
        let mut ledger = PersistentLedger::open(
            &path,
            initial_state,
            anchor,
            test_validation_context(),
            &verifier,
            &DenyAllMints,
        )
        .unwrap();

        ledger
            .apply(&transaction, &verifier, &DenyAllMints)
            .unwrap();
        drop(ledger);

        let initial_state = genesis();
        let anchor = test_anchor(&initial_state);
        let replay_verifier = BindingVerifier {
            expected_genesis_id: anchor.genesis_id,
            expected_validation_context_id: anchor.validation_context_id,
            expected_transaction_intent_id: transaction_intent_id(&transaction).unwrap(),
            expected_state_id: anchor.genesis_state_id,
        };
        let reopened = PersistentLedger::open(
            &path,
            initial_state,
            anchor,
            test_validation_context(),
            &replay_verifier,
            &DenyAllMints,
        )
        .unwrap();
        assert_eq!(reopened.status().sequence, 1);
    }

    #[test]
    fn persistent_ledger_binds_genesis_context_and_intent_into_each_mint_authorization() {
        let directory = TestDirectory::new();
        let path = directory.log_path();
        let initial_state = genesis();
        let anchor = test_anchor(&initial_state);
        let transaction = mint_transaction();
        let policy = BindingMintPolicy {
            expected_genesis_id: anchor.genesis_id,
            expected_validation_context_id: anchor.validation_context_id,
            expected_transaction_intent_id: transaction_intent_id(&transaction).unwrap(),
            expected_state_id: anchor.genesis_state_id,
        };
        let mut ledger = PersistentLedger::open(
            &path,
            initial_state,
            anchor,
            test_validation_context(),
            &TestVerifier,
            &policy,
        )
        .unwrap();
        ledger.apply(&transaction, &TestVerifier, &policy).unwrap();
        drop(ledger);

        let initial_state = genesis();
        let anchor = test_anchor(&initial_state);
        let replay_policy = BindingMintPolicy {
            expected_genesis_id: anchor.genesis_id,
            expected_validation_context_id: anchor.validation_context_id,
            expected_transaction_intent_id: transaction_intent_id(&transaction).unwrap(),
            expected_state_id: anchor.genesis_state_id,
        };
        let reopened = PersistentLedger::open(
            &path,
            initial_state,
            anchor,
            test_validation_context(),
            &TestVerifier,
            &replay_policy,
        )
        .unwrap();
        assert_eq!(reopened.status().sequence, 1);
        assert_eq!(
            reopened
                .state()
                .issued_supply(AssetId::new([2; 32]))
                .unwrap()
                .units(),
            100
        );
    }

    #[test]
    fn persistent_ledger_rejects_a_transaction_from_a_different_valid_suite() {
        let directory = TestDirectory::new();
        let path = directory.log_path();
        let mut ledger = open_persistent(&path).unwrap();
        let original_length = fs::metadata(&path).unwrap().len();
        let mut incompatible = transaction(1);
        incompatible.suite = different_valid_suite();

        assert!(matches!(
            ledger.apply(&incompatible, &TestVerifier, &DenyAllMints),
            Err(PersistentLedgerError::TransactionCryptoSuiteMismatch {
                expected,
                actual,
            }) if expected == CryptoSuite::RESEARCH_V1 && actual == different_valid_suite()
        ));
        assert_eq!(ledger.status().sequence, 0);
        assert_eq!(fs::metadata(&path).unwrap().len(), original_length);
    }

    #[test]
    fn recovery_refuses_a_durable_record_from_a_different_valid_suite() {
        let directory = TestDirectory::new();
        let path = directory.log_path();
        let initial_state = genesis();
        let anchor = test_anchor(&initial_state);
        let mut incompatible = transaction(1);
        incompatible.suite = different_valid_suite();
        let record = TransactionRecord::new(
            1,
            initial_state.state_id(anchor.genesis_id),
            encode_transaction(&incompatible).unwrap(),
            StateId::new([99; 32]),
        )
        .unwrap();
        let mut log = StateRecordLog::open_for_recovery(&path).unwrap();
        log.append_record(&record).unwrap();
        drop(log);

        assert!(matches!(
            PersistentLedger::open(
                &path,
                initial_state,
                anchor,
                test_validation_context(),
                &TestVerifier,
                &DenyAllMints
            ),
            Err(PersistentLedgerError::TransactionCryptoSuiteMismatch {
                expected,
                actual,
            }) if expected == CryptoSuite::RESEARCH_V1 && actual == different_valid_suite()
        ));
    }

    #[test]
    fn publishes_a_checkpoint_only_after_a_durable_record_and_verifies_it_on_reopen() {
        let directory = TestDirectory::new();
        let path = directory.log_path();
        let checkpoint_directory = directory.checkpoint_directory();
        let expected_snapshot;
        {
            let mut ledger = open_persistent(&path).unwrap();
            ledger
                .apply(&transaction(1), &TestVerifier, &DenyAllMints)
                .unwrap();
            ledger
                .apply(&transaction_with(2, 5, 6), &TestVerifier, &DenyAllMints)
                .unwrap();
            expected_snapshot = ledger.state().snapshot();
            let published = ledger
                .publish_checkpoint(checkpoint_directory.clone())
                .unwrap();
            assert_eq!(published.checkpoint.sequence(), 2);
            assert!(published.path.is_file());
        }

        let reopened = open_persistent_with_checkpoints(&path, checkpoint_directory).unwrap();
        assert_eq!(reopened.status().sequence, 2);
        assert_eq!(reopened.status().recovered_checkpoint_sequence, Some(2));
        assert_eq!(reopened.state().snapshot(), expected_snapshot);
    }

    #[test]
    fn checkpoint_at_genesis_is_refused_without_creating_artifacts() {
        let directory = TestDirectory::new();
        let checkpoint_directory = directory.checkpoint_directory();
        let mut ledger = open_persistent(&directory.log_path()).unwrap();
        assert!(matches!(
            ledger.publish_checkpoint(checkpoint_directory.clone()),
            Err(PersistentLedgerError::CheckpointAtGenesis)
        ));
        assert!(!checkpoint_directory.exists());
    }

    #[test]
    fn corrupted_checkpoint_is_ignored_but_a_complete_log_is_still_replayed() {
        let directory = TestDirectory::new();
        let path = directory.log_path();
        let checkpoint_directory = directory.checkpoint_directory();
        let expected_state_id;
        {
            let mut ledger = open_persistent(&path).unwrap();
            ledger
                .apply(&transaction(1), &TestVerifier, &DenyAllMints)
                .unwrap();
            expected_state_id = ledger.status().state_id;
            let published = ledger
                .publish_checkpoint(checkpoint_directory.clone())
                .unwrap();
            let mut bytes = fs::read(&published.path).unwrap();
            bytes[0] ^= 1;
            fs::write(&published.path, bytes).unwrap();
        }

        let reopened = open_persistent_with_checkpoints(&path, checkpoint_directory).unwrap();
        assert_eq!(reopened.status().state_id, expected_state_id);
        assert_eq!(reopened.status().recovered_checkpoint_sequence, None);
    }

    #[test]
    fn appends_durable_frames_and_recovers_them_in_order() {
        let directory = TestDirectory::new();
        let path = directory.log_path();
        let first = transaction(1);
        let second = transaction(2);

        let first_offset;
        {
            let mut log = TransactionLog::open(&path).unwrap();
            first_offset = log
                .append_transaction_bytes(&encode_transaction(&first).unwrap())
                .unwrap();
            let second_offset = log
                .append_transaction_bytes(&encode_transaction(&second).unwrap())
                .unwrap();
            assert_eq!(first_offset, 0);
            assert!(second_offset > first_offset);
        }

        let mut reopened = TransactionLog::open(&path).unwrap();
        let entries = reopened.read_transactions().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].offset, first_offset);
        assert_eq!(decode_transaction(&entries[0].bytes).unwrap(), first);
        assert_eq!(decode_transaction(&entries[1].bytes).unwrap(), second);
    }

    #[test]
    fn refuses_corrupted_payload_when_recovering() {
        let directory = TestDirectory::new();
        let path = directory.log_path();
        {
            let mut log = TransactionLog::open(&path).unwrap();
            log.append_transaction_bytes(&encode_transaction(&transaction(1)).unwrap())
                .unwrap();
        }

        let mut bytes = fs::read(&path).unwrap();
        bytes[FRAME_HEADER_LENGTH] ^= 0x80;
        fs::write(&path, bytes).unwrap();

        assert!(matches!(
            TransactionLog::open(&path),
            Err(StorageError::ChecksumMismatch { offset: 0, .. })
        ));
    }

    #[test]
    fn refuses_truncated_frame_when_recovering() {
        let directory = TestDirectory::new();
        let path = directory.log_path();
        {
            let mut log = TransactionLog::open(&path).unwrap();
            log.append_transaction_bytes(&encode_transaction(&transaction(1)).unwrap())
                .unwrap();
        }

        let mut bytes = fs::read(&path).unwrap();
        bytes.pop();
        fs::write(&path, bytes).unwrap();

        assert!(matches!(
            TransactionLog::open(&path),
            Err(StorageError::TruncatedFrame {
                offset: 0,
                section: "frame checksum"
            })
        ));
    }

    #[test]
    fn rejects_a_valid_checksum_wrapping_noncanonical_transaction_bytes() {
        let directory = TestDirectory::new();
        let path = directory.log_path();
        let invalid_payload = vec![0_u8; 3];
        fs::write(&path, encode_frame(&invalid_payload).unwrap()).unwrap();

        assert!(matches!(
            TransactionLog::open(&path),
            Err(StorageError::InvalidTransaction { offset: 0, .. })
        ));
    }

    #[test]
    fn rejects_unknown_frame_version_before_payload_allocation() {
        let directory = TestDirectory::new();
        let path = directory.log_path();
        let mut frame = encode_frame(&encode_transaction(&transaction(1)).unwrap()).unwrap();
        frame[4..6].copy_from_slice(&2_u16.to_be_bytes());
        fs::write(&path, frame).unwrap();

        assert!(matches!(
            TransactionLog::open(&path),
            Err(StorageError::UnsupportedFrameVersion {
                offset: 0,
                version: 2
            })
        ));
    }

    #[test]
    fn crc32_matches_the_standard_test_vector() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn persistent_ledger_replays_state_and_keeps_nullifiers_spent_after_restart() {
        let directory = TestDirectory::new();
        let path = directory.log_path();
        let accepted = transaction(1);
        let expected_root;
        {
            let mut ledger = open_persistent(&path).unwrap();
            ledger
                .apply(&accepted, &TestVerifier, &DenyAllMints)
                .unwrap();
            expected_root = ledger.state().merkle_root();
            assert_eq!(ledger.status().sequence, 1);
            assert!(ledger.state().is_spent(Nullifier::new([3; 32])));
        }

        let reopened = open_persistent(&path).unwrap();
        assert_eq!(reopened.state().merkle_root(), expected_root);
        assert_eq!(reopened.status().sequence, 1);
        assert!(reopened.state().is_spent(Nullifier::new([3; 32])));

        let mut reopened = reopened;
        let double_spend = transaction(2);
        assert!(matches!(
            reopened.apply(&double_spend, &TestVerifier, &DenyAllMints),
            Err(PersistentLedgerError::Ledger(
                LedgerError::NullifierAlreadySpent(_)
            ))
        ));
    }

    #[test]
    fn persistent_ledger_rejects_a_state_record_with_a_forged_result_identity() {
        let directory = TestDirectory::new();
        let path = directory.log_path();
        let initial_state = genesis();
        let anchor = test_anchor(&initial_state);
        let forged_record = TransactionRecord::new(
            1,
            initial_state.state_id(anchor.genesis_id),
            encode_transaction(&transaction(1)).unwrap(),
            StateId::new([99; 32]),
        )
        .unwrap();
        let mut log = StateRecordLog::open_for_recovery(&path).unwrap();
        log.append_record(&forged_record).unwrap();
        drop(log);

        assert!(matches!(
            PersistentLedger::open(
                &path,
                initial_state,
                anchor,
                test_validation_context(),
                &TestVerifier,
                &DenyAllMints
            ),
            Err(PersistentLedgerError::ResultingStateIdMismatch { .. })
        ));
    }

    #[test]
    fn persistent_ledger_rejects_a_noncontiguous_state_record_sequence() {
        let directory = TestDirectory::new();
        let path = directory.log_path();
        let initial_state = genesis();
        let anchor = test_anchor(&initial_state);
        let invalid_sequence = TransactionRecord::new(
            2,
            initial_state.state_id(anchor.genesis_id),
            encode_transaction(&transaction(1)).unwrap(),
            StateId::new([99; 32]),
        )
        .unwrap();
        let mut log = StateRecordLog::open_for_recovery(&path).unwrap();
        log.append_record(&invalid_sequence).unwrap();
        drop(log);

        assert!(matches!(
            PersistentLedger::open(
                &path,
                initial_state,
                anchor,
                test_validation_context(),
                &TestVerifier,
                &DenyAllMints
            ),
            Err(PersistentLedgerError::RecordChain(
                RecordError::UnexpectedSequence {
                    expected: 1,
                    actual: 2
                }
            ))
        ));
    }

    #[test]
    fn persistent_ledger_refuses_automatic_upgrade_of_a_legacy_transaction_log() {
        let directory = TestDirectory::new();
        let path = directory.log_path();
        let mut legacy_log = TransactionLog::open(&path).unwrap();
        legacy_log
            .append_transaction_bytes(&encode_transaction(&transaction(1)).unwrap())
            .unwrap();
        drop(legacy_log);

        assert!(matches!(
            open_persistent(&path),
            Err(PersistentLedgerError::RecordLog(
                RecordLogError::LegacyTransactionLog { offset: 0 }
            ))
        ));
    }

    #[test]
    fn persistent_ledger_refuses_a_record_history_from_another_genesis() {
        let directory = TestDirectory::new();
        let path = directory.log_path();
        {
            let mut ledger = open_persistent(&path).unwrap();
            ledger
                .apply(&transaction(1), &TestVerifier, &DenyAllMints)
                .unwrap();
        }
        let original_length = fs::metadata(&path).unwrap().len();
        let initial_state = genesis();
        let other_genesis_id = GenesisId::new([72; 32]);
        let other_anchor = ChainAnchor::new(
            other_genesis_id,
            test_validation_context().id(),
            ProofVerifierId::new([1; 32]),
            MintPolicyId::new([0; 32]),
            initial_state.state_id(other_genesis_id),
        );

        assert!(matches!(
            PersistentLedger::open(
                &path,
                initial_state,
                other_anchor,
                test_validation_context(),
                &TestVerifier,
                &DenyAllMints
            ),
            Err(PersistentLedgerError::RecordChain(
                RecordError::PreviousStateMismatch { .. }
            ))
        ));
        assert_eq!(fs::metadata(&path).unwrap().len(), original_length);
    }

    #[test]
    fn invalid_chain_anchor_is_rejected_before_a_log_is_opened() {
        let directory = TestDirectory::new();
        let path = directory.log_path();
        let initial_state = genesis();
        let invalid_anchor = ChainAnchor::new(
            GenesisId::new([80; 32]),
            test_validation_context().id(),
            ProofVerifierId::new([1; 32]),
            MintPolicyId::new([0; 32]),
            StateId::new([0; 32]),
        );

        assert!(matches!(
            PersistentLedger::open(
                &path,
                initial_state,
                invalid_anchor,
                test_validation_context(),
                &TestVerifier,
                &DenyAllMints
            ),
            Err(PersistentLedgerError::InvalidChainAnchor { .. })
        ));
        assert!(!path.exists());
    }

    #[test]
    fn recovery_truncates_only_a_verified_incomplete_final_state_record() {
        let directory = TestDirectory::new();
        let source_path = directory.0.join("source.nxrf");
        let first = transaction_with(1, 3, 4);
        let second = transaction_with(2, 5, 6);
        let first_frame_length;
        let expected_first_state_id;
        {
            let mut ledger = open_persistent(&source_path).unwrap();
            ledger.apply(&first, &TestVerifier, &DenyAllMints).unwrap();
            first_frame_length = fs::metadata(&source_path).unwrap().len() as usize;
            expected_first_state_id = ledger.status().state_id;
            ledger.apply(&second, &TestVerifier, &DenyAllMints).unwrap();
        }
        let complete_history = fs::read(&source_path).unwrap();

        for cut in (first_frame_length + 1)..complete_history.len() {
            let path = directory.0.join(format!("partial-state-record-{cut}.nxrf"));
            fs::write(&path, &complete_history[..cut]).unwrap();
            let recovered = open_persistent(&path).unwrap();
            assert_eq!(recovered.status().sequence, 1, "cut at {cut}");
            assert_eq!(
                recovered.status().state_id,
                expected_first_state_id,
                "cut at {cut}"
            );
            drop(recovered);
            assert_eq!(
                fs::metadata(&path).unwrap().len() as usize,
                first_frame_length,
                "cut at {cut}"
            );
        }
    }

    #[test]
    fn recovery_never_truncates_a_tail_before_replaying_its_complete_prefix() {
        let directory = TestDirectory::new();
        let path = directory.log_path();
        let initial_state = genesis();
        let anchor = test_anchor(&initial_state);
        let forged_record = TransactionRecord::new(
            1,
            initial_state.state_id(anchor.genesis_id),
            encode_transaction(&transaction(1)).unwrap(),
            StateId::new([99; 32]),
        )
        .unwrap();
        let mut log = StateRecordLog::open_for_recovery(&path).unwrap();
        log.append_record(&forged_record).unwrap();
        drop(log);
        {
            let mut file = OpenOptions::new().append(true).open(&path).unwrap();
            file.write_all(b"NX").unwrap();
            file.sync_all().unwrap();
        }
        let original_length = fs::metadata(&path).unwrap().len();

        assert!(matches!(
            PersistentLedger::open(
                &path,
                initial_state,
                anchor,
                test_validation_context(),
                &TestVerifier,
                &DenyAllMints
            ),
            Err(PersistentLedgerError::ResultingStateIdMismatch { .. })
        ));
        assert_eq!(fs::metadata(&path).unwrap().len(), original_length);
    }

    #[test]
    fn recovery_removes_only_a_plausible_incomplete_final_frame() {
        let directory = TestDirectory::new();
        let path = directory.log_path();
        {
            let mut log = TransactionLog::open(&path).unwrap();
            log.append_transaction_bytes(&encode_transaction(&transaction(1)).unwrap())
                .unwrap();
        }
        {
            use std::io::Write as _;
            let mut file = OpenOptions::new().append(true).open(&path).unwrap();
            file.write_all(b"NX").unwrap();
            file.sync_all().unwrap();
        }

        let mut recovered = TransactionLog::open_recovering_incomplete_tail(&path).unwrap();
        assert_eq!(recovered.read_transactions().unwrap().len(), 1);
        drop(recovered);
        assert!(TransactionLog::open(&path).is_ok());
    }

    #[test]
    fn recovery_refuses_invalid_tail_bytes() {
        let directory = TestDirectory::new();
        let path = directory.log_path();
        fs::write(&path, b"BAD").unwrap();
        assert!(matches!(
            TransactionLog::open_recovering_incomplete_tail(&path),
            Err(StorageError::InvalidMagic { offset: 0 })
        ));
    }

    #[test]
    fn recovery_handles_every_interruption_point_of_a_final_frame() {
        let directory = TestDirectory::new();
        let original_path = directory.0.join("original.nxlg");
        {
            let mut log = TransactionLog::open(&original_path).unwrap();
            log.append_transaction_bytes(&encode_transaction(&transaction(1)).unwrap())
                .unwrap();
            log.append_transaction_bytes(&encode_transaction(&transaction(2)).unwrap())
                .unwrap();
        }
        let original = fs::read(&original_path).unwrap();
        let first_frame_length = encode_frame(&encode_transaction(&transaction(1)).unwrap())
            .unwrap()
            .len();

        for cut in (first_frame_length + 1)..original.len() {
            let path = directory.0.join(format!("interruption-{cut}.nxlg"));
            fs::write(&path, &original[..cut]).unwrap();
            let mut recovered = TransactionLog::open_recovering_incomplete_tail(&path).unwrap();
            assert_eq!(
                recovered.read_transactions().unwrap().len(),
                1,
                "cut at {cut}"
            );
            recovered
                .append_transaction_bytes(&encode_transaction(&transaction(3)).unwrap())
                .unwrap();
            drop(recovered);
            let mut strict = TransactionLog::open(&path).unwrap();
            assert_eq!(strict.read_transactions().unwrap().len(), 2, "cut at {cut}");
        }
    }
}
