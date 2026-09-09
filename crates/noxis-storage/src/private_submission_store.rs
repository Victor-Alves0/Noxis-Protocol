//! Atomic local publication for the composite `NXPL v2` private journal.
//!
//! This is intentionally a new store type, not an automatic in-place upgrade
//! of [`crate::PrivateStateStoreV1`]. A caller must choose the explicit offline
//! migration policy before moving any existing v1 directory.

use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use fs2::FileExt;
use noxis_private_state::{
    CandidatePrivateLedgerError, CandidatePrivateLedgerStateV1, CandidatePrivateStateRecordError,
    CandidatePrivateTransferAdmissionReceiptV1, CandidatePrivateTransferAuthorizer,
    CandidatePrivateTransferRequestV1, PRIVATE_STATE_RECORD_MAX_BYTES,
    decode_candidate_private_ledger_state, encode_candidate_private_ledger_state,
};

use crate::{
    PrivateSubmissionJournalError, PrivateSubmissionJournalV2, PrivateSubmissionMetadataV1,
    StoredPrivateSubmissionV2,
};

const TEMPORARY_EXTENSION: &str = "tmp";
const LOCK_EXTENSION: &str = "lock";
const JOURNAL_EXTENSION: &str = "nxpl";
const BASE_EXTENSION: &str = "base";
static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Single-process v2 writer with one journal authority for state and receipt.
pub struct PrivateSubmissionStoreV2 {
    path: PathBuf,
    base_path: PathBuf,
    lock: File,
    journal: PrivateSubmissionJournalV2,
    state: CandidatePrivateLedgerStateV1,
}

impl PrivateSubmissionStoreV2 {
    /// Initializes a fresh v2 directory. Existing sidecars are never reused.
    pub fn initialize(
        path: impl Into<PathBuf>,
        state: CandidatePrivateLedgerStateV1,
    ) -> Result<Self, PrivateSubmissionStoreError> {
        let path = checked_path(path.into())?;
        ensure_parent(&path)?;
        let lock = acquire_lock(&path)?;
        if path.exists() {
            return Err(PrivateSubmissionStoreError::AlreadyInitialized(path));
        }
        let base_path = base_path(&path);
        let journal_path = journal_path(&path);
        if base_path.exists() || journal_path.exists() {
            return Err(PrivateSubmissionStoreError::UnexpectedSidecar {
                cache: path,
                base: base_path,
                journal: journal_path,
            });
        }
        publish_state(&path, &state)?;
        let journal = PrivateSubmissionJournalV2::open(&journal_path)
            .map_err(PrivateSubmissionStoreError::Journal)?;
        Ok(Self {
            path,
            base_path,
            lock,
            journal,
            state,
        })
    }

    /// Opens after validating every complete composite entry and repairing only
    /// a structurally verified final partial frame/cache publication window.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, PrivateSubmissionStoreError> {
        let path = checked_path(path.into())?;
        let lock = acquire_lock(&path)?;
        let base_path = base_path(&path);
        let journal_path = journal_path(&path);
        let mut journal = PrivateSubmissionJournalV2::open(&journal_path)
            .map_err(PrivateSubmissionStoreError::Journal)?;
        let first_scan = journal
            .scan_recoverable_tail()
            .map_err(PrivateSubmissionStoreError::Journal)?;
        let cache = if first_scan.latest().is_some() {
            read_state(&path).ok()
        } else {
            Some(read_state(&path)?)
        };
        let state = recover_authoritative_state(&mut journal, &base_path, cache.as_ref())?;
        if cache.as_ref().map(|value| value.anchor().state_id()) != Some(state.anchor().state_id())
        {
            publish_state(&path, &state)?;
        }
        Ok(Self {
            path,
            base_path,
            lock,
            journal,
            state,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn state(&self) -> &CandidatePrivateLedgerStateV1 {
        &self.state
    }

    /// Returns the complete locally durable receipt/state history after
    /// revalidating it against the immutable base.
    pub fn submissions(
        &mut self,
    ) -> Result<Vec<StoredPrivateSubmissionV2>, PrivateSubmissionStoreError> {
        let base = read_journal_base(&self.base_path)?;
        let recovered = self
            .journal
            .recover_from(&base)
            .map_err(PrivateSubmissionStoreError::Journal)?;
        if recovered.incomplete_tail.is_some() {
            return Err(PrivateSubmissionStoreError::JournalTailPresent);
        }
        Ok(recovered.entries)
    }

    /// Applies the supplied authorization to a clone, synchronizes a single
    /// composite frame, then publishes the successor cache and in-memory state.
    pub fn apply_transfer<A>(
        &mut self,
        request: &CandidatePrivateTransferRequestV1<A>,
        authorizer: &impl CandidatePrivateTransferAuthorizer<A>,
        metadata: PrivateSubmissionMetadataV1,
    ) -> Result<CandidatePrivateTransferAdmissionReceiptV1, PrivateSubmissionStoreError> {
        let predecessor = self.state.clone();
        let mut successor = predecessor.clone();
        let receipt = successor
            .apply_transfer(request, authorizer)
            .map_err(PrivateSubmissionStoreError::Ledger)?;
        self.prepare_journal_base()?;
        self.journal
            .append_submission(
                &predecessor,
                &successor,
                metadata,
                receipt.asset_id(),
                *receipt.input_nullifiers(),
                *receipt.output_commitments(),
            )
            .map_err(PrivateSubmissionStoreError::Journal)?;
        publish_state(&self.path, &successor)?;
        self.state = successor;
        Ok(receipt)
    }

    fn prepare_journal_base(&mut self) -> Result<(), PrivateSubmissionStoreError> {
        let scan = self
            .journal
            .scan_recoverable_tail()
            .map_err(PrivateSubmissionStoreError::Journal)?;
        if scan.incomplete_tail.is_some() {
            return Err(PrivateSubmissionStoreError::JournalTailPresent);
        }
        match scan.latest() {
            Some(_) => {
                let base = read_journal_base(&self.base_path)?;
                let recovered = self
                    .journal
                    .recover_from(&base)
                    .map_err(PrivateSubmissionStoreError::Journal)?;
                let latest = recovered
                    .latest()
                    .expect("nonempty submission journal remains nonempty");
                if latest.state_id() != self.state.anchor().state_id() {
                    return Err(PrivateSubmissionStoreError::JournalCacheMismatch {
                        journal: latest.state_id(),
                        cache: self.state.anchor().state_id(),
                    });
                }
            }
            None => write_or_validate_journal_base(&self.base_path, &self.state)?,
        }
        Ok(())
    }
}

impl Drop for PrivateSubmissionStoreV2 {
    fn drop(&mut self) {
        let _ = self.lock.unlock();
    }
}

fn checked_path(path: PathBuf) -> Result<PathBuf, PrivateSubmissionStoreError> {
    if path.as_os_str().is_empty() {
        Err(PrivateSubmissionStoreError::EmptyPath)
    } else {
        Ok(path)
    }
}
fn ensure_parent(path: &Path) -> Result<(), PrivateSubmissionStoreError> {
    let parent = path
        .parent()
        .ok_or_else(|| PrivateSubmissionStoreError::NoParent(path.to_path_buf()))?;
    fs::create_dir_all(parent).map_err(|source| PrivateSubmissionStoreError::Io {
        operation: "create private-submission directory",
        path: parent.to_path_buf(),
        source,
    })
}
fn acquire_lock(path: &Path) -> Result<File, PrivateSubmissionStoreError> {
    ensure_parent(path)?;
    let lock_path = path.with_extension(LOCK_EXTENSION);
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|source| PrivateSubmissionStoreError::Io {
            operation: "open private-submission writer lock",
            path: lock_path.clone(),
            source,
        })?;
    lock.try_lock_exclusive()
        .map_err(|source| PrivateSubmissionStoreError::WriterLocked {
            path: lock_path,
            source,
        })?;
    Ok(lock)
}
fn temporary_path(path: &Path) -> PathBuf {
    let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    path.with_extension(format!(
        "{}-{sequence}.{TEMPORARY_EXTENSION}",
        std::process::id()
    ))
}
fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("nxpr");
    path.with_extension(format!("{extension}.{suffix}"))
}
fn journal_path(path: &Path) -> PathBuf {
    sidecar_path(path, JOURNAL_EXTENSION)
}
fn base_path(path: &Path) -> PathBuf {
    sidecar_path(path, BASE_EXTENSION)
}
fn publish_state(
    path: &Path,
    state: &CandidatePrivateLedgerStateV1,
) -> Result<(), PrivateSubmissionStoreError> {
    let encoded = encode_candidate_private_ledger_state(state)
        .map_err(PrivateSubmissionStoreError::Record)?;
    let temporary = temporary_path(path);
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|source| PrivateSubmissionStoreError::Io {
                operation: "create temporary private-submission state",
                path: temporary.clone(),
                source,
            })?;
        file.write_all(&encoded)
            .map_err(|source| PrivateSubmissionStoreError::Io {
                operation: "write temporary private-submission state",
                path: temporary.clone(),
                source,
            })?;
        file.sync_all()
            .map_err(|source| PrivateSubmissionStoreError::Io {
                operation: "sync temporary private-submission state",
                path: temporary.clone(),
                source,
            })?;
        drop(file);
        fs::rename(&temporary, path).map_err(|source| PrivateSubmissionStoreError::Io {
            operation: "atomically publish private-submission state",
            path: path.to_path_buf(),
            source,
        })?;
        let rebuilt = read_state(path)?;
        if encode_candidate_private_ledger_state(&rebuilt)
            .map_err(PrivateSubmissionStoreError::Record)?
            != encoded
        {
            return Err(PrivateSubmissionStoreError::PublishedStateMismatch(
                path.to_path_buf(),
            ));
        }
        Ok(())
    })();
    if temporary.exists() {
        fs::remove_file(&temporary).map_err(|source| PrivateSubmissionStoreError::Io {
            operation: "remove temporary private-submission state",
            path: temporary,
            source,
        })?;
    }
    result
}
fn write_or_validate_journal_base(
    path: &Path,
    state: &CandidatePrivateLedgerStateV1,
) -> Result<(), PrivateSubmissionStoreError> {
    if path.exists() {
        let base = read_state(path)?;
        if base.anchor().state_id() != state.anchor().state_id() {
            return Err(PrivateSubmissionStoreError::JournalBaseMismatch {
                base: base.anchor().state_id(),
                cache: state.anchor().state_id(),
            });
        }
        Ok(())
    } else {
        publish_state(path, state)
    }
}
fn read_journal_base(
    path: &Path,
) -> Result<CandidatePrivateLedgerStateV1, PrivateSubmissionStoreError> {
    if !path.exists() {
        return Err(PrivateSubmissionStoreError::MissingJournalBase(
            path.to_path_buf(),
        ));
    }
    read_state(path)
}
fn recover_authoritative_state(
    journal: &mut PrivateSubmissionJournalV2,
    base_path: &Path,
    cache: Option<&CandidatePrivateLedgerStateV1>,
) -> Result<CandidatePrivateLedgerStateV1, PrivateSubmissionStoreError> {
    let scan = journal
        .scan_recoverable_tail()
        .map_err(PrivateSubmissionStoreError::Journal)?;
    match scan.latest() {
        Some(_) => {
            let base = read_journal_base(base_path)?;
            let recovered = journal
                .recover_from(&base)
                .map_err(PrivateSubmissionStoreError::Journal)?;
            let state = recovered
                .latest()
                .expect("nonempty submission journal remains nonempty")
                .state
                .clone();
            if let Some(tail) = recovered.incomplete_tail {
                journal
                    .truncate_verified_incomplete_tail(tail)
                    .map_err(PrivateSubmissionStoreError::Journal)?;
            }
            Ok(state)
        }
        None => {
            let cache = cache.expect("empty submission journal requires a valid cache");
            if scan.incomplete_tail.is_some() && !base_path.exists() {
                return Err(PrivateSubmissionStoreError::MissingJournalBase(
                    base_path.to_path_buf(),
                ));
            }
            if base_path.exists() {
                let base = read_journal_base(base_path)?;
                if base.anchor().state_id() != cache.anchor().state_id() {
                    return Err(PrivateSubmissionStoreError::JournalBaseMismatch {
                        base: base.anchor().state_id(),
                        cache: cache.anchor().state_id(),
                    });
                }
            }
            if let Some(tail) = scan.incomplete_tail {
                journal
                    .truncate_verified_incomplete_tail(tail)
                    .map_err(PrivateSubmissionStoreError::Journal)?;
            }
            Ok(cache.clone())
        }
    }
}
fn read_state(path: &Path) -> Result<CandidatePrivateLedgerStateV1, PrivateSubmissionStoreError> {
    let metadata = fs::metadata(path).map_err(|source| PrivateSubmissionStoreError::Io {
        operation: "inspect private-submission state",
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.len() > PRIVATE_STATE_RECORD_MAX_BYTES as u64 {
        return Err(PrivateSubmissionStoreError::Oversized {
            path: path.to_path_buf(),
            length: metadata.len(),
        });
    }
    let bytes = fs::read(path).map_err(|source| PrivateSubmissionStoreError::Io {
        operation: "read private-submission state",
        path: path.to_path_buf(),
        source,
    })?;
    decode_candidate_private_ledger_state(&bytes).map_err(|source| {
        PrivateSubmissionStoreError::InvalidRecord {
            path: path.to_path_buf(),
            source,
        }
    })
}

/// Fail-closed errors for the composite v2 store.
#[derive(Debug)]
pub enum PrivateSubmissionStoreError {
    EmptyPath,
    NoParent(PathBuf),
    AlreadyInitialized(PathBuf),
    UnexpectedSidecar {
        cache: PathBuf,
        base: PathBuf,
        journal: PathBuf,
    },
    PublishedStateMismatch(PathBuf),
    MissingJournalBase(PathBuf),
    JournalBaseMismatch {
        base: noxis_types::StateId,
        cache: noxis_types::StateId,
    },
    JournalCacheMismatch {
        journal: noxis_types::StateId,
        cache: noxis_types::StateId,
    },
    JournalTailPresent,
    WriterLocked {
        path: PathBuf,
        source: io::Error,
    },
    Oversized {
        path: PathBuf,
        length: u64,
    },
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    Record(CandidatePrivateStateRecordError),
    Journal(PrivateSubmissionJournalError),
    InvalidRecord {
        path: PathBuf,
        source: CandidatePrivateStateRecordError,
    },
    Ledger(CandidatePrivateLedgerError),
}
impl fmt::Display for PrivateSubmissionStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "candidate private-submission store error: {self:?}"
        )
    }
}
impl std::error::Error for PrivateSubmissionStoreError {}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
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
    };

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
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
            .join(format!("noxis-private-submission-store-{nonce}-{sequence}"))
            .join("state.nxpr")
    }
    fn state() -> CandidatePrivateLedgerStateV1 {
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        let snapshot = CandidatePrivateStateSnapshotV1::new(
            vec![commitment(1), commitment(2)],
            vec![],
            &reference,
        )
        .unwrap();
        let tree = NullifierSparseTreeStateV1::new_candidate().unwrap();
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
            tree,
        )
        .unwrap();
        state
            .register_asset(AssetDefinition::new(ASSET, "NOX", AssetKind::Synthetic).unwrap())
            .unwrap();
        state
    }
    fn intent(state: &CandidatePrivateLedgerStateV1) -> PrivateTransferIntentV2 {
        PrivateTransferIntentV2::new(
            CircuitId::new([4; 32]),
            state.anchor().genesis_id(),
            state.anchor().validation_context_id(),
            state.anchor().state_id(),
            state.anchor().note_tree_parameters(),
            state.anchor().note_root(),
            ASSET,
            [nullifier(10), nullifier(11)],
            [
                PrivateTransferOutputV2::new(
                    commitment(12),
                    CiphertextDigestV2::from_elements([20; 16]).unwrap(),
                ),
                PrivateTransferOutputV2::new(
                    commitment(13),
                    CiphertextDigestV2::from_elements([21; 16]).unwrap(),
                ),
            ],
        )
        .unwrap()
    }

    #[test]
    fn one_composite_frame_recovers_receipt_and_state_together() {
        let path = path();
        let metadata = PrivateSubmissionMetadataV1::new([9; 32]).unwrap();
        let receipt;
        {
            let mut store = PrivateSubmissionStoreV2::initialize(&path, state()).unwrap();
            let request = CandidatePrivateTransferRequestV1::new(intent(store.state()), ());
            receipt = store
                .apply_transfer(&request, &AcceptAll, metadata)
                .unwrap();
            let history = store.submissions().unwrap();
            assert_eq!(history.len(), 1);
            assert_eq!(history[0].metadata, metadata);
            assert_eq!(history[0].resulting_state_id, receipt.post_state_id());
            assert_eq!(history[0].input_nullifiers, *receipt.input_nullifiers());
            assert_eq!(history[0].output_commitments, *receipt.output_commitments());
        }
        let mut reopened = PrivateSubmissionStoreV2::open(&path).unwrap();
        assert_eq!(
            reopened.state().anchor().state_id(),
            receipt.post_state_id()
        );
        let history = reopened.submissions().unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].metadata.envelope_id(), [9; 32]);
        drop(reopened);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn recovery_removes_only_a_partial_final_composite_frame() {
        let path = path();
        let metadata = PrivateSubmissionMetadataV1::new([8; 32]).unwrap();
        {
            let mut store = PrivateSubmissionStoreV2::initialize(&path, state()).unwrap();
            let request = CandidatePrivateTransferRequestV1::new(intent(store.state()), ());
            store
                .apply_transfer(&request, &AcceptAll, metadata)
                .unwrap();
        }
        let journal_path = journal_path(&path);
        let complete_length = fs::metadata(&journal_path).unwrap().len();
        let mut journal_file = OpenOptions::new().append(true).open(&journal_path).unwrap();
        journal_file.write_all(b"NXP").unwrap();
        journal_file.sync_all().unwrap();
        drop(journal_file);

        let mut reopened = PrivateSubmissionStoreV2::open(&path).unwrap();
        assert_eq!(reopened.submissions().unwrap().len(), 1);
        drop(reopened);
        assert_eq!(fs::metadata(&journal_path).unwrap().len(), complete_length);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
