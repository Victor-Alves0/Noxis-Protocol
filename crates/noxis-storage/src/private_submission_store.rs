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

#[cfg(test)]
use std::cell::Cell;

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

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_STATE_PUBLICATION: Cell<bool> = const { Cell::new(false) };
}

/// Single-process v2 writer with one journal authority for state and receipt.
pub struct PrivateSubmissionStoreV2 {
    path: PathBuf,
    base_path: PathBuf,
    lock: File,
    journal: PrivateSubmissionJournalV2,
    state: CandidatePrivateLedgerStateV1,
}

/// Non-secret local facts obtained only after validating the v2 journal.
///
/// This is an operator-status view, not a network query, wallet balance or
/// consensus commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateSubmissionStoreStatusV1 {
    state_id: noxis_types::StateId,
    commitment_count: usize,
    spent_nullifier_count: usize,
    durable_submission_count: usize,
}

impl PrivateSubmissionStoreStatusV1 {
    pub const fn state_id(self) -> noxis_types::StateId {
        self.state_id
    }
    pub const fn commitment_count(self) -> usize {
        self.commitment_count
    }
    pub const fn spent_nullifier_count(self) -> usize {
        self.spent_nullifier_count
    }
    pub const fn durable_submission_count(self) -> usize {
        self.durable_submission_count
    }
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

    /// Initializes a fresh v2 store and synchronizes its immutable base before
    /// returning. This is for an explicit offline migration whose first v2
    /// state has no reconstructable historic submission receipts.
    pub fn initialize_with_authenticated_base(
        path: impl Into<PathBuf>,
        state: CandidatePrivateLedgerStateV1,
    ) -> Result<Self, PrivateSubmissionStoreError> {
        let mut store = Self::initialize(path, state)?;
        store.prepare_journal_base()?;
        Ok(store)
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

    /// Revalidates local durable history before returning a compact operator
    /// view. A corrupt, incomplete or unlinked frame produces an error rather
    /// than a partial count.
    pub fn status(
        &mut self,
    ) -> Result<PrivateSubmissionStoreStatusV1, PrivateSubmissionStoreError> {
        let durable_submission_count = self.submissions()?.len();
        Ok(PrivateSubmissionStoreStatusV1 {
            state_id: self.state.anchor().state_id(),
            commitment_count: self.state.snapshot().commitments().len(),
            spent_nullifier_count: self.state.snapshot().spent_nullifiers().len(),
            durable_submission_count,
        })
    }

    /// Returns the complete locally durable receipt/state history after
    /// revalidating it against the immutable base.
    pub fn submissions(
        &mut self,
    ) -> Result<Vec<StoredPrivateSubmissionV2>, PrivateSubmissionStoreError> {
        let scan = self
            .journal
            .scan_recoverable_tail()
            .map_err(PrivateSubmissionStoreError::Journal)?;
        if scan.incomplete_tail.is_some() {
            return Err(PrivateSubmissionStoreError::JournalTailPresent);
        }
        if scan.entries.is_empty() {
            return Ok(Vec::new());
        }
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
    #[cfg(test)]
    if take_state_publication_failpoint() {
        return Err(PrivateSubmissionStoreError::Io {
            operation: "inject private-submission cache publication failure",
            path: path.to_path_buf(),
            source: io::Error::other("test-only private-submission cache failpoint"),
        });
    }
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

#[cfg(test)]
fn fail_next_state_publication() {
    FAIL_NEXT_STATE_PUBLICATION.with(|value| value.set(true));
}

#[cfg(test)]
fn take_state_publication_failpoint() -> bool {
    FAIL_NEXT_STATE_PUBLICATION.with(|value| value.replace(false))
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
        let status = reopened.status().unwrap();
        assert_eq!(status.state_id(), receipt.post_state_id());
        assert_eq!(status.commitment_count(), 4);
        assert_eq!(status.spent_nullifier_count(), 2);
        assert_eq!(status.durable_submission_count(), 1);
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

    #[test]
    fn complete_composite_frame_repairs_a_cache_never_published_after_sync() {
        let path = path();
        let metadata = PrivateSubmissionMetadataV1::new([7; 32]).unwrap();
        let expected;
        {
            let mut store = PrivateSubmissionStoreV2::initialize(&path, state()).unwrap();
            let predecessor = store.state.clone();
            let request = CandidatePrivateTransferRequestV1::new(intent(&predecessor), ());
            let mut successor = predecessor.clone();
            let receipt = successor.apply_transfer(&request, &AcceptAll).unwrap();
            expected = receipt.post_state_id();
            store.prepare_journal_base().unwrap();
            store
                .journal
                .append_submission(
                    &predecessor,
                    &successor,
                    metadata,
                    receipt.asset_id(),
                    *receipt.input_nullifiers(),
                    *receipt.output_commitments(),
                )
                .unwrap();
            // Deliberately omit cache publication: this models a crash after
            // `sync_data` of one complete composite frame.
        }

        let mut reopened = PrivateSubmissionStoreV2::open(&path).unwrap();
        assert_eq!(reopened.state().anchor().state_id(), expected);
        assert_eq!(reopened.submissions().unwrap().len(), 1);
        drop(reopened);
        assert_eq!(read_state(&path).unwrap().anchor().state_id(), expected);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn injected_cache_publication_failure_keeps_the_synced_journal_authoritative() {
        let path = path();
        let initial = state();
        let initial_id = initial.anchor().state_id();
        let expected_id;
        {
            let mut expected = initial.clone();
            let request = CandidatePrivateTransferRequestV1::new(intent(&expected), ());
            expected_id = expected
                .apply_transfer(&request, &AcceptAll)
                .unwrap()
                .post_state_id();
        }
        {
            let mut store = PrivateSubmissionStoreV2::initialize(&path, initial).unwrap();
            store.prepare_journal_base().unwrap();
            let request = CandidatePrivateTransferRequestV1::new(intent(store.state()), ());
            fail_next_state_publication();
            assert!(matches!(
                store.apply_transfer(
                    &request,
                    &AcceptAll,
                    PrivateSubmissionMetadataV1::new([4; 32]).unwrap(),
                ),
                Err(PrivateSubmissionStoreError::Io {
                    operation: "inject private-submission cache publication failure",
                    ..
                })
            ));
            assert_eq!(store.state().anchor().state_id(), initial_id);
            assert!(!fs::read(journal_path(&path)).unwrap().is_empty());
        }

        let mut reopened = PrivateSubmissionStoreV2::open(&path).unwrap();
        assert_eq!(reopened.state().anchor().state_id(), expected_id);
        assert_eq!(reopened.submissions().unwrap().len(), 1);
        drop(reopened);
        assert_eq!(read_state(&path).unwrap().anchor().state_id(), expected_id);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn incomplete_first_frame_rolls_back_to_the_authenticated_base() {
        let path = path();
        let initial = state();
        let expected = initial.anchor().state_id();
        {
            let mut store = PrivateSubmissionStoreV2::initialize(&path, initial).unwrap();
            store.prepare_journal_base().unwrap();
        }
        let journal_path = journal_path(&path);
        fs::write(&journal_path, b"NXP").unwrap();

        let mut reopened = PrivateSubmissionStoreV2::open(&path).unwrap();
        assert_eq!(reopened.state().anchor().state_id(), expected);
        assert!(reopened.submissions().unwrap().is_empty());
        drop(reopened);
        assert_eq!(fs::metadata(&journal_path).unwrap().len(), 0);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn recovery_handles_every_interruption_point_of_one_composite_frame() {
        let source_path = path();
        let target_path = source_path
            .parent()
            .unwrap()
            .join("interruption-target.nxpr");
        let initial = state();
        let expected_id;
        {
            let mut source =
                PrivateSubmissionStoreV2::initialize(&source_path, initial.clone()).unwrap();
            let request = CandidatePrivateTransferRequestV1::new(intent(source.state()), ());
            expected_id = source
                .apply_transfer(
                    &request,
                    &AcceptAll,
                    PrivateSubmissionMetadataV1::new([5; 32]).unwrap(),
                )
                .unwrap()
                .post_state_id();
        }
        let complete_frame = fs::read(journal_path(&source_path)).unwrap();
        assert!(!complete_frame.is_empty());

        {
            let mut target = PrivateSubmissionStoreV2::initialize(&target_path, initial).unwrap();
            target.prepare_journal_base().unwrap();
        }
        let target_journal_path = journal_path(&target_path);
        for interruption_at in 1..complete_frame.len() {
            fs::write(&target_journal_path, &complete_frame[..interruption_at]).unwrap();
            let mut journal = PrivateSubmissionJournalV2::open(&target_journal_path).unwrap();
            let scan = journal.scan_recoverable_tail().unwrap();
            assert!(scan.entries.is_empty());
            assert!(scan.incomplete_tail.is_some());
        }

        fs::write(&target_journal_path, &complete_frame).unwrap();
        let mut reopened = PrivateSubmissionStoreV2::open(&target_path).unwrap();
        assert_eq!(reopened.state().anchor().state_id(), expected_id);
        assert_eq!(reopened.submissions().unwrap().len(), 1);
        drop(reopened);
        assert_eq!(fs::read(&target_journal_path).unwrap(), complete_frame);
        fs::remove_dir_all(source_path.parent().unwrap()).unwrap();
    }

    #[test]
    fn complete_frame_with_a_recomputed_checksum_still_rejects_zero_envelope_id() {
        let path = path();
        let metadata = PrivateSubmissionMetadataV1::new([6; 32]).unwrap();
        {
            let mut store = PrivateSubmissionStoreV2::initialize(&path, state()).unwrap();
            let request = CandidatePrivateTransferRequestV1::new(intent(store.state()), ());
            store
                .apply_transfer(&request, &AcceptAll, metadata)
                .unwrap();
        }
        let journal_path = journal_path(&path);
        let mut bytes = fs::read(&journal_path).unwrap();
        let payload_start = crate::PRIVATE_SUBMISSION_JOURNAL_HEADER_LENGTH;
        let envelope_start = payload_start + 72;
        bytes[envelope_start..envelope_start + 32].fill(0);
        let checksum_start = bytes.len() - crate::PRIVATE_SUBMISSION_JOURNAL_CHECKSUM_LENGTH;
        let checksum = crate::crc32(&bytes[payload_start..checksum_start]).to_be_bytes();
        bytes[checksum_start..].copy_from_slice(&checksum);
        fs::write(&journal_path, bytes).unwrap();

        assert!(matches!(
            PrivateSubmissionStoreV2::open(&path),
            Err(PrivateSubmissionStoreError::Journal(
                crate::PrivateSubmissionJournalError::ZeroEnvelopeId
            ))
        ));
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn offline_v1_migration_preserves_final_state_without_fabricating_receipts() {
        let source_path = path();
        let target_path = source_path.parent().unwrap().join("migrated.nxpr");
        let source_state_id;
        {
            let mut source = crate::PrivateStateStoreV1::initialize(&source_path, state()).unwrap();
            let request = CandidatePrivateTransferRequestV1::new(intent(source.state()), ());
            source_state_id = source
                .apply_transfer(&request, &AcceptAll)
                .unwrap()
                .post_state_id();
        }
        let source_journal_path = journal_path(&source_path);
        let source_journal_before = fs::read(&source_journal_path).unwrap();

        let receipt = crate::migrate_private_state_store_v1_to_submission_store_v2(
            &source_path,
            &target_path,
        )
        .unwrap();
        assert_eq!(receipt.source_state_id(), source_state_id);
        assert_eq!(receipt.target_state_id(), source_state_id);
        assert_eq!(
            fs::read(&source_journal_path).unwrap(),
            source_journal_before
        );
        assert_eq!(
            u16::from_be_bytes(source_journal_before[4..6].try_into().unwrap()),
            1
        );

        let mut target = PrivateSubmissionStoreV2::open(&target_path).unwrap();
        assert_eq!(target.state().anchor().state_id(), source_state_id);
        assert!(target.submissions().unwrap().is_empty());
        drop(target);
        assert!(base_path(&target_path).exists());
        fs::remove_dir_all(source_path.parent().unwrap()).unwrap();
    }

    #[test]
    fn migration_refuses_an_in_place_target() {
        let source_path = path();
        let store = crate::PrivateStateStoreV1::initialize(&source_path, state()).unwrap();
        drop(store);
        assert!(matches!(
            crate::migrate_private_state_store_v1_to_submission_store_v2(
                &source_path,
                &source_path
            ),
            Err(crate::PrivateSubmissionMigrationError::SamePath(_))
        ));
        fs::remove_dir_all(source_path.parent().unwrap()).unwrap();
    }

    #[test]
    fn migration_refuses_a_partial_existing_target_without_changing_complete_source() {
        let source_path = path();
        let target_path = source_path.parent().unwrap().join("partial-target.nxpr");
        {
            let mut source = crate::PrivateStateStoreV1::initialize(&source_path, state()).unwrap();
            let request = CandidatePrivateTransferRequestV1::new(intent(source.state()), ());
            source.apply_transfer(&request, &AcceptAll).unwrap();
        }
        let source_journal_path = journal_path(&source_path);
        let source_before = fs::read(&source_journal_path).unwrap();
        // A cache-only v2 target models an interrupted target initialization.
        let target = PrivateSubmissionStoreV2::initialize(&target_path, state()).unwrap();
        let target_state_id = target.state().anchor().state_id();
        drop(target);

        assert!(matches!(
            crate::migrate_private_state_store_v1_to_submission_store_v2(
                &source_path,
                &target_path
            ),
            Err(crate::PrivateSubmissionMigrationError::Target(
                PrivateSubmissionStoreError::AlreadyInitialized(_)
            ))
        ));
        assert_eq!(fs::read(&source_journal_path).unwrap(), source_before);
        assert_eq!(
            PrivateSubmissionStoreV2::open(&target_path)
                .unwrap()
                .state()
                .anchor()
                .state_id(),
            target_state_id
        );
        fs::remove_dir_all(source_path.parent().unwrap()).unwrap();
    }

    #[test]
    fn migration_rejects_corrupt_source_before_creating_a_target() {
        let source_path = path();
        let target_path = source_path.parent().unwrap().join("unused-target.nxpr");
        {
            let mut source = crate::PrivateStateStoreV1::initialize(&source_path, state()).unwrap();
            let request = CandidatePrivateTransferRequestV1::new(intent(source.state()), ());
            source.apply_transfer(&request, &AcceptAll).unwrap();
        }
        let source_journal_path = journal_path(&source_path);
        let mut corrupt = fs::read(&source_journal_path).unwrap();
        corrupt[0] ^= 0xff;
        fs::write(&source_journal_path, &corrupt).unwrap();

        assert!(matches!(
            crate::migrate_private_state_store_v1_to_submission_store_v2(
                &source_path,
                &target_path
            ),
            Err(crate::PrivateSubmissionMigrationError::Source(
                crate::PrivateStateStoreError::Journal(
                    crate::PrivateStateJournalError::InvalidMagic { .. }
                )
            ))
        ));
        assert_eq!(fs::read(&source_journal_path).unwrap(), corrupt);
        assert!(!target_path.exists());
        assert!(!base_path(&target_path).exists());
        assert!(!journal_path(&target_path).exists());
        fs::remove_dir_all(source_path.parent().unwrap()).unwrap();
    }
}
