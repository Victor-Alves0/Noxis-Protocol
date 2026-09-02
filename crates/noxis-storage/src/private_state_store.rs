//! Atomic local publication for canonical candidate private-state records.
//!
//! This component retains an immutable `NXPR v1` base, an append-only `NXPL`
//! journal and a replaceable `NXPR v1` cache under one cooperative writer
//! lock. The journal is authoritative after its first entry: a crash after a
//! journal append but before cache publication is repaired on reopen.
//!
//! It remains candidate local storage, not a consensus database or a proof
//! replay system. `NXPL` snapshots do not contain serializable proof witnesses.

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

use crate::{PrivateStateJournalError, PrivateStateJournalV1};

const TEMPORARY_EXTENSION: &str = "tmp";
const LOCK_EXTENSION: &str = "lock";
const JOURNAL_EXTENSION: &str = "nxpl";
const BASE_EXTENSION: &str = "base";
static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A single-process writer for one candidate private-ledger snapshot path.
pub struct PrivateStateStoreV1 {
    path: PathBuf,
    base_path: PathBuf,
    lock: File,
    journal: PrivateStateJournalV1,
    state: CandidatePrivateLedgerStateV1,
}

impl PrivateStateStoreV1 {
    /// Creates a new store only when no complete state record exists at `path`.
    pub fn initialize(
        path: impl Into<PathBuf>,
        state: CandidatePrivateLedgerStateV1,
    ) -> Result<Self, PrivateStateStoreError> {
        let path = checked_path(path.into())?;
        ensure_parent(&path)?;
        let lock = acquire_lock(&path)?;
        if path.exists() {
            return Err(PrivateStateStoreError::AlreadyInitialized(path));
        }
        let base_path = base_path(&path);
        let journal_path = journal_path(&path);
        if base_path.exists() || journal_path.exists() {
            return Err(PrivateStateStoreError::UnexpectedSidecar {
                cache: path,
                base: base_path,
                journal: journal_path,
            });
        }
        publish_state(&path, &state)?;
        let journal =
            PrivateStateJournalV1::open(&journal_path).map_err(PrivateStateStoreError::Journal)?;
        Ok(Self {
            path,
            base_path,
            lock,
            journal,
            state,
        })
    }

    /// Opens an existing complete record under an exclusive cooperative lock.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, PrivateStateStoreError> {
        let path = checked_path(path.into())?;
        let lock = acquire_lock(&path)?;
        let base_path = base_path(&path);
        let journal_path = journal_path(&path);
        let mut journal =
            PrivateStateJournalV1::open(&journal_path).map_err(PrivateStateStoreError::Journal)?;
        let first_scan = journal
            .scan_recoverable_tail()
            .map_err(PrivateStateStoreError::Journal)?;
        let cache = if first_scan.latest().is_some() {
            read_state(&path).ok()
        } else {
            Some(read_state(&path)?)
        };
        let state = recover_authoritative_state(&mut journal, &base_path, cache.as_ref())?;
        if cache.as_ref().map(|cache| cache.anchor().state_id()) != Some(state.anchor().state_id())
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

    /// Validates one private transfer against a clone, synchronizes the full
    /// successor snapshot, then publishes that clone to callers.
    pub fn apply_transfer<A>(
        &mut self,
        request: &CandidatePrivateTransferRequestV1<A>,
        authorizer: &impl CandidatePrivateTransferAuthorizer<A>,
    ) -> Result<CandidatePrivateTransferAdmissionReceiptV1, PrivateStateStoreError> {
        let mut candidate = self.state.clone();
        let receipt = candidate
            .apply_transfer(request, authorizer)
            .map_err(PrivateStateStoreError::Ledger)?;
        let predecessor = self.state.anchor().state_id();
        self.prepare_journal_base()?;
        self.journal
            .append_post_state(predecessor, &candidate)
            .map_err(PrivateStateStoreError::Journal)?;
        self.publish(&candidate)?;
        self.state = candidate;
        Ok(receipt)
    }

    fn publish(
        &self,
        candidate: &CandidatePrivateLedgerStateV1,
    ) -> Result<(), PrivateStateStoreError> {
        publish_state(&self.path, candidate)
    }

    fn prepare_journal_base(&mut self) -> Result<(), PrivateStateStoreError> {
        let scan = self
            .journal
            .scan_recoverable_tail()
            .map_err(PrivateStateStoreError::Journal)?;
        if scan.incomplete_tail.is_some() {
            return Err(PrivateStateStoreError::JournalTailPresent);
        }
        match scan.latest() {
            Some(_) => {
                let base = read_journal_base(&self.base_path)?;
                let verified = self
                    .journal
                    .recover_from(base.anchor().state_id())
                    .map_err(PrivateStateStoreError::Journal)?;
                let recovered = verified
                    .latest()
                    .expect("nonempty private journal remains nonempty");
                if recovered.state_id() != self.state.anchor().state_id() {
                    return Err(PrivateStateStoreError::JournalCacheMismatch {
                        journal: recovered.state_id(),
                        cache: self.state.anchor().state_id(),
                    });
                }
            }
            None => write_or_validate_journal_base(&self.base_path, &self.state)?,
        }
        Ok(())
    }
}

impl Drop for PrivateStateStoreV1 {
    fn drop(&mut self) {
        let _ = self.lock.unlock();
    }
}

fn checked_path(path: PathBuf) -> Result<PathBuf, PrivateStateStoreError> {
    if path.as_os_str().is_empty() {
        Err(PrivateStateStoreError::EmptyPath)
    } else {
        Ok(path)
    }
}
fn ensure_parent(path: &Path) -> Result<(), PrivateStateStoreError> {
    let parent = path
        .parent()
        .ok_or_else(|| PrivateStateStoreError::NoParent(path.to_path_buf()))?;
    fs::create_dir_all(parent).map_err(|source| PrivateStateStoreError::Io {
        operation: "create private-state directory",
        path: parent.to_path_buf(),
        source,
    })
}
fn acquire_lock(path: &Path) -> Result<File, PrivateStateStoreError> {
    ensure_parent(path)?;
    let lock_path = path.with_extension(LOCK_EXTENSION);
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|source| PrivateStateStoreError::Io {
            operation: "open private-state writer lock",
            path: lock_path.clone(),
            source,
        })?;
    lock.try_lock_exclusive()
        .map_err(|source| PrivateStateStoreError::WriterLocked {
            path: lock_path,
            source,
        })?;
    Ok(lock)
}
fn temporary_path(path: &Path) -> PathBuf {
    let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    path.with_extension(format!(
        "{}-{}-{sequence}.{TEMPORARY_EXTENSION}",
        std::process::id(),
        path.extension()
            .and_then(|value| value.to_str())
            .unwrap_or("nxpr")
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
    candidate: &CandidatePrivateLedgerStateV1,
) -> Result<(), PrivateStateStoreError> {
    let encoded =
        encode_candidate_private_ledger_state(candidate).map_err(PrivateStateStoreError::Record)?;
    let temporary = temporary_path(path);
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|source| PrivateStateStoreError::Io {
                operation: "create temporary private state",
                path: temporary.clone(),
                source,
            })?;
        file.write_all(&encoded)
            .map_err(|source| PrivateStateStoreError::Io {
                operation: "write temporary private state",
                path: temporary.clone(),
                source,
            })?;
        file.sync_all()
            .map_err(|source| PrivateStateStoreError::Io {
                operation: "sync temporary private state",
                path: temporary.clone(),
                source,
            })?;
        drop(file);
        fs::rename(&temporary, path).map_err(|source| PrivateStateStoreError::Io {
            operation: "atomically publish private state",
            path: path.to_path_buf(),
            source,
        })?;
        let recovered = read_state(path)?;
        let recovered_bytes = encode_candidate_private_ledger_state(&recovered)
            .map_err(PrivateStateStoreError::Record)?;
        if recovered_bytes != encoded {
            return Err(PrivateStateStoreError::PublishedStateMismatch(
                path.to_path_buf(),
            ));
        }
        Ok(())
    })();
    if temporary.exists() {
        fs::remove_file(&temporary).map_err(|source| PrivateStateStoreError::Io {
            operation: "remove temporary private state",
            path: temporary,
            source,
        })?;
    }
    result
}
fn write_or_validate_journal_base(
    path: &Path,
    state: &CandidatePrivateLedgerStateV1,
) -> Result<(), PrivateStateStoreError> {
    if path.exists() {
        let base = read_state(path)?;
        if base.anchor().state_id() != state.anchor().state_id() {
            return Err(PrivateStateStoreError::JournalBaseMismatch {
                base: base.anchor().state_id(),
                cache: state.anchor().state_id(),
            });
        }
        return Ok(());
    }
    publish_state(path, state)
}
fn read_journal_base(path: &Path) -> Result<CandidatePrivateLedgerStateV1, PrivateStateStoreError> {
    if !path.exists() {
        return Err(PrivateStateStoreError::MissingJournalBase(
            path.to_path_buf(),
        ));
    }
    read_state(path)
}
fn recover_authoritative_state(
    journal: &mut PrivateStateJournalV1,
    base_path: &Path,
    cache: Option<&CandidatePrivateLedgerStateV1>,
) -> Result<CandidatePrivateLedgerStateV1, PrivateStateStoreError> {
    let scan = journal
        .scan_recoverable_tail()
        .map_err(PrivateStateStoreError::Journal)?;
    match scan.latest() {
        Some(_) => {
            let base = read_journal_base(base_path)?;
            let verified = journal
                .recover_from(base.anchor().state_id())
                .map_err(PrivateStateStoreError::Journal)?;
            let state = verified
                .latest()
                .expect("nonempty private journal remains nonempty")
                .state
                .clone();
            if let Some(tail) = verified.incomplete_tail {
                journal
                    .truncate_verified_incomplete_tail(tail)
                    .map_err(PrivateStateStoreError::Journal)?;
            }
            Ok(state)
        }
        None => {
            let cache = cache.expect("an empty private journal requires a valid cache");
            if scan.incomplete_tail.is_some() && !base_path.exists() {
                return Err(PrivateStateStoreError::MissingJournalBase(
                    base_path.to_path_buf(),
                ));
            }
            if base_path.exists() {
                let base = read_journal_base(base_path)?;
                if base.anchor().state_id() != cache.anchor().state_id() {
                    return Err(PrivateStateStoreError::JournalBaseMismatch {
                        base: base.anchor().state_id(),
                        cache: cache.anchor().state_id(),
                    });
                }
            }
            if let Some(tail) = scan.incomplete_tail {
                journal
                    .truncate_verified_incomplete_tail(tail)
                    .map_err(PrivateStateStoreError::Journal)?;
            }
            Ok(cache.clone())
        }
    }
}
fn read_state(path: &Path) -> Result<CandidatePrivateLedgerStateV1, PrivateStateStoreError> {
    let metadata = fs::metadata(path).map_err(|source| PrivateStateStoreError::Io {
        operation: "inspect private-state record",
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.len() > PRIVATE_STATE_RECORD_MAX_BYTES as u64 {
        return Err(PrivateStateStoreError::Oversized {
            path: path.to_path_buf(),
            length: metadata.len(),
        });
    }
    let bytes = fs::read(path).map_err(|source| PrivateStateStoreError::Io {
        operation: "read private-state record",
        path: path.to_path_buf(),
        source,
    })?;
    decode_candidate_private_ledger_state(&bytes).map_err(|source| {
        PrivateStateStoreError::InvalidRecord {
            path: path.to_path_buf(),
            source,
        }
    })
}

/// Fail-closed local storage errors for candidate private state.
#[derive(Debug)]
pub enum PrivateStateStoreError {
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
    Journal(PrivateStateJournalError),
    InvalidRecord {
        path: PathBuf,
        source: CandidatePrivateStateRecordError,
    },
    Ledger(CandidatePrivateLedgerError),
}
impl fmt::Display for PrivateStateStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "candidate private-state store error: {self:?}")
    }
}
impl std::error::Error for PrivateStateStoreError {}

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
            .join(format!("noxis-private-store-{nonce}-{sequence}"))
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
    fn transition_survives_reopen_with_all_private_effects() {
        let path = path();
        let mut store = PrivateStateStoreV1::initialize(&path, state()).unwrap();
        let request = CandidatePrivateTransferRequestV1::new(intent(store.state()), ());
        let receipt = store.apply_transfer(&request, &AcceptAll).unwrap();
        assert_eq!(store.state().snapshot().commitments().len(), 4);
        drop(store);
        let reopened = PrivateStateStoreV1::open(&path).unwrap();
        assert_eq!(
            reopened.state().anchor().state_id(),
            receipt.post_state_id()
        );
        assert_eq!(reopened.state().snapshot().commitments().len(), 4);
        assert!(reopened.state().nullifier_tree().is_spent(nullifier(10)));
        assert!(reopened.state().nullifier_tree().is_spent(nullifier(11)));
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn corrupt_record_is_not_opened() {
        let path = path();
        let store = PrivateStateStoreV1::initialize(&path, state()).unwrap();
        drop(store);
        let mut bytes = fs::read(&path).unwrap();
        bytes[10] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(matches!(
            PrivateStateStoreV1::open(&path),
            Err(PrivateStateStoreError::InvalidRecord { .. })
        ));
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn initialization_never_overwrites_an_existing_private_state() {
        let path = path();
        let store = PrivateStateStoreV1::initialize(&path, state()).unwrap();
        drop(store);
        assert!(matches!(
            PrivateStateStoreV1::initialize(&path, state()),
            Err(PrivateStateStoreError::AlreadyInitialized(_))
        ));
        let reopened = PrivateStateStoreV1::open(&path).unwrap();
        assert_eq!(reopened.state().snapshot().commitments().len(), 2);
        drop(reopened);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn incomplete_temporary_sibling_never_changes_recovery_target() {
        let path = path();
        let store = PrivateStateStoreV1::initialize(&path, state()).unwrap();
        let expected = store.state().anchor().state_id();
        drop(store);
        let temporary = temporary_path(&path);
        fs::write(&temporary, b"NXPR\x00").unwrap();
        let reopened = PrivateStateStoreV1::open(&path).unwrap();
        assert_eq!(reopened.state().anchor().state_id(), expected);
        drop(reopened);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn journal_is_authoritative_if_cache_publication_was_interrupted() {
        let path = path();
        let initial = state();
        let mut store = PrivateStateStoreV1::initialize(&path, initial).unwrap();
        let request = CandidatePrivateTransferRequestV1::new(intent(store.state()), ());
        let mut successor = store.state.clone();
        successor.apply_transfer(&request, &AcceptAll).unwrap();
        let expected = successor.anchor().state_id();
        store.prepare_journal_base().unwrap();
        store
            .journal
            .append_post_state(store.state.anchor().state_id(), &successor)
            .unwrap();
        // Deliberately omit `publish`: this is the crash window after the
        // synchronized journal append and before cache replacement.
        drop(store);

        let reopened = PrivateStateStoreV1::open(&path).unwrap();
        assert_eq!(reopened.state().anchor().state_id(), expected);
        assert_eq!(read_state(&path).unwrap().anchor().state_id(), expected);
        assert!(base_path(&path).exists());
        drop(reopened);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn journal_recovery_removes_only_a_verified_final_partial_frame() {
        let path = path();
        let mut store = PrivateStateStoreV1::initialize(&path, state()).unwrap();
        let request = CandidatePrivateTransferRequestV1::new(intent(store.state()), ());
        let receipt = store.apply_transfer(&request, &AcceptAll).unwrap();
        drop(store);
        let journal_path = journal_path(&path);
        let complete_length = fs::metadata(&journal_path).unwrap().len();
        let mut journal_file = OpenOptions::new().append(true).open(&journal_path).unwrap();
        journal_file.write_all(b"NXP").unwrap();
        journal_file.sync_all().unwrap();
        drop(journal_file);

        let reopened = PrivateStateStoreV1::open(&path).unwrap();
        assert_eq!(
            reopened.state().anchor().state_id(),
            receipt.post_state_id()
        );
        assert_eq!(fs::metadata(&journal_path).unwrap().len(), complete_length);
        drop(reopened);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn journal_with_a_wrong_immutable_base_fails_closed_on_open() {
        let path = path();
        let initial = state();
        let mut store = PrivateStateStoreV1::initialize(&path, initial).unwrap();
        store.prepare_journal_base().unwrap();
        let state = store.state().clone();
        store
            .journal
            .append_post_state(noxis_types::StateId::new([77; 32]), &state)
            .unwrap();
        drop(store);

        assert!(matches!(
            PrivateStateStoreV1::open(&path),
            Err(PrivateStateStoreError::Journal(
                PrivateStateJournalError::BaseStateMismatch { .. }
            ))
        ));
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn valid_journal_repairs_a_corrupt_replaceable_cache() {
        let path = path();
        let initial = state();
        let mut store = PrivateStateStoreV1::initialize(&path, initial).unwrap();
        store.prepare_journal_base().unwrap();
        let state = store.state().clone();
        let expected = state.anchor().state_id();
        store.journal.append_post_state(expected, &state).unwrap();
        drop(store);
        let mut bytes = fs::read(&path).unwrap();
        bytes[10] ^= 1;
        fs::write(&path, bytes).unwrap();

        let reopened = PrivateStateStoreV1::open(&path).unwrap();
        assert_eq!(reopened.state().anchor().state_id(), expected);
        assert_eq!(read_state(&path).unwrap().anchor().state_id(), expected);
        drop(reopened);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
