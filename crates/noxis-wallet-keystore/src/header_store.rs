//! Crash-aware persistence for the public `NXKS` header only.
//!
//! The store never accepts encrypted payloads or secret root bytes. It exists
//! to validate the directory lifecycle before a reviewed keystore is allowed
//! to persist a real wallet secret.

use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use crate::{
    CandidateKeystorePayloadStore, KEYSTORE_HEADER_V2_LENGTH, KeystoreHeaderError,
    KeystoreHeaderV2, PayloadStoreError,
};

/// Process-lifetime lock file for the public candidate-header directory.
pub const KEYSTORE_HEADER_LOCK_FILE_NAME: &str = ".noxis-wallet-keystore.lock";
const HEADER_FILE_NAME: &str = "wallet-header.nxks";
const TEMPORARY_HEADER_FILE_NAME: &str = ".wallet-header.nxks.tmp";
// The old experimental v1 header was 100 bytes. Keep the read cap high enough
// to let its decoder report the explicit revocation, while retaining a strict,
// tiny allocation bound for this public metadata file.
const MAX_RECOGNIZABLE_HEADER_FILE_BYTES: u64 = 100;

/// Opened directory that owns one public candidate `NXKS` header.
#[derive(Debug)]
pub struct CandidateKeystoreHeaderStore {
    root: PathBuf,
    _lock: HeaderStoreLock,
}

/// Result of initializing the immutable candidate header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderStoreInitializeOutcome {
    Initialized,
    AlreadyInitialized,
}

/// Fail-closed errors for the public-header lifecycle.
#[derive(Debug)]
pub enum HeaderStoreError {
    EmptyDirectoryPath,
    DirectoryAlreadyLocked(PathBuf),
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    HeaderFileTooLarge {
        path: PathBuf,
        actual: u64,
    },
    InvalidHeaderFile {
        path: PathBuf,
        source: KeystoreHeaderError,
    },
    HeaderConflict {
        path: PathBuf,
    },
}

impl fmt::Display for HeaderStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyDirectoryPath => {
                formatter.write_str("keystore-header path must not be empty")
            }
            Self::DirectoryAlreadyLocked(path) => write!(
                formatter,
                "candidate keystore header directory is already open: {}",
                path.display()
            ),
            Self::Io {
                operation,
                path,
                source,
            } => write!(formatter, "{operation} {}: {source}", path.display()),
            Self::HeaderFileTooLarge { path, actual } => write!(
                formatter,
                "candidate keystore header {} is {actual} bytes, above the {}-byte limit",
                path.display(),
                MAX_RECOGNIZABLE_HEADER_FILE_BYTES
            ),
            Self::InvalidHeaderFile { path, source } => {
                write!(
                    formatter,
                    "invalid candidate keystore header {}: {source}",
                    path.display()
                )
            }
            Self::HeaderConflict { path } => write!(
                formatter,
                "candidate keystore header conflicts with requested initialization: {}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for HeaderStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::InvalidHeaderFile { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl CandidateKeystoreHeaderStore {
    /// Opens or creates the header directory and obtains its exclusive writer
    /// lock. A complete synchronized temporary header is published if a prior
    /// process stopped before rename; an invalid temporary file fails closed.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, HeaderStoreError> {
        let root = root.into();
        if root.as_os_str().is_empty() {
            return Err(HeaderStoreError::EmptyDirectoryPath);
        }
        fs::create_dir_all(&root).map_err(|source| HeaderStoreError::Io {
            operation: "create candidate keystore-header directory",
            path: root.clone(),
            source,
        })?;
        let lock = HeaderStoreLock::acquire(root.join(KEYSTORE_HEADER_LOCK_FILE_NAME))?;
        let store = Self { root, _lock: lock };
        store.recover_temporary_header()?;
        Ok(store)
    }

    /// Directory containing only the public header and its process lock.
    pub fn path(&self) -> &Path {
        &self.root
    }

    /// Writes one immutable public header atomically. Repeating the exact
    /// initialization is idempotent; a different header fails rather than
    /// silently replacing wallet identity or key epoch.
    pub fn initialize(
        &self,
        header: KeystoreHeaderV2,
    ) -> Result<HeaderStoreInitializeOutcome, HeaderStoreError> {
        let destination = self.header_path();
        if destination.exists() {
            if self.load()? == header {
                return Ok(HeaderStoreInitializeOutcome::AlreadyInitialized);
            }
            return Err(HeaderStoreError::HeaderConflict { path: destination });
        }
        self.write_new_header(&header.encode())?;
        Ok(HeaderStoreInitializeOutcome::Initialized)
    }

    /// Loads the bounded, canonical public header. It never opens a secret
    /// payload because none exists in this candidate store.
    pub fn load(&self) -> Result<KeystoreHeaderV2, HeaderStoreError> {
        self.load_header_file(&self.header_path())
    }

    /// Opens the separate synthetic-payload lifecycle while retaining this
    /// store's exclusive directory lock. It fails closed if a prior payload
    /// publication left a malformed or unbound temporary file behind.
    pub fn open_payloads(&self) -> Result<CandidateKeystorePayloadStore<'_>, PayloadStoreError> {
        CandidateKeystorePayloadStore::open(self)
    }

    fn header_path(&self) -> PathBuf {
        self.root.join(HEADER_FILE_NAME)
    }

    fn temporary_header_path(&self) -> PathBuf {
        self.root.join(TEMPORARY_HEADER_FILE_NAME)
    }

    fn recover_temporary_header(&self) -> Result<(), HeaderStoreError> {
        let temporary = self.temporary_header_path();
        if !temporary.exists() {
            return Ok(());
        }
        let destination = self.header_path();
        if destination.exists() {
            fs::remove_file(&temporary).map_err(|source| HeaderStoreError::Io {
                operation: "remove superseded candidate keystore-header temporary file",
                path: temporary,
                source,
            })?;
            return Ok(());
        }
        self.load_header_file(&temporary)?;
        fs::rename(&temporary, &destination).map_err(|source| HeaderStoreError::Io {
            operation: "recover synchronized candidate keystore-header temporary file",
            path: destination,
            source,
        })
    }

    fn load_header_file(&self, path: &Path) -> Result<KeystoreHeaderV2, HeaderStoreError> {
        let metadata = fs::metadata(path).map_err(|source| HeaderStoreError::Io {
            operation: "inspect candidate keystore-header file",
            path: path.to_path_buf(),
            source,
        })?;
        if metadata.len() > MAX_RECOGNIZABLE_HEADER_FILE_BYTES {
            return Err(HeaderStoreError::HeaderFileTooLarge {
                path: path.to_path_buf(),
                actual: metadata.len(),
            });
        }
        let bytes = fs::read(path).map_err(|source| HeaderStoreError::Io {
            operation: "read candidate keystore-header file",
            path: path.to_path_buf(),
            source,
        })?;
        KeystoreHeaderV2::decode(&bytes).map_err(|source| HeaderStoreError::InvalidHeaderFile {
            path: path.to_path_buf(),
            source,
        })
    }

    fn write_new_header(
        &self,
        bytes: &[u8; KEYSTORE_HEADER_V2_LENGTH],
    ) -> Result<(), HeaderStoreError> {
        let temporary = self.temporary_header_path();
        let destination = self.header_path();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|source| HeaderStoreError::Io {
                operation: "create candidate keystore-header temporary file",
                path: temporary.clone(),
                source,
            })?;
        file.write_all(bytes)
            .map_err(|source| HeaderStoreError::Io {
                operation: "write candidate keystore-header temporary file",
                path: temporary.clone(),
                source,
            })?;
        file.sync_all().map_err(|source| HeaderStoreError::Io {
            operation: "synchronize candidate keystore-header temporary file",
            path: temporary.clone(),
            source,
        })?;
        drop(file);
        fs::rename(&temporary, &destination).map_err(|source| HeaderStoreError::Io {
            operation: "publish candidate keystore-header file",
            path: destination,
            source,
        })
    }
}

#[derive(Debug)]
struct HeaderStoreLock {
    file: Option<File>,
    path: PathBuf,
}

impl HeaderStoreLock {
    fn acquire(path: PathBuf) -> Result<Self, HeaderStoreError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|source| {
                if source.kind() == io::ErrorKind::AlreadyExists {
                    HeaderStoreError::DirectoryAlreadyLocked(path.clone())
                } else {
                    HeaderStoreError::Io {
                        operation: "create candidate keystore-header lock",
                        path: path.clone(),
                        source,
                    }
                }
            })?;
        Ok(Self {
            file: Some(file),
            path,
        })
    }
}

impl Drop for HeaderStoreLock {
    fn drop(&mut self) {
        drop(self.file.take());
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::Write as _,
        sync::atomic::{AtomicU64, Ordering},
    };

    use crate::KeystoreHeaderV2;

    use super::{
        CandidateKeystoreHeaderStore, HEADER_FILE_NAME, HeaderStoreError,
        HeaderStoreInitializeOutcome, TEMPORARY_HEADER_FILE_NAME,
    };

    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn test_directory(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "noxis-wallet-keystore-header-{label}-{}-{}",
            std::process::id(),
            TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn header() -> KeystoreHeaderV2 {
        KeystoreHeaderV2::generate([7; 32], 42).unwrap()
    }

    #[test]
    fn header_survives_reopen_and_exact_initialization_is_idempotent() {
        let root = test_directory("reopen");
        let header = header();
        {
            let store = CandidateKeystoreHeaderStore::open(&root).unwrap();
            assert_eq!(
                store.initialize(header).unwrap(),
                HeaderStoreInitializeOutcome::Initialized
            );
            assert_eq!(
                store.initialize(header).unwrap(),
                HeaderStoreInitializeOutcome::AlreadyInitialized
            );
        }
        let reopened = CandidateKeystoreHeaderStore::open(&root).unwrap();
        assert_eq!(reopened.load().unwrap(), header);
        drop(reopened);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn header_store_refuses_a_second_open_writer() {
        let root = test_directory("lock");
        let first = CandidateKeystoreHeaderStore::open(&root).unwrap();
        assert!(matches!(
            CandidateKeystoreHeaderStore::open(&root),
            Err(HeaderStoreError::DirectoryAlreadyLocked(_))
        ));
        drop(first);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn synchronized_temporary_header_is_recovered_after_reopen() {
        let root = test_directory("recovery");
        let header = header();
        {
            let store = CandidateKeystoreHeaderStore::open(&root).unwrap();
            let temporary = store.path().join(TEMPORARY_HEADER_FILE_NAME);
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .unwrap();
            file.write_all(&header.encode()).unwrap();
            file.sync_all().unwrap();
        }
        let recovered = CandidateKeystoreHeaderStore::open(&root).unwrap();
        assert_eq!(recovered.load().unwrap(), header);
        assert!(!recovered.path().join(TEMPORARY_HEADER_FILE_NAME).exists());
        drop(recovered);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn truncated_temporary_header_fails_closed_on_reopen() {
        let root = test_directory("truncated-recovery");
        {
            let store = CandidateKeystoreHeaderStore::open(&root).unwrap();
            std::fs::write(store.path().join(TEMPORARY_HEADER_FILE_NAME), [1_u8; 8]).unwrap();
        }
        assert!(matches!(
            CandidateKeystoreHeaderStore::open(&root),
            Err(HeaderStoreError::InvalidHeaderFile { .. })
        ));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn revoked_v1_header_fails_with_its_explicit_revocation_error() {
        let root = test_directory("revoked-v1");
        {
            let store = CandidateKeystoreHeaderStore::open(&root).unwrap();
            let mut old_header = [0_u8; 100];
            old_header[..4].copy_from_slice(b"NXKS");
            old_header[4..6].copy_from_slice(&1_u16.to_be_bytes());
            std::fs::write(store.path().join(HEADER_FILE_NAME), old_header).unwrap();
        }
        assert!(matches!(
            CandidateKeystoreHeaderStore::open(&root).unwrap().load(),
            Err(HeaderStoreError::InvalidHeaderFile {
                source: crate::KeystoreHeaderError::RevokedVersionV1,
                ..
            })
        ));
        std::fs::remove_dir_all(root).unwrap();
    }
}
