//! Crash-aware lifecycle for opaque synthetic `NXKP` generations.
//!
//! The store is borrowed from the already-locked public-header store. Payload
//! generations are immutable files, so publication never needs an unsafe
//! overwrite or platform-specific replacement primitive. Release builds only
//! write opaque ciphertext bytes that were already parsed; they never receive
//! plaintext or a password.

use std::{
    fmt,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use crate::{
    CandidateKeystoreHeaderStore, CandidateKeystorePayloadV1, ExternalRollbackAnchorMismatch,
    ExternalRollbackAnchorV1, HeaderStoreError, KEYSTORE_PAYLOAD_V1_LENGTH,
    KeystorePayloadBindingError, KeystorePayloadError,
};

const PAYLOAD_FILE_PREFIX: &str = "payload-";
const PAYLOAD_FILE_SUFFIX: &str = ".nxkp";
const TEMPORARY_PAYLOAD_FILE_PREFIX: &str = ".payload-";
const TEMPORARY_PAYLOAD_FILE_SUFFIX: &str = ".nxkp.tmp";
/// Bound on retained immutable synthetic payload generations per candidate
/// directory. Real wallet retention needs separate backup/UX review.
pub const MAX_SYNTHETIC_PAYLOAD_GENERATIONS: usize = 32;

/// Lifecycle view for opaque synthetic payload generations. It borrows the
/// header store, and therefore cannot outlive that store's exclusive lock.
#[derive(Debug)]
pub struct CandidateKeystorePayloadStore<'a> {
    header_store: &'a CandidateKeystoreHeaderStore,
}

/// Outcome of publishing one immutable synthetic payload generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadStorePublishOutcome {
    Published,
    AlreadyPublished,
}

/// Fail-closed errors for the synthetic-payload file lifecycle. None includes
/// a password, plaintext or wallet secret.
#[derive(Debug)]
pub enum PayloadStoreError {
    HeaderStore {
        source: HeaderStoreError,
    },
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    PayloadFileTooLarge {
        path: PathBuf,
        actual: u64,
    },
    InvalidPayloadFile {
        path: PathBuf,
        source: KeystorePayloadError,
    },
    PayloadHeaderBinding {
        path: PathBuf,
        source: KeystorePayloadBindingError,
    },
    PayloadGenerationPathMismatch {
        path: PathBuf,
        expected: u64,
        actual: u64,
    },
    NonCanonicalPayloadFileName {
        path: PathBuf,
    },
    PayloadPathNotFile {
        path: PathBuf,
    },
    GenerationConflict {
        path: PathBuf,
    },
    NonMonotonicGeneration {
        highest_existing: u64,
        requested: u64,
    },
    NonceReuse {
        existing_generation: u64,
        requested_generation: u64,
    },
    TooManyGenerations {
        maximum: usize,
    },
    TemporaryPayloadConflict {
        temporary: PathBuf,
        destination: PathBuf,
    },
    ExternalAnchorMismatch {
        source: ExternalRollbackAnchorMismatch,
    },
}

impl fmt::Display for PayloadStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderStore { source } => write!(formatter, "keystore header: {source}"),
            Self::Io {
                operation,
                path,
                source,
            } => write!(formatter, "{operation} {}: {source}", path.display()),
            Self::PayloadFileTooLarge { path, actual } => write!(
                formatter,
                "candidate keystore payload {} is {actual} bytes, above the {}-byte limit",
                path.display(),
                KEYSTORE_PAYLOAD_V1_LENGTH
            ),
            Self::InvalidPayloadFile { path, source } => {
                write!(
                    formatter,
                    "invalid candidate keystore payload {}: {source}",
                    path.display()
                )
            }
            Self::PayloadHeaderBinding { path, source } => write!(
                formatter,
                "candidate keystore payload {} does not bind to its header: {source}",
                path.display()
            ),
            Self::PayloadGenerationPathMismatch {
                path,
                expected,
                actual,
            } => write!(
                formatter,
                "candidate keystore payload {} has generation {actual}, expected {expected}",
                path.display()
            ),
            Self::NonCanonicalPayloadFileName { path } => write!(
                formatter,
                "candidate keystore payload file name is not canonical: {}",
                path.display()
            ),
            Self::PayloadPathNotFile { path } => write!(
                formatter,
                "candidate keystore payload path is not a regular file: {}",
                path.display()
            ),
            Self::GenerationConflict { path } => write!(
                formatter,
                "candidate keystore payload generation conflicts with existing bytes: {}",
                path.display()
            ),
            Self::NonMonotonicGeneration {
                highest_existing,
                requested,
            } => write!(
                formatter,
                "candidate keystore payload generation {requested} is not above existing generation {highest_existing}"
            ),
            Self::NonceReuse {
                existing_generation,
                requested_generation,
            } => write!(
                formatter,
                "candidate keystore payload generation {requested_generation} reuses the nonce from generation {existing_generation}"
            ),
            Self::TooManyGenerations { maximum } => write!(
                formatter,
                "candidate keystore has reached its {maximum}-generation synthetic-payload limit"
            ),
            Self::TemporaryPayloadConflict {
                temporary,
                destination,
            } => write!(
                formatter,
                "candidate keystore payload temporary {} conflicts with destination {}",
                temporary.display(),
                destination.display()
            ),
            Self::ExternalAnchorMismatch { source } => {
                write!(
                    formatter,
                    "candidate keystore payload differs from external anchor: {source}"
                )
            }
        }
    }
}

impl std::error::Error for PayloadStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::HeaderStore { source } => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::InvalidPayloadFile { source, .. } => Some(source),
            Self::PayloadHeaderBinding { source, .. } => Some(source),
            Self::ExternalAnchorMismatch { source } => Some(source),
            _ => None,
        }
    }
}

impl<'a> CandidateKeystorePayloadStore<'a> {
    pub(crate) fn open(
        header_store: &'a CandidateKeystoreHeaderStore,
    ) -> Result<Self, PayloadStoreError> {
        let store = Self { header_store };
        let header = store.header()?;
        store.recover_temporary_payloads(header)?;
        Ok(store)
    }

    /// Atomically adds an immutable generation after binding it to the current
    /// public header and to an independently retained `NXKA` receipt. Existing
    /// generation files are never overwritten.
    pub fn publish(
        &self,
        payload: CandidateKeystorePayloadV1,
        external_anchor: ExternalRollbackAnchorV1,
    ) -> Result<PayloadStorePublishOutcome, PayloadStoreError> {
        let header = self.header()?;
        self.verify_payload_for_generation(
            payload,
            header,
            payload.generation(),
            &self.payload_path(payload.generation()),
        )?;
        external_anchor
            .verify(header.id(), payload.generation(), payload.ciphertext_id())
            .map_err(|source| PayloadStoreError::ExternalAnchorMismatch { source })?;

        let paths = self.payload_paths(false)?;
        let destination = self.payload_path(payload.generation());
        let mut highest_existing = 0_u64;
        for (generation, path) in &paths {
            let existing = self.load_payload_file(path, *generation)?;
            self.verify_payload_for_generation(existing, header, *generation, path)?;
            if *generation == payload.generation() {
                if existing == payload {
                    return Ok(PayloadStorePublishOutcome::AlreadyPublished);
                }
                return Err(PayloadStoreError::GenerationConflict { path: path.clone() });
            }
            if existing.uses_same_nonce_as(payload) {
                return Err(PayloadStoreError::NonceReuse {
                    existing_generation: *generation,
                    requested_generation: payload.generation(),
                });
            }
            highest_existing = highest_existing.max(*generation);
        }
        if paths.len() >= MAX_SYNTHETIC_PAYLOAD_GENERATIONS {
            return Err(PayloadStoreError::TooManyGenerations {
                maximum: MAX_SYNTHETIC_PAYLOAD_GENERATIONS,
            });
        }
        if payload.generation() <= highest_existing {
            return Err(PayloadStoreError::NonMonotonicGeneration {
                highest_existing,
                requested: payload.generation(),
            });
        }
        self.write_new_payload(&destination, payload.generation(), &payload.encode())?;
        Ok(PayloadStorePublishOutcome::Published)
    }

    /// Loads only the generation named by the externally retained receipt and
    /// requires exact header, generation and ciphertext-ID agreement. A copied
    /// older directory cannot satisfy a newer independently retained receipt.
    pub fn load_anchored(
        &self,
        external_anchor: ExternalRollbackAnchorV1,
    ) -> Result<CandidateKeystorePayloadV1, PayloadStoreError> {
        let header = self.header()?;
        let generation = external_anchor.payload_generation();
        let path = self.payload_path(generation);
        let payload = self.load_payload_file(&path, generation)?;
        self.verify_payload_for_generation(payload, header, generation, &path)?;
        external_anchor
            .verify(header.id(), payload.generation(), payload.ciphertext_id())
            .map_err(|source| PayloadStoreError::ExternalAnchorMismatch { source })?;
        Ok(payload)
    }

    fn header(&self) -> Result<crate::KeystoreHeaderV2, PayloadStoreError> {
        self.header_store
            .load()
            .map_err(|source| PayloadStoreError::HeaderStore { source })
    }

    fn recover_temporary_payloads(
        &self,
        header: crate::KeystoreHeaderV2,
    ) -> Result<(), PayloadStoreError> {
        for (generation, temporary) in self.payload_paths(true)? {
            let temporary_payload = self.load_payload_file(&temporary, generation)?;
            self.verify_payload_for_generation(temporary_payload, header, generation, &temporary)?;
            let destination = self.payload_path(generation);
            if destination.exists() {
                let existing = self.load_payload_file(&destination, generation)?;
                self.verify_payload_for_generation(existing, header, generation, &destination)?;
                if existing != temporary_payload {
                    return Err(PayloadStoreError::TemporaryPayloadConflict {
                        temporary,
                        destination,
                    });
                }
                fs::remove_file(&temporary).map_err(|source| PayloadStoreError::Io {
                    operation: "remove synchronized candidate keystore payload temporary file",
                    path: temporary,
                    source,
                })?;
            } else {
                fs::rename(&temporary, &destination).map_err(|source| PayloadStoreError::Io {
                    operation: "recover synchronized candidate keystore payload temporary file",
                    path: destination,
                    source,
                })?;
            }
        }
        Ok(())
    }

    fn payload_paths(&self, temporary: bool) -> Result<Vec<(u64, PathBuf)>, PayloadStoreError> {
        let root = self.header_store.path();
        let entries = fs::read_dir(root).map_err(|source| PayloadStoreError::Io {
            operation: "list candidate keystore payload directory",
            path: root.to_path_buf(),
            source,
        })?;
        let mut paths = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| PayloadStoreError::Io {
                operation: "read candidate keystore payload directory entry",
                path: root.to_path_buf(),
                source,
            })?;
            let path = entry.path();
            let Some(generation) = generation_from_payload_path(&path, temporary)? else {
                continue;
            };
            let file_type = entry.file_type().map_err(|source| PayloadStoreError::Io {
                operation: "inspect candidate keystore payload path type",
                path: path.clone(),
                source,
            })?;
            if !file_type.is_file() {
                return Err(PayloadStoreError::PayloadPathNotFile { path });
            }
            paths.push((generation, path));
        }
        paths.sort_by_key(|(generation, _)| *generation);
        Ok(paths)
    }

    fn payload_path(&self, generation: u64) -> PathBuf {
        self.header_store.path().join(payload_file_name(generation))
    }

    fn temporary_payload_path(&self, generation: u64) -> PathBuf {
        self.header_store
            .path()
            .join(temporary_payload_file_name(generation))
    }

    fn load_payload_file(
        &self,
        path: &Path,
        expected_generation: u64,
    ) -> Result<CandidateKeystorePayloadV1, PayloadStoreError> {
        let metadata = fs::metadata(path).map_err(|source| PayloadStoreError::Io {
            operation: "inspect candidate keystore payload file",
            path: path.to_path_buf(),
            source,
        })?;
        if metadata.len() > KEYSTORE_PAYLOAD_V1_LENGTH as u64 {
            return Err(PayloadStoreError::PayloadFileTooLarge {
                path: path.to_path_buf(),
                actual: metadata.len(),
            });
        }
        let bytes = fs::read(path).map_err(|source| PayloadStoreError::Io {
            operation: "read candidate keystore payload file",
            path: path.to_path_buf(),
            source,
        })?;
        let payload = CandidateKeystorePayloadV1::decode(&bytes).map_err(|source| {
            PayloadStoreError::InvalidPayloadFile {
                path: path.to_path_buf(),
                source,
            }
        })?;
        if payload.generation() != expected_generation {
            return Err(PayloadStoreError::PayloadGenerationPathMismatch {
                path: path.to_path_buf(),
                expected: expected_generation,
                actual: payload.generation(),
            });
        }
        Ok(payload)
    }

    fn verify_payload_for_generation(
        &self,
        payload: CandidateKeystorePayloadV1,
        header: crate::KeystoreHeaderV2,
        expected_generation: u64,
        path: &Path,
    ) -> Result<(), PayloadStoreError> {
        if payload.generation() != expected_generation {
            return Err(PayloadStoreError::PayloadGenerationPathMismatch {
                path: path.to_path_buf(),
                expected: expected_generation,
                actual: payload.generation(),
            });
        }
        payload
            .verify_header(header)
            .map_err(|source| PayloadStoreError::PayloadHeaderBinding {
                path: path.to_path_buf(),
                source,
            })
    }

    fn write_new_payload(
        &self,
        destination: &Path,
        generation: u64,
        bytes: &[u8; KEYSTORE_PAYLOAD_V1_LENGTH],
    ) -> Result<(), PayloadStoreError> {
        let temporary = self.temporary_payload_path(generation);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|source| PayloadStoreError::Io {
                operation: "create candidate keystore payload temporary file",
                path: temporary.clone(),
                source,
            })?;
        file.write_all(bytes)
            .map_err(|source| PayloadStoreError::Io {
                operation: "write candidate keystore payload temporary file",
                path: temporary.clone(),
                source,
            })?;
        file.sync_all().map_err(|source| PayloadStoreError::Io {
            operation: "synchronize candidate keystore payload temporary file",
            path: temporary.clone(),
            source,
        })?;
        drop(file);
        fs::rename(&temporary, destination).map_err(|source| PayloadStoreError::Io {
            operation: "publish candidate keystore payload file",
            path: destination.to_path_buf(),
            source,
        })
    }
}

fn generation_from_payload_path(
    path: &Path,
    temporary: bool,
) -> Result<Option<u64>, PayloadStoreError> {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return Ok(None);
    };
    let (prefix, suffix) = if temporary {
        (TEMPORARY_PAYLOAD_FILE_PREFIX, TEMPORARY_PAYLOAD_FILE_SUFFIX)
    } else {
        (PAYLOAD_FILE_PREFIX, PAYLOAD_FILE_SUFFIX)
    };
    let Some(remainder) = name.strip_prefix(prefix) else {
        return Ok(None);
    };
    let Some(generation_text) = remainder.strip_suffix(suffix) else {
        return Err(PayloadStoreError::NonCanonicalPayloadFileName {
            path: path.to_path_buf(),
        });
    };
    let generation = generation_text
        .parse::<u64>()
        .ok()
        .filter(|generation| *generation != 0)
        .ok_or_else(|| PayloadStoreError::NonCanonicalPayloadFileName {
            path: path.to_path_buf(),
        })?;
    let expected_name = if temporary {
        temporary_payload_file_name(generation)
    } else {
        payload_file_name(generation)
    };
    if name != expected_name {
        return Err(PayloadStoreError::NonCanonicalPayloadFileName {
            path: path.to_path_buf(),
        });
    }
    Ok(Some(generation))
}

fn payload_file_name(generation: u64) -> String {
    format!("{PAYLOAD_FILE_PREFIX}{generation:020}{PAYLOAD_FILE_SUFFIX}")
}

fn temporary_payload_file_name(generation: u64) -> String {
    format!("{TEMPORARY_PAYLOAD_FILE_PREFIX}{generation:020}{TEMPORARY_PAYLOAD_FILE_SUFFIX}")
}

#[cfg(test)]
mod tests {
    use std::{
        io::Write as _,
        sync::atomic::{AtomicU64, Ordering},
    };

    use crate::{
        CandidateKeystoreHeaderStore, CandidateKeystorePayloadV1, ExternalRollbackAnchorV1,
        HeaderStoreInitializeOutcome, KeystoreHeaderV2,
    };

    use super::{
        PayloadStoreError, PayloadStorePublishOutcome, payload_file_name,
        temporary_payload_file_name,
    };

    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn test_directory(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "noxis-wallet-keystore-payload-{label}-{}-{}",
            std::process::id(),
            TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn header() -> KeystoreHeaderV2 {
        KeystoreHeaderV2::with_test_entropy([7; 32], 42, [8; 16])
    }

    fn synthetic_payload(
        header: KeystoreHeaderV2,
        generation: u64,
        nonce: u8,
    ) -> CandidateKeystorePayloadV1 {
        CandidateKeystorePayloadV1::seal_synthetic_fixture(
            header,
            generation,
            [nonce; 24],
            b"correct horse battery staple",
            &[0xA5; 64],
        )
        .unwrap()
    }

    fn anchor_for(
        header: KeystoreHeaderV2,
        payload: CandidateKeystorePayloadV1,
    ) -> ExternalRollbackAnchorV1 {
        ExternalRollbackAnchorV1::new(header.id(), payload.generation(), payload.ciphertext_id())
            .unwrap()
    }

    #[test]
    fn immutable_payload_generation_publishes_and_reopens_only_with_its_anchor() {
        let root = test_directory("publish");
        let header = header();
        let payload = synthetic_payload(header, 7, 9);
        let external_anchor = anchor_for(header, payload);
        {
            let headers = CandidateKeystoreHeaderStore::open(&root).unwrap();
            assert_eq!(
                headers.initialize(header).unwrap(),
                HeaderStoreInitializeOutcome::Initialized
            );
            let payloads = headers.open_payloads().unwrap();
            assert_eq!(
                payloads.publish(payload, external_anchor).unwrap(),
                PayloadStorePublishOutcome::Published
            );
            assert_eq!(
                payloads.publish(payload, external_anchor).unwrap(),
                PayloadStorePublishOutcome::AlreadyPublished
            );
            assert_eq!(payloads.load_anchored(external_anchor).unwrap(), payload);
            let conflicting = synthetic_payload(header, 7, 10);
            assert!(matches!(
                payloads.publish(conflicting, anchor_for(header, conflicting)),
                Err(PayloadStoreError::GenerationConflict { .. })
            ));
            let non_monotonic = synthetic_payload(header, 6, 10);
            assert!(matches!(
                payloads.publish(non_monotonic, anchor_for(header, non_monotonic)),
                Err(PayloadStoreError::NonMonotonicGeneration {
                    highest_existing: 7,
                    requested: 6,
                })
            ));
            let reused_nonce = synthetic_payload(header, 8, 9);
            assert!(matches!(
                payloads.publish(reused_nonce, anchor_for(header, reused_nonce)),
                Err(PayloadStoreError::NonceReuse {
                    existing_generation: 7,
                    requested_generation: 8,
                })
            ));
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn synchronized_temporary_payload_is_recovered_after_reopen() {
        let root = test_directory("recovery");
        let header = header();
        let payload = synthetic_payload(header, 7, 9);
        let external_anchor = anchor_for(header, payload);
        {
            let headers = CandidateKeystoreHeaderStore::open(&root).unwrap();
            headers.initialize(header).unwrap();
            let temporary = headers.path().join(temporary_payload_file_name(7));
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .unwrap();
            file.write_all(&payload.encode()).unwrap();
            file.sync_all().unwrap();
        }
        let headers = CandidateKeystoreHeaderStore::open(&root).unwrap();
        let payloads = headers.open_payloads().unwrap();
        assert_eq!(payloads.load_anchored(external_anchor).unwrap(), payload);
        assert!(!headers.path().join(temporary_payload_file_name(7)).exists());
        assert!(headers.path().join(payload_file_name(7)).exists());
        drop(headers);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn external_anchor_rejects_a_restored_old_generation_or_substituted_path() {
        let root = test_directory("rollback");
        let header = header();
        let first = synthetic_payload(header, 7, 9);
        let second = synthetic_payload(header, 8, 10);
        let first_anchor = anchor_for(header, first);
        let second_anchor = anchor_for(header, second);
        let headers = CandidateKeystoreHeaderStore::open(&root).unwrap();
        headers.initialize(header).unwrap();
        let payloads = headers.open_payloads().unwrap();
        payloads.publish(first, first_anchor).unwrap();
        payloads.publish(second, second_anchor).unwrap();
        assert_eq!(payloads.load_anchored(second_anchor).unwrap(), second);

        let old_path = headers.path().join(payload_file_name(7));
        let current_path = headers.path().join(payload_file_name(8));
        std::fs::remove_file(&current_path).unwrap();
        std::fs::copy(old_path, &current_path).unwrap();
        assert!(matches!(
            payloads.load_anchored(second_anchor),
            Err(PayloadStoreError::PayloadGenerationPathMismatch {
                expected: 8,
                actual: 7,
                ..
            })
        ));
        drop(headers);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_temporary_payload_fails_closed_before_recovery() {
        let root = test_directory("malformed-temp");
        let header = header();
        {
            let headers = CandidateKeystoreHeaderStore::open(&root).unwrap();
            headers.initialize(header).unwrap();
            std::fs::write(
                headers.path().join(temporary_payload_file_name(7)),
                [1_u8; 8],
            )
            .unwrap();
        }
        let headers = CandidateKeystoreHeaderStore::open(&root).unwrap();
        assert!(matches!(
            headers.open_payloads(),
            Err(PayloadStoreError::InvalidPayloadFile { .. })
        ));
        drop(headers);
        std::fs::remove_dir_all(root).unwrap();
    }
}
