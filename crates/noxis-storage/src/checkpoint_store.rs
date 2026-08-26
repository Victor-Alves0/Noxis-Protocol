//! Atomic publication and candidate discovery for canonical `NXCP` files.
//!
//! This module owns filesystem mechanics only. It never decides whether a
//! candidate belongs to a particular record history; `PersistentLedger` makes
//! that decision while replaying the complete `NXRF` history.

use std::{
    fmt,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use noxis_checkpoint::{Checkpoint, CheckpointError, MAX_CHECKPOINT_BYTES};

/// Suffix of complete checkpoint files eligible for discovery.
pub const CHECKPOINT_FILE_EXTENSION: &str = "nxcp";
const TEMPORARY_FILE_EXTENSION: &str = "tmp";
const MAX_DISCOVERED_CHECKPOINTS: usize = 1_024;

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Filesystem boundary for non-authoritative checkpoint artifacts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointStore {
    directory: PathBuf,
}

/// A checkpoint known to be durably published and revalidated from disk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointReceipt {
    pub path: PathBuf,
    pub checkpoint: Checkpoint,
}

impl CheckpointStore {
    /// Creates a store handle without opening or creating any filesystem entry.
    pub fn new(directory: impl Into<PathBuf>) -> Result<Self, CheckpointStoreError> {
        let directory = directory.into();
        if directory.as_os_str().is_empty() {
            return Err(CheckpointStoreError::EmptyDirectoryPath);
        }
        Ok(Self { directory })
    }

    /// Directory in which complete checkpoints may be published.
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Publishes one complete checkpoint without overwriting an existing file.
    ///
    /// The complete file is first synchronized under a temporary name in the
    /// same directory. A hard link then atomically creates the final name only
    /// when it does not already exist; removing the temporary name completes
    /// publication. A crash may leave a `.tmp` file, which discovery ignores.
    pub fn publish(
        &self,
        checkpoint: &Checkpoint,
    ) -> Result<CheckpointReceipt, CheckpointStoreError> {
        self.ensure_directory()?;
        let encoded = checkpoint.encode();
        let final_path = self.final_path(checkpoint);
        if final_path.exists() {
            return self.verify_existing(&final_path, checkpoint);
        }

        let temporary_path = self.temporary_path();
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary_path)
                .map_err(|source| CheckpointStoreError::Io {
                    operation: "create temporary checkpoint",
                    path: temporary_path.clone(),
                    source,
                })?;
            file.write_all(&encoded)
                .map_err(|source| CheckpointStoreError::Io {
                    operation: "write temporary checkpoint",
                    path: temporary_path.clone(),
                    source,
                })?;
            file.sync_all().map_err(|source| CheckpointStoreError::Io {
                operation: "sync temporary checkpoint",
                path: temporary_path.clone(),
                source,
            })?;
            drop(file);

            match fs::hard_link(&temporary_path, &final_path) {
                Ok(()) => {}
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                    return self.verify_existing(&final_path, checkpoint);
                }
                Err(source) => {
                    return Err(CheckpointStoreError::Io {
                        operation: "publish checkpoint without overwrite",
                        path: final_path.clone(),
                        source,
                    });
                }
            }
            self.verify_existing(&final_path, checkpoint)
        })();
        let cleanup_result = fs::remove_file(&temporary_path);
        match (result, cleanup_result) {
            (Ok(receipt), Ok(())) => Ok(receipt),
            (Ok(receipt), Err(error)) if error.kind() == io::ErrorKind::NotFound => Ok(receipt),
            (Ok(_), Err(source)) => Err(CheckpointStoreError::Io {
                operation: "remove published temporary checkpoint",
                path: temporary_path,
                source,
            }),
            (Err(error), _) => Err(error),
        }
    }

    /// Finds every complete, decodable candidate in descending sequence order.
    ///
    /// A malformed, interrupted or unrelated `*.nxcp` entry is deliberately
    /// ignored: only a fully decoded checkpoint can become eligible during
    /// strict history recovery. I/O failures while inspecting entries remain
    /// fail-closed errors.
    pub fn load_candidates(&self) -> Result<Vec<CheckpointReceipt>, CheckpointStoreError> {
        match fs::read_dir(&self.directory) {
            Ok(entries) => {
                let mut candidates = Vec::new();
                for entry in entries {
                    let entry = entry.map_err(|source| CheckpointStoreError::Io {
                        operation: "read checkpoint directory entry",
                        path: self.directory.clone(),
                        source,
                    })?;
                    let path = entry.path();
                    if !is_candidate_filename(&path) {
                        continue;
                    }
                    let metadata = entry
                        .metadata()
                        .map_err(|source| CheckpointStoreError::Io {
                            operation: "inspect checkpoint candidate",
                            path: path.clone(),
                            source,
                        })?;
                    if !metadata.is_file() {
                        continue;
                    }
                    if metadata.len() > MAX_CHECKPOINT_BYTES as u64 {
                        continue;
                    }
                    let bytes = fs::read(&path).map_err(|source| CheckpointStoreError::Io {
                        operation: "read checkpoint candidate",
                        path: path.clone(),
                        source,
                    })?;
                    let Ok(checkpoint) = Checkpoint::decode(&bytes) else {
                        continue;
                    };
                    candidates.push(CheckpointReceipt { path, checkpoint });
                    if candidates.len() > MAX_DISCOVERED_CHECKPOINTS {
                        return Err(CheckpointStoreError::TooManyCandidates {
                            maximum: MAX_DISCOVERED_CHECKPOINTS,
                        });
                    }
                }
                candidates.sort_unstable_by(|left, right| {
                    right
                        .checkpoint
                        .sequence()
                        .cmp(&left.checkpoint.sequence())
                        .then_with(|| left.path.cmp(&right.path))
                });
                Ok(candidates)
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(source) => Err(CheckpointStoreError::Io {
                operation: "read checkpoint directory",
                path: self.directory.clone(),
                source,
            }),
        }
    }

    fn ensure_directory(&self) -> Result<(), CheckpointStoreError> {
        fs::create_dir_all(&self.directory).map_err(|source| CheckpointStoreError::Io {
            operation: "create checkpoint directory",
            path: self.directory.clone(),
            source,
        })?;
        let metadata =
            fs::metadata(&self.directory).map_err(|source| CheckpointStoreError::Io {
                operation: "inspect checkpoint directory",
                path: self.directory.clone(),
                source,
            })?;
        if metadata.is_dir() {
            Ok(())
        } else {
            Err(CheckpointStoreError::DirectoryIsNotDirectory(
                self.directory.clone(),
            ))
        }
    }

    fn final_path(&self, checkpoint: &Checkpoint) -> PathBuf {
        self.directory.join(format!(
            "checkpoint-{:020}-{}.{}",
            checkpoint.sequence(),
            encode_hex(&checkpoint.terminal_record_hash().as_bytes()),
            CHECKPOINT_FILE_EXTENSION,
        ))
    }

    fn temporary_path(&self) -> PathBuf {
        let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        self.directory.join(format!(
            ".checkpoint-{}-{sequence}.{TEMPORARY_FILE_EXTENSION}",
            std::process::id(),
        ))
    }

    fn verify_existing(
        &self,
        path: &Path,
        expected: &Checkpoint,
    ) -> Result<CheckpointReceipt, CheckpointStoreError> {
        let metadata = fs::metadata(path).map_err(|source| CheckpointStoreError::Io {
            operation: "inspect published checkpoint",
            path: path.to_path_buf(),
            source,
        })?;
        if metadata.len() > MAX_CHECKPOINT_BYTES as u64 {
            return Err(CheckpointStoreError::ExistingFileConflict(
                path.to_path_buf(),
            ));
        }
        let bytes = fs::read(path).map_err(|source| CheckpointStoreError::Io {
            operation: "read published checkpoint",
            path: path.to_path_buf(),
            source,
        })?;
        let checkpoint = Checkpoint::decode(&bytes).map_err(|source| {
            CheckpointStoreError::InvalidPublishedCheckpoint {
                path: path.to_path_buf(),
                source,
            }
        })?;
        if &checkpoint != expected {
            return Err(CheckpointStoreError::ExistingFileConflict(
                path.to_path_buf(),
            ));
        }
        Ok(CheckpointReceipt {
            path: path.to_path_buf(),
            checkpoint,
        })
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(value, "{byte:02x}").expect("writing to a String cannot fail");
    }
    value
}

fn is_candidate_filename(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let Some(stem) = name.strip_suffix(".nxcp") else {
        return false;
    };
    let Some((prefix, hash)) = stem.rsplit_once('-') else {
        return false;
    };
    let Some(sequence) = prefix.strip_prefix("checkpoint-") else {
        return false;
    };
    sequence.len() == 20
        && sequence.bytes().all(|byte| byte.is_ascii_digit())
        && hash.len() == 64
        && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// A filesystem error while publishing or inspecting a checkpoint.
#[derive(Debug)]
pub enum CheckpointStoreError {
    EmptyDirectoryPath,
    DirectoryIsNotDirectory(PathBuf),
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    ExistingFileConflict(PathBuf),
    InvalidPublishedCheckpoint {
        path: PathBuf,
        source: CheckpointError,
    },
    TooManyCandidates {
        maximum: usize,
    },
}

impl fmt::Display for CheckpointStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyDirectoryPath => {
                formatter.write_str("checkpoint directory path cannot be empty")
            }
            Self::DirectoryIsNotDirectory(path) => {
                write!(
                    formatter,
                    "checkpoint path is not a directory: {}",
                    path.display()
                )
            }
            Self::Io {
                operation,
                path,
                source,
            } => write!(formatter, "{operation} at {}: {source}", path.display()),
            Self::ExistingFileConflict(path) => write!(
                formatter,
                "checkpoint file already exists with different or invalid content: {}",
                path.display()
            ),
            Self::InvalidPublishedCheckpoint { path, source } => write!(
                formatter,
                "published checkpoint at {} cannot be verified: {source}",
                path.display()
            ),
            Self::TooManyCandidates { maximum } => {
                write!(
                    formatter,
                    "checkpoint directory has more than {maximum} candidates"
                )
            }
        }
    }
}

impl std::error::Error for CheckpointStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::InvalidPublishedCheckpoint { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_is_stable_lowercase() {
        assert_eq!(encode_hex(&[0, 15, 16, 255]), "000f10ff");
    }

    #[test]
    fn only_exact_final_names_are_candidates() {
        assert!(is_candidate_filename(Path::new(
            "checkpoint-00000000000000000001-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.nxcp"
        )));
        assert!(!is_candidate_filename(Path::new("checkpoint-1.nxcp")));
        assert!(!is_candidate_filename(Path::new(
            "checkpoint-00000000000000000001-0123.tmp"
        )));
    }
}
