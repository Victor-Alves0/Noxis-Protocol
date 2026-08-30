//! Persistent catalog of public diversified payment addresses.
//!
//! This module intentionally persists only canonical `NXPA` address bytes.
//! It never receives private recipient keys, identity keys, seeds, shared
//! secrets, envelopes or note data. It is therefore useful for public address
//! distribution, but it is not a keystore or a spend-capable wallet.

use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{
    HybridPaymentAddress, PaymentAddressCodecError, decode_payment_address, encode_payment_address,
};

/// Name of the process-lifetime lock held while a public address book is open.
pub const PUBLIC_ADDRESS_BOOK_LOCK_FILE_NAME: &str = ".noxis-public-address-book.lock";
const ADDRESS_FILE_PREFIX: &str = "address-";
const ADDRESS_FILE_SUFFIX: &str = ".nxpa";
const MAX_PAYMENT_ADDRESS_FILE_BYTES: u64 = 2_048;
static TEMPORARY_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// An opened local catalog of canonical public `NXPA` payment addresses.
///
/// The catalog holds an exclusive lock until dropped, preventing two local
/// writers from racing over the same address directory. A crash may leave an
/// ignored temporary file, but a visible address file is created only after
/// its bytes have been synchronized and renamed into place.
#[derive(Debug)]
pub struct PublicAddressBook {
    root: PathBuf,
    _lock: AddressBookLock,
}

/// Result of idempotently adding a public address to a catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressBookStoreOutcome {
    Stored,
    AlreadyStored,
}

/// Reasons a public-address catalog cannot be safely opened or used.
#[derive(Debug)]
pub enum PublicAddressBookError {
    EmptyDirectoryPath,
    DirectoryAlreadyLocked(PathBuf),
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    AddressFileTooLarge {
        path: PathBuf,
        actual: u64,
        maximum: u64,
    },
    InvalidAddressFile {
        path: PathBuf,
        source: PaymentAddressCodecError,
    },
    AddressFileIdentityMismatch {
        path: PathBuf,
    },
}

impl fmt::Display for PublicAddressBookError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyDirectoryPath => {
                formatter.write_str("public address-book path must not be empty")
            }
            Self::DirectoryAlreadyLocked(path) => write!(
                formatter,
                "public address book is already open: {}",
                path.display()
            ),
            Self::Io {
                operation,
                path,
                source,
            } => write!(formatter, "{operation} {}: {source}", path.display()),
            Self::AddressFileTooLarge {
                path,
                actual,
                maximum,
            } => write!(
                formatter,
                "public address file {} is {actual} bytes, above the {maximum}-byte limit",
                path.display()
            ),
            Self::InvalidAddressFile { path, source } => {
                write!(
                    formatter,
                    "invalid public address file {}: {source}",
                    path.display()
                )
            }
            Self::AddressFileIdentityMismatch { path } => write!(
                formatter,
                "public address file name does not match the address identity: {}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for PublicAddressBookError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::InvalidAddressFile { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl PublicAddressBook {
    /// Opens or creates one public-address catalog and obtains its exclusive
    /// process-lifetime writer lock.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, PublicAddressBookError> {
        let root = root.into();
        if root.as_os_str().is_empty() {
            return Err(PublicAddressBookError::EmptyDirectoryPath);
        }
        fs::create_dir_all(&root).map_err(|source| PublicAddressBookError::Io {
            operation: "create public address-book directory",
            path: root.clone(),
            source,
        })?;
        let lock = AddressBookLock::acquire(root.join(PUBLIC_ADDRESS_BOOK_LOCK_FILE_NAME))?;
        Ok(Self { root, _lock: lock })
    }

    /// Returns the directory containing immutable public `NXPA` entries.
    pub fn path(&self) -> &Path {
        &self.root
    }

    /// Stores a canonical public payment address exactly once. Repeating the
    /// same address is safe and reports [`AddressBookStoreOutcome::AlreadyStored`].
    pub fn store(
        &self,
        address: &HybridPaymentAddress,
    ) -> Result<AddressBookStoreOutcome, PublicAddressBookError> {
        let path = self.address_path(address.address_id());
        let bytes = encode_payment_address(address);
        if path.exists() {
            let existing = self.load(address.address_id())?;
            if encode_payment_address(&existing) == bytes {
                return Ok(AddressBookStoreOutcome::AlreadyStored);
            }
            return Err(PublicAddressBookError::AddressFileIdentityMismatch { path });
        }

        self.write_new_address_file(&path, &bytes)?;
        Ok(AddressBookStoreOutcome::Stored)
    }

    /// Loads one address only when the file has bounded canonical bytes and
    /// its identity matches the untrusted filename-derived lookup key.
    pub fn load(
        &self,
        address_id: [u8; 32],
    ) -> Result<HybridPaymentAddress, PublicAddressBookError> {
        let path = self.address_path(address_id);
        let metadata = fs::metadata(&path).map_err(|source| PublicAddressBookError::Io {
            operation: "inspect public address file",
            path: path.clone(),
            source,
        })?;
        if metadata.len() > MAX_PAYMENT_ADDRESS_FILE_BYTES {
            return Err(PublicAddressBookError::AddressFileTooLarge {
                path,
                actual: metadata.len(),
                maximum: MAX_PAYMENT_ADDRESS_FILE_BYTES,
            });
        }
        let bytes = fs::read(&path).map_err(|source| PublicAddressBookError::Io {
            operation: "read public address file",
            path: path.clone(),
            source,
        })?;
        let address = decode_payment_address(&bytes).map_err(|source| {
            PublicAddressBookError::InvalidAddressFile {
                path: path.clone(),
                source,
            }
        })?;
        if address.address_id() != address_id {
            return Err(PublicAddressBookError::AddressFileIdentityMismatch { path });
        }
        Ok(address)
    }

    fn address_path(&self, address_id: [u8; 32]) -> PathBuf {
        self.root.join(format!(
            "{ADDRESS_FILE_PREFIX}{}{ADDRESS_FILE_SUFFIX}",
            hex(&address_id)
        ))
    }

    fn write_new_address_file(
        &self,
        destination: &Path,
        bytes: &[u8],
    ) -> Result<(), PublicAddressBookError> {
        let temporary = self.root.join(format!(
            ".{ADDRESS_FILE_PREFIX}{}-{}-{}.tmp",
            std::process::id(),
            TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed),
            destination
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("entry")
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|source| PublicAddressBookError::Io {
                operation: "create temporary public address file",
                path: temporary.clone(),
                source,
            })?;
        file.write_all(bytes)
            .map_err(|source| PublicAddressBookError::Io {
                operation: "write temporary public address file",
                path: temporary.clone(),
                source,
            })?;
        file.sync_all()
            .map_err(|source| PublicAddressBookError::Io {
                operation: "synchronize temporary public address file",
                path: temporary.clone(),
                source,
            })?;
        drop(file);
        fs::rename(&temporary, destination).map_err(|source| PublicAddressBookError::Io {
            operation: "publish public address file",
            path: destination.to_path_buf(),
            source,
        })?;
        Ok(())
    }
}

#[derive(Debug)]
struct AddressBookLock {
    file: Option<File>,
    path: PathBuf,
}

impl AddressBookLock {
    fn acquire(path: PathBuf) -> Result<Self, PublicAddressBookError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|source| {
                if source.kind() == io::ErrorKind::AlreadyExists {
                    PublicAddressBookError::DirectoryAlreadyLocked(path.clone())
                } else {
                    PublicAddressBookError::Io {
                        operation: "create public address-book lock",
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

impl Drop for AddressBookLock {
    fn drop(&mut self) {
        drop(self.file.take());
        let _ = fs::remove_file(&self.path);
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::{HybridPaymentAddressEntry, PaymentDiversifier};

    use super::{AddressBookStoreOutcome, PublicAddressBook, PublicAddressBookError};

    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn test_directory(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "noxis-public-address-book-{label}-{}-{}",
            std::process::id(),
            TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn public_address_survives_reopen_without_any_private_key_storage() {
        let root = test_directory("reopen");
        let entry =
            HybridPaymentAddressEntry::with_diversifier(PaymentDiversifier::from_bytes([7; 16]), 3);
        let address_id = entry.address().address_id();
        {
            let book = PublicAddressBook::open(&root).unwrap();
            assert_eq!(
                book.store(entry.address()).unwrap(),
                AddressBookStoreOutcome::Stored
            );
            assert_eq!(
                book.store(entry.address()).unwrap(),
                AddressBookStoreOutcome::AlreadyStored
            );
        }
        let reopened = PublicAddressBook::open(&root).unwrap();
        let loaded = reopened.load(address_id).unwrap();
        assert_eq!(loaded.address_id(), address_id);
        assert_eq!(loaded.key_epoch(), 3);
        drop(reopened);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn address_book_refuses_a_second_open_writer() {
        let root = test_directory("lock");
        let first = PublicAddressBook::open(&root).unwrap();
        assert!(matches!(
            PublicAddressBook::open(&root),
            Err(PublicAddressBookError::DirectoryAlreadyLocked(_))
        ));
        drop(first);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn address_book_rejects_tampered_canonical_address_bytes() {
        let root = test_directory("tamper");
        let entry =
            HybridPaymentAddressEntry::with_diversifier(PaymentDiversifier::from_bytes([9; 16]), 4);
        let address_id = entry.address().address_id();
        let book = PublicAddressBook::open(&root).unwrap();
        book.store(entry.address()).unwrap();
        let path = book.address_path(address_id);
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(path, bytes).unwrap();

        assert!(matches!(
            book.load(address_id),
            Err(PublicAddressBookError::InvalidAddressFile { .. })
        ));
        drop(book);
        std::fs::remove_dir_all(root).unwrap();
    }
}
