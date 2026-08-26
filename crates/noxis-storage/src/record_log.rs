//! Framed durable storage for state-transition records.
//!
//! This module owns only physical framing and incomplete-tail recovery. Logical
//! continuity and state-transition replay are enforced by `PersistentLedger`.

use std::{
    fmt,
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use noxis_record_chain::{RecordError, TransactionRecord};

use crate::crc32;

/// Magic bytes identifying one state-record log frame.
pub const RECORD_FRAME_MAGIC: [u8; 4] = *b"NXRF";
/// Version of the outer record-log frame.
pub const RECORD_FRAME_VERSION: u16 = 1;
/// Fixed bytes before a record payload.
pub const RECORD_FRAME_HEADER_LENGTH: usize = 10;
/// Fixed CRC-32 bytes after a record payload.
pub const RECORD_FRAME_CHECKSUM_LENGTH: usize = 4;
/// Largest accepted encoded `NXRC` payload.
pub const MAX_RECORD_FRAME_PAYLOAD_LENGTH: u32 =
    noxis_record_chain::MAX_RECORD_TRANSACTION_BYTES + 146;

/// One validated record recovered at a physical byte offset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredRecord {
    /// Byte offset of the enclosing frame.
    pub offset: u64,
    /// Fully decoded and hash-verified state-transition record.
    pub record: TransactionRecord,
}

enum FrameScan {
    Complete(Vec<StoredRecord>),
    IncompleteTail {
        records: Vec<StoredRecord>,
        valid_prefix_length: u64,
        section: &'static str,
    },
}

/// A final partial frame observed during recovery scanning.
///
/// It cannot be truncated until the caller has validated every preceding
/// record and then asks this log to re-scan the same tail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IncompleteTail {
    valid_prefix_length: u64,
    section: &'static str,
}

/// A non-mutating recovery scan of a state-record log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordRecoveryScan {
    /// Every complete, validated record preceding a possible partial tail.
    pub records: Vec<StoredRecord>,
    /// A structurally plausible final partial frame, if one exists.
    pub incomplete_tail: Option<IncompleteTail>,
}

/// A single-writer append-only log of `NXRC` state-transition records.
pub struct StateRecordLog {
    path: PathBuf,
    file: File,
}

impl StateRecordLog {
    /// Opens a log for a non-mutating recovery scan.
    ///
    /// Call [`Self::scan_recoverable_tail`], replay its complete records, and
    /// only then call [`Self::truncate_verified_incomplete_tail`] for a tail
    /// returned by that scan. This ordering prevents a partial tail from
    /// hiding an invalid complete history prefix.
    pub fn open_for_recovery(path: impl AsRef<Path>) -> Result<Self, RecordLogError> {
        let path = path.as_ref().to_path_buf();
        let mut file = open_file(&path)?;
        file.seek(SeekFrom::End(0))
            .map_err(|source| RecordLogError::Io {
                operation: "seek state-record log end",
                source,
            })?;
        Ok(Self { path, file })
    }

    /// Returns the path used by this log writer.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends one complete, validated record and synchronizes it before
    /// returning its physical offset.
    pub fn append_record(&mut self, record: &TransactionRecord) -> Result<u64, RecordLogError> {
        let payload = record.encode();
        // Re-decoding makes this boundary reject any future construction path
        // that accidentally bypasses canonical record validation.
        TransactionRecord::decode(&payload).map_err(RecordLogError::Record)?;
        let frame = encode_frame(&payload)?;
        let offset = self
            .file
            .seek(SeekFrom::End(0))
            .map_err(|source| RecordLogError::Io {
                operation: "seek state-record log end",
                source,
            })?;
        self.file
            .write_all(&frame)
            .map_err(|source| RecordLogError::Io {
                operation: "append state-record frame",
                source,
            })?;
        self.file.flush().map_err(|source| RecordLogError::Io {
            operation: "flush state-record frame",
            source,
        })?;
        self.file.sync_data().map_err(|source| RecordLogError::Io {
            operation: "sync state-record frame",
            source,
        })?;
        Ok(offset)
    }

    /// Scans all complete frames without changing the file.
    pub fn scan_recoverable_tail(&mut self) -> Result<RecordRecoveryScan, RecordLogError> {
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|source| RecordLogError::Io {
                operation: "seek state-record log start",
                source,
            })?;
        let scan = match scan_frames(&mut self.file)? {
            FrameScan::Complete(records) => RecordRecoveryScan {
                records,
                incomplete_tail: None,
            },
            FrameScan::IncompleteTail {
                records,
                valid_prefix_length,
                section,
            } => RecordRecoveryScan {
                records,
                incomplete_tail: Some(IncompleteTail {
                    valid_prefix_length,
                    section,
                }),
            },
        };
        self.file
            .seek(SeekFrom::End(0))
            .map_err(|source| RecordLogError::Io {
                operation: "seek state-record log end",
                source,
            })?;
        Ok(scan)
    }

    /// Removes the exact partial tail returned by a successful recovery scan.
    ///
    /// This re-scans before truncating, so a caller cannot accidentally remove
    /// a different or newly changed suffix.
    pub fn truncate_verified_incomplete_tail(
        &mut self,
        expected: IncompleteTail,
    ) -> Result<(), RecordLogError> {
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|source| RecordLogError::Io {
                operation: "seek state-record log start",
                source,
            })?;
        let actual = match scan_frames(&mut self.file)? {
            FrameScan::Complete(_) => return Err(RecordLogError::RecoveryTailChanged),
            FrameScan::IncompleteTail {
                valid_prefix_length,
                section,
                ..
            } => IncompleteTail {
                valid_prefix_length,
                section,
            },
        };
        if actual != expected {
            return Err(RecordLogError::RecoveryTailChanged);
        }
        self.file
            .set_len(actual.valid_prefix_length)
            .map_err(|source| RecordLogError::Io {
                operation: "remove verified incomplete state-record-log tail",
                source,
            })?;
        self.file.sync_all().map_err(|source| RecordLogError::Io {
            operation: "sync recovered state-record log",
            source,
        })?;
        validate_file(&mut self.file)?;
        self.file
            .seek(SeekFrom::End(0))
            .map_err(|source| RecordLogError::Io {
                operation: "seek state-record log end",
                source,
            })?;
        Ok(())
    }
}

fn validate_file(file: &mut File) -> Result<(), RecordLogError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|source| RecordLogError::Io {
            operation: "seek state-record log start",
            source,
        })?;
    match scan_frames(file)? {
        FrameScan::Complete(_) => Ok(()),
        FrameScan::IncompleteTail {
            valid_prefix_length,
            section,
            ..
        } => Err(RecordLogError::TruncatedFrame {
            offset: valid_prefix_length,
            section,
        }),
    }
}

fn scan_frames(file: &mut File) -> Result<FrameScan, RecordLogError> {
    let mut entries = Vec::new();
    let mut offset = 0_u64;
    let file_length = file
        .metadata()
        .map_err(|source| RecordLogError::Io {
            operation: "read state-record log metadata",
            source,
        })?
        .len();

    while offset < file_length {
        let remaining = file_length - offset;
        if remaining < 4 {
            let mut partial_magic = vec![0_u8; remaining as usize];
            read_exact(file, &mut partial_magic)?;
            if RECORD_FRAME_MAGIC.starts_with(&partial_magic) {
                return Ok(FrameScan::IncompleteTail {
                    records: entries,
                    valid_prefix_length: offset,
                    section: "frame magic",
                });
            }
            return Err(RecordLogError::InvalidMagic { offset });
        }

        let mut magic = [0_u8; 4];
        read_exact(file, &mut magic)?;
        if magic == *b"NXLG" {
            return Err(RecordLogError::LegacyTransactionLog { offset });
        }
        if magic != RECORD_FRAME_MAGIC {
            return Err(RecordLogError::InvalidMagic { offset });
        }
        if remaining < RECORD_FRAME_HEADER_LENGTH as u64 {
            return Ok(FrameScan::IncompleteTail {
                records: entries,
                valid_prefix_length: offset,
                section: "frame header",
            });
        }

        let mut header_remainder = [0_u8; RECORD_FRAME_HEADER_LENGTH - 4];
        read_exact(file, &mut header_remainder)?;
        let version = u16::from_be_bytes([header_remainder[0], header_remainder[1]]);
        if version != RECORD_FRAME_VERSION {
            return Err(RecordLogError::UnsupportedFrameVersion { offset, version });
        }
        let payload_length = u32::from_be_bytes([
            header_remainder[2],
            header_remainder[3],
            header_remainder[4],
            header_remainder[5],
        ]);
        if payload_length > MAX_RECORD_FRAME_PAYLOAD_LENGTH {
            return Err(RecordLogError::FrameTooLarge {
                offset,
                actual: payload_length,
                maximum: MAX_RECORD_FRAME_PAYLOAD_LENGTH,
            });
        }
        let frame_length = (RECORD_FRAME_HEADER_LENGTH as u64)
            .checked_add(payload_length as u64)
            .and_then(|length| length.checked_add(RECORD_FRAME_CHECKSUM_LENGTH as u64))
            .ok_or(RecordLogError::OffsetOverflow)?;
        if remaining < frame_length {
            return Ok(FrameScan::IncompleteTail {
                records: entries,
                valid_prefix_length: offset,
                section: if remaining < RECORD_FRAME_HEADER_LENGTH as u64 + payload_length as u64 {
                    "frame payload"
                } else {
                    "frame checksum"
                },
            });
        }

        let mut payload = vec![0_u8; payload_length as usize];
        read_exact(file, &mut payload)?;
        let mut checksum = [0_u8; RECORD_FRAME_CHECKSUM_LENGTH];
        read_exact(file, &mut checksum)?;
        let expected_checksum = u32::from_be_bytes(checksum);
        let actual_checksum = crc32(&payload);
        if actual_checksum != expected_checksum {
            return Err(RecordLogError::ChecksumMismatch {
                offset,
                expected: expected_checksum,
                actual: actual_checksum,
            });
        }
        let record = TransactionRecord::decode(&payload)
            .map_err(|source| RecordLogError::Record { offset, source })?;
        entries.push(StoredRecord { offset, record });
        offset = offset
            .checked_add(frame_length)
            .ok_or(RecordLogError::OffsetOverflow)?;
    }
    Ok(FrameScan::Complete(entries))
}

fn open_file(path: &Path) -> Result<File, RecordLogError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
        .map_err(|source| RecordLogError::Io {
            operation: "open state-record log",
            source,
        })
}

fn read_exact(file: &mut File, bytes: &mut [u8]) -> Result<(), RecordLogError> {
    file.read_exact(bytes).map_err(|source| RecordLogError::Io {
        operation: "read state-record frame",
        source,
    })
}

fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, RecordLogError> {
    let payload_length =
        u32::try_from(payload.len()).map_err(|_| RecordLogError::FrameTooLarge {
            offset: 0,
            actual: u32::MAX,
            maximum: MAX_RECORD_FRAME_PAYLOAD_LENGTH,
        })?;
    if payload_length > MAX_RECORD_FRAME_PAYLOAD_LENGTH {
        return Err(RecordLogError::FrameTooLarge {
            offset: 0,
            actual: payload_length,
            maximum: MAX_RECORD_FRAME_PAYLOAD_LENGTH,
        });
    }
    let mut frame = Vec::with_capacity(
        RECORD_FRAME_HEADER_LENGTH + payload.len() + RECORD_FRAME_CHECKSUM_LENGTH,
    );
    frame.extend_from_slice(&RECORD_FRAME_MAGIC);
    frame.extend_from_slice(&RECORD_FRAME_VERSION.to_be_bytes());
    frame.extend_from_slice(&payload_length.to_be_bytes());
    frame.extend_from_slice(payload);
    frame.extend_from_slice(&crc32(payload).to_be_bytes());
    Ok(frame)
}

/// Reasons a state-record log cannot be safely opened or written.
#[derive(Debug)]
pub enum RecordLogError {
    Io {
        operation: &'static str,
        source: io::Error,
    },
    InvalidMagic {
        offset: u64,
    },
    /// A v0 transaction-only `NXLG` file was found; it has no state links and
    /// is intentionally not upgraded by opening a durable state chain.
    LegacyTransactionLog {
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
    Record {
        offset: u64,
        source: RecordError,
    },
    OffsetOverflow,
    RecoveryTailChanged,
}

impl fmt::Display for RecordLogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, source } => write!(formatter, "{operation}: {source}"),
            Self::InvalidMagic { offset } => {
                write!(formatter, "invalid record frame magic at offset {offset}")
            }
            Self::LegacyTransactionLog { offset } => write!(
                formatter,
                "legacy transaction-only log at offset {offset}; explicit migration is required"
            ),
            Self::UnsupportedFrameVersion { offset, version } => write!(
                formatter,
                "unsupported state-record frame version {version} at offset {offset}"
            ),
            Self::FrameTooLarge {
                offset,
                actual,
                maximum,
            } => write!(
                formatter,
                "state-record frame at offset {offset} has length {actual}, above limit {maximum}"
            ),
            Self::TruncatedFrame { offset, section } => write!(
                formatter,
                "truncated {section} for state-record frame at offset {offset}"
            ),
            Self::ChecksumMismatch {
                offset,
                expected,
                actual,
            } => write!(
                formatter,
                "state-record checksum mismatch at offset {offset}: expected {expected:08x}, got {actual:08x}"
            ),
            Self::Record { offset, source } => {
                write!(
                    formatter,
                    "invalid state record at offset {offset}: {source}"
                )
            }
            Self::OffsetOverflow => formatter.write_str("state-record log offset overflow"),
            Self::RecoveryTailChanged => formatter.write_str(
                "state-record log changed after recovery scan; refusing to truncate its tail",
            ),
        }
    }
}

impl std::error::Error for RecordLogError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Record { source, .. } => Some(source),
            _ => None,
        }
    }
}
