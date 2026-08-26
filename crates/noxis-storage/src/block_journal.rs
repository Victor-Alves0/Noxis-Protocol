//! Framed durable storage for fully executed blocks.
//!
//! This module owns the physical `NXCB` frame and the canonical `NXBP` block
//! payload inside it.  It deliberately does not replay ledger transitions,
//! establish cross-block parent continuity, or decide consensus finality; those
//! checks belong to the recovery coordinator.  It does, however, verify every
//! contained `NXBH` header and `NXRC` record, their intra-block state links,
//! and the header's record commitment before returning a [`StoredBlock`].

use std::{
    convert::Infallible,
    fmt,
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use fs2::FileExt;
use noxis_consensus::{
    BlockHeader, CometBftDecision, ConsensusError, MAX_BLOCK_RECORDS, decode_block_header,
    encode_block_header,
};
use noxis_record_chain::{RecordError, TransactionRecord};
use noxis_types::{AppHash, StateId};

use crate::crc32;

/// Magic bytes identifying an outer durable block frame.
pub const BLOCK_FRAME_MAGIC: [u8; 4] = *b"NXCB";
/// Version of the outer durable block frame.
pub const BLOCK_FRAME_VERSION: u16 = 2;
/// Bytes before a block-frame payload.
pub const BLOCK_FRAME_HEADER_LENGTH: usize = 10;
/// CRC-32 bytes after a block-frame payload.
pub const BLOCK_FRAME_CHECKSUM_LENGTH: usize = 4;

/// Magic bytes identifying a canonical block payload inside an `NXCB` frame.
pub const BLOCK_PAYLOAD_MAGIC: [u8; 4] = *b"NXBP";
/// Version of the canonical block payload.
pub const BLOCK_PAYLOAD_VERSION: u16 = 2;

const BLOCK_HEADER_MAXIMUM_LENGTH: u32 = 4 * 1024;
const RECORD_ENVELOPE_OVERHEAD: u32 = 4 + 2 + 8 + 32 + 4 + 32 + 32 + 32;
const MAX_ENCODED_RECORD_LENGTH: u32 =
    noxis_record_chain::MAX_RECORD_TRANSACTION_BYTES + RECORD_ENVELOPE_OVERHEAD;
const COMET_DECISION_ENCODED_BYTES: u64 = 32 + 8 + 32 + 32;
const BLOCK_PAYLOAD_FIXED_BYTES: u64 = 4 + 2 + 4 + 32 + COMET_DECISION_ENCODED_BYTES + 4;

/// Largest accepted canonical block payload.
///
/// The bound covers the consensus-wide maximum aggregate transaction bytes,
/// one `NXRC` envelope and length prefix per possible record, a header, and
/// the app hash.  It is deliberately independent of an untrusted header.
pub const MAX_BLOCK_FRAME_PAYLOAD_LENGTH: u32 = 64 * 1024 * 1024
    + (MAX_BLOCK_RECORDS as u32) * (RECORD_ENVELOPE_OVERHEAD + 4)
    + BLOCK_PAYLOAD_FIXED_BYTES as u32
    + BLOCK_HEADER_MAXIMUM_LENGTH;

/// One complete, validated block recovered at a physical byte offset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredBlock {
    /// Byte offset of the enclosing `NXCB` frame.
    pub offset: u64,
    /// Canonical Noxis block header (`NXBH`).
    pub header: BlockHeader,
    /// Deterministic application commitment after this block.
    pub app_hash: AppHash,
    /// Exact CometBFT decision bound to this Noxis block.
    pub comet_decision: CometBftDecision,
    /// Ordered, hash-verified state-transition records (`NXRC`).
    pub records: Vec<TransactionRecord>,
}

impl StoredBlock {
    /// Creates a block suitable for a durable journal append.
    ///
    /// The offset is assigned by [`BlockJournal::append_block`].
    pub fn new(
        header: BlockHeader,
        app_hash: AppHash,
        comet_decision: CometBftDecision,
        records: Vec<TransactionRecord>,
    ) -> Result<Self, BlockJournalError> {
        validate_block(&header, &records)?;
        Ok(Self {
            offset: 0,
            header,
            app_hash,
            comet_decision,
            records,
        })
    }
}

enum FrameScan {
    Complete(Vec<StoredBlock>),
    IncompleteTail {
        blocks: Vec<StoredBlock>,
        valid_prefix_length: u64,
        section: &'static str,
    },
}

/// A final partial frame observed during a non-mutating recovery scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IncompleteBlockTail {
    valid_prefix_length: u64,
    section: &'static str,
}

/// Result of a non-mutating journal recovery scan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockRecoveryScan {
    /// All complete, fully verified blocks before a possible partial tail.
    pub blocks: Vec<StoredBlock>,
    /// A plausible final partial frame, if one exists.
    pub incomplete_tail: Option<IncompleteBlockTail>,
}

/// Failure emitted while replaying a journal frame-by-frame.
#[derive(Debug)]
pub enum BlockJournalReplayError<E> {
    Journal(BlockJournalError),
    Visitor(E),
}

/// Single-writer append-only physical journal of executed blocks.
pub struct BlockJournal {
    path: PathBuf,
    file: File,
}

impl BlockJournal {
    /// Opens a journal after strictly validating every complete frame.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, BlockJournalError> {
        let mut journal = Self::open_for_recovery(path)?;
        validate_file(&mut journal.file)?;
        journal
            .file
            .seek(SeekFrom::End(0))
            .map_err(|source| BlockJournalError::Io {
                operation: "seek block journal end",
                source,
            })?;
        Ok(journal)
    }

    /// Opens a journal so its complete prefix can be recovered before a
    /// plausible final partial frame is truncated.
    pub fn open_for_recovery(path: impl AsRef<Path>) -> Result<Self, BlockJournalError> {
        let path = path.as_ref().to_path_buf();
        let mut file = open_file(&path)?;
        file.try_lock_exclusive()
            .map_err(|source| BlockJournalError::Io {
                operation: "acquire exclusive block-journal lock",
                source,
            })?;
        file.seek(SeekFrom::End(0))
            .map_err(|source| BlockJournalError::Io {
                operation: "seek block journal end",
                source,
            })?;
        Ok(Self { path, file })
    }

    /// Returns the path used by this journal writer.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Writes one complete verified block and synchronizes its data before
    /// returning the durable frame offset.
    pub fn append_block(&mut self, block: &StoredBlock) -> Result<u64, BlockJournalError> {
        validate_block(&block.header, &block.records)?;
        let payload = encode_payload(
            &block.header,
            block.app_hash,
            block.comet_decision,
            &block.records,
        )?;
        // Decode the exact canonical bytes at the storage boundary.  This
        // makes malformed future construction paths fail before disk I/O.
        decode_payload(&payload).map_err(|source| BlockJournalError::Payload {
            offset: 0,
            source: Box::new(source),
        })?;
        let frame = encode_frame(&payload)?;
        let offset = self
            .file
            .seek(SeekFrom::End(0))
            .map_err(|source| BlockJournalError::Io {
                operation: "seek block journal end",
                source,
            })?;
        self.file
            .write_all(&frame)
            .map_err(|source| BlockJournalError::Io {
                operation: "append block frame",
                source,
            })?;
        self.file.flush().map_err(|source| BlockJournalError::Io {
            operation: "flush block frame",
            source,
        })?;
        self.file
            .sync_data()
            .map_err(|source| BlockJournalError::Io {
                operation: "sync block frame",
                source,
            })?;
        // `sync_data` does not make a just-created POSIX directory entry
        // durable. Repeat this barrier for every acknowledged append so a
        // previous interrupted initialization cannot weaken a later commit.
        sync_parent_directory(&self.path)?;
        Ok(offset)
    }

    /// Reads every complete frame without altering the journal.
    ///
    /// This diagnostic API materializes the entire history and is unsuitable
    /// for normal recovery of an unbounded journal. Use
    /// [`Self::replay_recoverable_tail`] instead.
    #[deprecated(
        note = "materializes all blocks; use replay_recoverable_tail for bounded-memory recovery"
    )]
    pub fn scan_recoverable_tail(&mut self) -> Result<BlockRecoveryScan, BlockJournalError> {
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|source| BlockJournalError::Io {
                operation: "seek block journal start",
                source,
            })?;
        let scan = match scan_frames(&mut self.file)? {
            FrameScan::Complete(blocks) => BlockRecoveryScan {
                blocks,
                incomplete_tail: None,
            },
            FrameScan::IncompleteTail {
                blocks,
                valid_prefix_length,
                section,
            } => BlockRecoveryScan {
                blocks,
                incomplete_tail: Some(IncompleteBlockTail {
                    valid_prefix_length,
                    section,
                }),
            },
        };
        self.file
            .seek(SeekFrom::End(0))
            .map_err(|source| BlockJournalError::Io {
                operation: "seek block journal end",
                source,
            })?;
        Ok(scan)
    }

    /// Replays each complete frame immediately instead of retaining the whole
    /// journal in memory. The caller supplies the semantic validation (for
    /// example, deterministic execution) for one decoded block at a time.
    ///
    /// The final incomplete frame is returned only after the visitor has
    /// accepted every preceding complete frame. Any visitor rejection leaves
    /// the journal unchanged and prevents tail truncation.
    pub fn replay_recoverable_tail<E>(
        &mut self,
        mut visitor: impl FnMut(StoredBlock) -> Result<(), E>,
    ) -> Result<Option<IncompleteBlockTail>, BlockJournalReplayError<E>> {
        self.file.seek(SeekFrom::Start(0)).map_err(|source| {
            BlockJournalReplayError::Journal(BlockJournalError::Io {
                operation: "seek block journal start",
                source,
            })
        })?;
        let result = stream_frames(&mut self.file, &mut visitor);
        self.file.seek(SeekFrom::End(0)).map_err(|source| {
            BlockJournalReplayError::Journal(BlockJournalError::Io {
                operation: "seek block journal end",
                source,
            })
        })?;
        result
    }

    /// Removes exactly the partial tail returned by a successful recovery
    /// scan, after re-scanning to ensure the file has not changed.
    pub fn truncate_verified_incomplete_tail(
        &mut self,
        expected: IncompleteBlockTail,
    ) -> Result<(), BlockJournalError> {
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|source| BlockJournalError::Io {
                operation: "seek block journal start",
                source,
            })?;
        let actual = match stream_frames(&mut self.file, &mut |_| Ok::<(), Infallible>(()))
            .map_err(|error| match error {
                BlockJournalReplayError::Journal(error) => error,
                BlockJournalReplayError::Visitor(never) => match never {},
            })? {
            None => return Err(BlockJournalError::RecoveryTailChanged),
            Some(tail) => tail,
        };
        if actual != expected {
            return Err(BlockJournalError::RecoveryTailChanged);
        }
        self.file
            .set_len(actual.valid_prefix_length)
            .map_err(|source| BlockJournalError::Io {
                operation: "remove verified incomplete block-journal tail",
                source,
            })?;
        self.file
            .sync_all()
            .map_err(|source| BlockJournalError::Io {
                operation: "sync recovered block journal",
                source,
            })?;
        validate_complete_file_streaming(&mut self.file)?;
        self.file
            .seek(SeekFrom::End(0))
            .map_err(|source| BlockJournalError::Io {
                operation: "seek block journal end",
                source,
            })?;
        Ok(())
    }
}

fn validate_file(file: &mut File) -> Result<(), BlockJournalError> {
    validate_complete_file_streaming(file)
}

fn validate_complete_file_streaming(file: &mut File) -> Result<(), BlockJournalError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|source| BlockJournalError::Io {
            operation: "seek block journal start",
            source,
        })?;
    match stream_frames(file, &mut |_| Ok::<(), Infallible>(())).map_err(|error| match error {
        BlockJournalReplayError::Journal(error) => error,
        BlockJournalReplayError::Visitor(never) => match never {},
    })? {
        None => Ok(()),
        Some(tail) => Err(BlockJournalError::TruncatedFrame {
            offset: tail.valid_prefix_length,
            section: tail.section,
        }),
    }
}

fn scan_frames(file: &mut File) -> Result<FrameScan, BlockJournalError> {
    let mut blocks = Vec::new();
    let incomplete_tail = stream_frames(file, &mut |block| {
        blocks.push(block);
        Ok::<(), Infallible>(())
    })
    .map_err(|error| match error {
        BlockJournalReplayError::Journal(error) => error,
        BlockJournalReplayError::Visitor(never) => match never {},
    })?;
    Ok(match incomplete_tail {
        Some(tail) => FrameScan::IncompleteTail {
            blocks,
            valid_prefix_length: tail.valid_prefix_length,
            section: tail.section,
        },
        None => FrameScan::Complete(blocks),
    })
}

fn stream_frames<E>(
    file: &mut File,
    visitor: &mut impl FnMut(StoredBlock) -> Result<(), E>,
) -> Result<Option<IncompleteBlockTail>, BlockJournalReplayError<E>> {
    let mut offset = 0_u64;
    let file_length = file
        .metadata()
        .map_err(|source| {
            BlockJournalReplayError::Journal(BlockJournalError::Io {
                operation: "read block journal metadata",
                source,
            })
        })?
        .len();

    while offset < file_length {
        let remaining = file_length - offset;
        if remaining < 4 {
            let mut partial_magic = vec![0_u8; remaining as usize];
            read_exact(file, &mut partial_magic).map_err(BlockJournalReplayError::Journal)?;
            if BLOCK_FRAME_MAGIC.starts_with(&partial_magic) {
                return Ok(Some(IncompleteBlockTail {
                    valid_prefix_length: offset,
                    section: "frame magic",
                }));
            }
            return Err(BlockJournalReplayError::Journal(
                BlockJournalError::InvalidMagic { offset },
            ));
        }

        let mut magic = [0_u8; 4];
        read_exact(file, &mut magic).map_err(BlockJournalReplayError::Journal)?;
        if magic != BLOCK_FRAME_MAGIC {
            return Err(BlockJournalReplayError::Journal(
                BlockJournalError::InvalidMagic { offset },
            ));
        }
        if remaining < BLOCK_FRAME_HEADER_LENGTH as u64 {
            return Ok(Some(IncompleteBlockTail {
                valid_prefix_length: offset,
                section: "frame header",
            }));
        }
        let mut header_remainder = [0_u8; BLOCK_FRAME_HEADER_LENGTH - 4];
        read_exact(file, &mut header_remainder).map_err(BlockJournalReplayError::Journal)?;
        let version = u16::from_be_bytes([header_remainder[0], header_remainder[1]]);
        if version != BLOCK_FRAME_VERSION {
            return Err(BlockJournalReplayError::Journal(
                BlockJournalError::UnsupportedFrameVersion { offset, version },
            ));
        }
        let payload_length = u32::from_be_bytes([
            header_remainder[2],
            header_remainder[3],
            header_remainder[4],
            header_remainder[5],
        ]);
        if payload_length > MAX_BLOCK_FRAME_PAYLOAD_LENGTH {
            return Err(BlockJournalReplayError::Journal(
                BlockJournalError::FrameTooLarge {
                    offset,
                    actual: payload_length,
                    maximum: MAX_BLOCK_FRAME_PAYLOAD_LENGTH,
                },
            ));
        }
        let frame_length = (BLOCK_FRAME_HEADER_LENGTH as u64)
            .checked_add(u64::from(payload_length))
            .and_then(|value| value.checked_add(BLOCK_FRAME_CHECKSUM_LENGTH as u64))
            .ok_or(BlockJournalReplayError::Journal(
                BlockJournalError::OffsetOverflow,
            ))?;
        if remaining < frame_length {
            return Ok(Some(IncompleteBlockTail {
                valid_prefix_length: offset,
                section: if remaining < BLOCK_FRAME_HEADER_LENGTH as u64 + u64::from(payload_length)
                {
                    "frame payload"
                } else {
                    "frame checksum"
                },
            }));
        }
        let mut payload = vec![0_u8; payload_length as usize];
        read_exact(file, &mut payload).map_err(BlockJournalReplayError::Journal)?;
        let mut checksum = [0_u8; BLOCK_FRAME_CHECKSUM_LENGTH];
        read_exact(file, &mut checksum).map_err(BlockJournalReplayError::Journal)?;
        let expected = u32::from_be_bytes(checksum);
        let actual = crc32(&payload);
        if actual != expected {
            return Err(BlockJournalReplayError::Journal(
                BlockJournalError::ChecksumMismatch {
                    offset,
                    expected,
                    actual,
                },
            ));
        }
        let mut block = decode_payload(&payload).map_err(|source| {
            BlockJournalReplayError::Journal(BlockJournalError::Payload {
                offset,
                source: Box::new(source),
            })
        })?;
        block.offset = offset;
        visitor(block).map_err(BlockJournalReplayError::Visitor)?;
        offset = offset
            .checked_add(frame_length)
            .ok_or(BlockJournalReplayError::Journal(
                BlockJournalError::OffsetOverflow,
            ))?;
    }
    Ok(None)
}

fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, BlockJournalError> {
    let payload_length =
        u32::try_from(payload.len()).map_err(|_| BlockJournalError::FrameTooLarge {
            offset: 0,
            actual: u32::MAX,
            maximum: MAX_BLOCK_FRAME_PAYLOAD_LENGTH,
        })?;
    if payload_length > MAX_BLOCK_FRAME_PAYLOAD_LENGTH {
        return Err(BlockJournalError::FrameTooLarge {
            offset: 0,
            actual: payload_length,
            maximum: MAX_BLOCK_FRAME_PAYLOAD_LENGTH,
        });
    }
    let mut frame =
        Vec::with_capacity(BLOCK_FRAME_HEADER_LENGTH + payload.len() + BLOCK_FRAME_CHECKSUM_LENGTH);
    frame.extend_from_slice(&BLOCK_FRAME_MAGIC);
    frame.extend_from_slice(&BLOCK_FRAME_VERSION.to_be_bytes());
    frame.extend_from_slice(&payload_length.to_be_bytes());
    frame.extend_from_slice(payload);
    frame.extend_from_slice(&crc32(payload).to_be_bytes());
    Ok(frame)
}

fn encode_payload(
    header: &BlockHeader,
    app_hash: AppHash,
    comet_decision: CometBftDecision,
    records: &[TransactionRecord],
) -> Result<Vec<u8>, BlockJournalError> {
    validate_block(header, records)?;
    let header_bytes = encode_block_header(header);
    let total_record_bytes = records.iter().try_fold(0_usize, |total, record| {
        total
            .checked_add(4)
            .and_then(|value| value.checked_add(record.encode().len()))
            .ok_or(BlockJournalError::PayloadLengthOverflow)
    })?;
    let capacity = (BLOCK_PAYLOAD_FIXED_BYTES as usize)
        .checked_add(header_bytes.len())
        .and_then(|value| value.checked_add(total_record_bytes))
        .ok_or(BlockJournalError::PayloadLengthOverflow)?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(&BLOCK_PAYLOAD_MAGIC);
    bytes.extend_from_slice(&BLOCK_PAYLOAD_VERSION.to_be_bytes());
    bytes.extend_from_slice(&(header_bytes.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&header_bytes);
    bytes.extend_from_slice(&app_hash.0);
    bytes.extend_from_slice(&comet_decision.network_id());
    bytes.extend_from_slice(&comet_decision.height().to_be_bytes());
    bytes.extend_from_slice(&comet_decision.block_hash());
    bytes.extend_from_slice(&comet_decision.next_validators_hash());
    bytes.extend_from_slice(&(records.len() as u32).to_be_bytes());
    for record in records {
        let encoded = record.encode();
        bytes.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&encoded);
    }
    if bytes.len() > MAX_BLOCK_FRAME_PAYLOAD_LENGTH as usize {
        return Err(BlockJournalError::FrameTooLarge {
            offset: 0,
            actual: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
            maximum: MAX_BLOCK_FRAME_PAYLOAD_LENGTH,
        });
    }
    Ok(bytes)
}

fn decode_payload(bytes: &[u8]) -> Result<StoredBlock, PayloadError> {
    let mut reader = PayloadReader::new(bytes);
    if reader.read_array::<4>()? != BLOCK_PAYLOAD_MAGIC {
        return Err(PayloadError::InvalidPayloadMagic);
    }
    let version = reader.read_u16()?;
    if version != BLOCK_PAYLOAD_VERSION {
        return Err(PayloadError::UnsupportedPayloadVersion(version));
    }
    let header_length = reader.read_u32()?;
    if header_length > BLOCK_HEADER_MAXIMUM_LENGTH {
        return Err(PayloadError::HeaderTooLarge {
            actual: header_length,
            maximum: BLOCK_HEADER_MAXIMUM_LENGTH,
        });
    }
    let header_bytes = reader.read_exact(header_length as usize)?;
    let header = decode_block_header(header_bytes).map_err(PayloadError::Consensus)?;
    if encode_block_header(&header) != header_bytes {
        return Err(PayloadError::NonCanonicalHeader);
    }
    let app_hash = AppHash::new(reader.read_array()?);
    let network_id = reader.read_array()?;
    let decision_height = i64::from_be_bytes(reader.read_array()?);
    let block_hash = reader.read_array()?;
    let next_validators_hash = reader.read_array()?;
    let record_count = reader.read_u32()?;
    if record_count as usize > MAX_BLOCK_RECORDS {
        return Err(PayloadError::TooManyRecords {
            actual: record_count as usize,
            maximum: MAX_BLOCK_RECORDS,
        });
    }
    let mut records = Vec::with_capacity(record_count as usize);
    for index in 0..record_count as usize {
        let record_length = reader.read_u32()?;
        if record_length > MAX_ENCODED_RECORD_LENGTH {
            return Err(PayloadError::RecordTooLarge {
                index,
                actual: record_length,
                maximum: MAX_ENCODED_RECORD_LENGTH,
            });
        }
        let record_bytes = reader.read_exact(record_length as usize)?;
        let record = TransactionRecord::decode(record_bytes)
            .map_err(|source| PayloadError::Record { index, source })?;
        if record.encode() != record_bytes {
            return Err(PayloadError::NonCanonicalRecord { index });
        }
        records.push(record);
    }
    reader.finish()?;
    validate_block(&header, &records).map_err(PayloadError::Block)?;
    Ok(StoredBlock {
        offset: 0,
        header,
        app_hash,
        comet_decision: CometBftDecision::from_persisted(
            network_id,
            decision_height,
            block_hash,
            next_validators_hash,
        )
        .map_err(PayloadError::EngineIdentity)?,
        records,
    })
}

fn validate_block(
    header: &BlockHeader,
    records: &[TransactionRecord],
) -> Result<(), BlockJournalError> {
    if records.len() != header.record_count() as usize {
        return Err(BlockJournalError::RecordCountMismatch {
            header: header.record_count(),
            payload: records.len(),
        });
    }
    let hashes: Vec<_> = records.iter().map(TransactionRecord::record_hash).collect();
    header
        .validate_record_hashes(&hashes)
        .map_err(BlockJournalError::Consensus)?;
    if let Some(first) = records.first() {
        if first.sequence() != header.first_record_sequence() {
            return Err(BlockJournalError::FirstRecordSequenceMismatch {
                header: header.first_record_sequence(),
                record: first.sequence(),
            });
        }
        if first.previous_state_id() != header.previous_state_id() {
            return Err(BlockJournalError::PreviousStateMismatch {
                record_index: 0,
                expected: header.previous_state_id(),
                actual: first.previous_state_id(),
            });
        }
        for (index, pair) in records.windows(2).enumerate() {
            let previous = &pair[0];
            let current = &pair[1];
            let expected_sequence = previous
                .sequence()
                .checked_add(1)
                .ok_or(BlockJournalError::RecordSequenceOverflow)?;
            if current.sequence() != expected_sequence {
                return Err(BlockJournalError::RecordSequenceMismatch {
                    record_index: index + 1,
                    expected: expected_sequence,
                    actual: current.sequence(),
                });
            }
            if current.previous_state_id() != previous.resulting_state_id() {
                return Err(BlockJournalError::PreviousStateMismatch {
                    record_index: index + 1,
                    expected: previous.resulting_state_id(),
                    actual: current.previous_state_id(),
                });
            }
        }
        let last = records.last().expect("first record proves a last record");
        if last.resulting_state_id() != header.resulting_state_id() {
            return Err(BlockJournalError::ResultingStateMismatch {
                expected: header.resulting_state_id(),
                actual: last.resulting_state_id(),
            });
        }
    } else if header.previous_state_id() != header.resulting_state_id() {
        return Err(BlockJournalError::EmptyBlockStateMismatch {
            previous: header.previous_state_id(),
            resulting: header.resulting_state_id(),
        });
    }
    Ok(())
}

fn open_file(path: &Path) -> Result<File, BlockJournalError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|source| BlockJournalError::Io {
            operation: "open block journal",
            source,
        })
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<(), BlockJournalError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| BlockJournalError::Io {
            operation: "sync new block-journal parent directory",
            source,
        })
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> Result<(), BlockJournalError> {
    Err(BlockJournalError::DirectorySyncUnavailable)
}

fn read_exact(file: &mut File, bytes: &mut [u8]) -> Result<(), BlockJournalError> {
    file.read_exact(bytes)
        .map_err(|source| BlockJournalError::Io {
            operation: "read block frame",
            source,
        })
}

struct PayloadReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> PayloadReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_u16(&mut self) -> Result<u16, PayloadError> {
        Ok(u16::from_be_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> Result<u32, PayloadError> {
        Ok(u32::from_be_bytes(self.read_array()?))
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], PayloadError> {
        self.read_exact(N)?
            .try_into()
            .map_err(|_| PayloadError::UnexpectedEnd {
                offset: self.offset,
            })
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], PayloadError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(PayloadError::LengthOverflow)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(PayloadError::UnexpectedEnd {
                offset: self.offset,
            })?;
        self.offset = end;
        Ok(bytes)
    }

    fn finish(self) -> Result<(), PayloadError> {
        let remaining = self.bytes.len().saturating_sub(self.offset);
        if remaining == 0 {
            Ok(())
        } else {
            Err(PayloadError::TrailingBytes { count: remaining })
        }
    }
}

/// Reasons a canonical `NXBP` payload is invalid inside an otherwise intact
/// `NXCB` frame.
#[derive(Debug)]
pub enum PayloadError {
    InvalidPayloadMagic,
    UnsupportedPayloadVersion(u16),
    HeaderTooLarge {
        actual: u32,
        maximum: u32,
    },
    TooManyRecords {
        actual: usize,
        maximum: usize,
    },
    RecordTooLarge {
        index: usize,
        actual: u32,
        maximum: u32,
    },
    UnexpectedEnd {
        offset: usize,
    },
    LengthOverflow,
    TrailingBytes {
        count: usize,
    },
    Consensus(ConsensusError),
    EngineIdentity(noxis_consensus::EngineIdentityError),
    NonCanonicalHeader,
    Record {
        index: usize,
        source: RecordError,
    },
    NonCanonicalRecord {
        index: usize,
    },
    Block(BlockJournalError),
}

impl fmt::Display for PayloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPayloadMagic => formatter.write_str("invalid block payload magic"),
            Self::UnsupportedPayloadVersion(version) => {
                write!(formatter, "unsupported block payload version {version}")
            }
            Self::HeaderTooLarge { actual, maximum } => write!(
                formatter,
                "block header length {actual} exceeds maximum {maximum}"
            ),
            Self::TooManyRecords { actual, maximum } => {
                write!(
                    formatter,
                    "block payload has {actual} records, above maximum {maximum}"
                )
            }
            Self::RecordTooLarge {
                index,
                actual,
                maximum,
            } => write!(
                formatter,
                "record {index} length {actual} exceeds maximum {maximum}"
            ),
            Self::UnexpectedEnd { offset } => {
                write!(
                    formatter,
                    "unexpected end of block payload at offset {offset}"
                )
            }
            Self::LengthOverflow => formatter.write_str("block payload length overflow"),
            Self::TrailingBytes { count } => {
                write!(formatter, "block payload has {count} trailing bytes")
            }
            Self::Consensus(source) => write!(formatter, "invalid block header: {source}"),
            Self::EngineIdentity(source) => {
                write!(formatter, "invalid persisted CometBFT decision: {source}")
            }
            Self::NonCanonicalHeader => formatter.write_str("noncanonical block header"),
            Self::Record { index, source } => write!(formatter, "invalid record {index}: {source}"),
            Self::NonCanonicalRecord { index } => {
                write!(formatter, "noncanonical record {index}")
            }
            Self::Block(source) => write!(formatter, "invalid block contents: {source}"),
        }
    }
}

impl std::error::Error for PayloadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Consensus(source) => Some(source),
            Self::EngineIdentity(source) => Some(source),
            Self::Record { source, .. } => Some(source),
            Self::Block(source) => Some(source),
            _ => None,
        }
    }
}

/// Reasons a block journal cannot be safely opened or written.
#[derive(Debug)]
pub enum BlockJournalError {
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
    Payload {
        offset: u64,
        source: Box<PayloadError>,
    },
    Consensus(ConsensusError),
    RecordCountMismatch {
        header: u32,
        payload: usize,
    },
    FirstRecordSequenceMismatch {
        header: u64,
        record: u64,
    },
    RecordSequenceMismatch {
        record_index: usize,
        expected: u64,
        actual: u64,
    },
    RecordSequenceOverflow,
    PreviousStateMismatch {
        record_index: usize,
        expected: StateId,
        actual: StateId,
    },
    ResultingStateMismatch {
        expected: StateId,
        actual: StateId,
    },
    EmptyBlockStateMismatch {
        previous: StateId,
        resulting: StateId,
    },
    OffsetOverflow,
    PayloadLengthOverflow,
    RecoveryTailChanged,
    DirectorySyncUnavailable,
}

impl fmt::Display for BlockJournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, source } => write!(formatter, "{operation}: {source}"),
            Self::InvalidMagic { offset } => {
                write!(formatter, "invalid block frame magic at offset {offset}")
            }
            Self::UnsupportedFrameVersion { offset, version } => write!(
                formatter,
                "unsupported block frame version {version} at offset {offset}"
            ),
            Self::FrameTooLarge {
                offset,
                actual,
                maximum,
            } => write!(
                formatter,
                "block frame at offset {offset} has length {actual}, above limit {maximum}"
            ),
            Self::TruncatedFrame { offset, section } => write!(
                formatter,
                "truncated {section} for block frame at offset {offset}"
            ),
            Self::ChecksumMismatch {
                offset,
                expected,
                actual,
            } => write!(
                formatter,
                "block frame checksum mismatch at offset {offset}: expected {expected:08x}, got {actual:08x}"
            ),
            Self::Payload { offset, source } => {
                write!(
                    formatter,
                    "invalid block payload at offset {offset}: {source}"
                )
            }
            Self::Consensus(source) => write!(formatter, "invalid block contents: {source}"),
            Self::RecordCountMismatch { header, payload } => write!(
                formatter,
                "block header declares {header} records but payload contains {payload}"
            ),
            Self::FirstRecordSequenceMismatch { header, record } => write!(
                formatter,
                "block header first record sequence {header} does not match record sequence {record}"
            ),
            Self::RecordSequenceMismatch {
                record_index,
                expected,
                actual,
            } => write!(
                formatter,
                "record {record_index} has sequence {actual}, expected {expected}"
            ),
            Self::RecordSequenceOverflow => formatter.write_str("block record sequence overflow"),
            Self::PreviousStateMismatch {
                record_index,
                expected,
                actual,
            } => write!(
                formatter,
                "record {record_index} has previous state {actual}, expected {expected}"
            ),
            Self::ResultingStateMismatch { expected, actual } => write!(
                formatter,
                "last block record results in state {actual}, expected {expected}"
            ),
            Self::EmptyBlockStateMismatch {
                previous,
                resulting,
            } => write!(
                formatter,
                "empty block changes state from {previous} to {resulting}"
            ),
            Self::OffsetOverflow => formatter.write_str("block journal offset overflow"),
            Self::PayloadLengthOverflow => formatter.write_str("block payload length overflow"),
            Self::RecoveryTailChanged => formatter.write_str(
                "block journal changed after recovery scan; refusing to truncate its tail",
            ),
            Self::DirectorySyncUnavailable => formatter.write_str(
                "this platform cannot durably synchronize creation of a new block journal",
            ),
        }
    }
}

impl std::error::Error for BlockJournalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Payload { source, .. } => Some(source),
            Self::Consensus(source) => Some(source),
            _ => None,
        }
    }
}
