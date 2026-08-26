//! Strict, hash-addressed transaction records linked through state identifiers.
//!
//! A record is a durable representation of one canonical transaction and its
//! claimed state transition. The `RecordChain` verifies sequence and state-link
//! continuity; it does not perform ledger validation, proof verification, or
//! consensus, which remain separate responsibilities.

use std::fmt;

use noxis_codec::{CodecError, decode_transaction, encode_transaction, transaction_intent_id};
use noxis_types::{StateId, TransactionIntentId};
use sha2::{Digest, Sha256};

/// Prefix identifying a record-chain wire message.
pub const RECORD_MAGIC: [u8; 4] = *b"NXRC";
/// Only record format currently accepted.
pub const RECORD_FORMAT_VERSION: u16 = 1;
/// Upper bound on canonical transaction bytes held by one record.
pub const MAX_RECORD_TRANSACTION_BYTES: u32 = 32 * 1024 * 1024;

const RECORD_HASH_DOMAIN: &[u8] = b"NOXIS/RECORD-CHAIN/V1/RECORD";
const RECORD_FIXED_PREFIX_BYTES: usize = 4 + 2 + 8 + 32 + 4;
const RECORD_FIXED_SUFFIX_BYTES: usize = 32 + 32 + 32;

/// Typed SHA-256 identifier of a complete, validated record.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RecordHash([u8; 32]);

impl RecordHash {
    /// Reconstructs a hash previously read from a canonical record or checkpoint.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical record digest bytes.
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// A canonical transaction plus its ordered state-transition metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionRecord {
    sequence: u64,
    previous_state_id: StateId,
    transaction_bytes: Vec<u8>,
    transaction_intent_id: TransactionIntentId,
    resulting_state_id: StateId,
    record_hash: RecordHash,
}

impl TransactionRecord {
    /// Constructs a record from canonical transaction bytes.
    ///
    /// The transaction is decoded and re-encoded, so callers cannot place a
    /// noncanonical representation or an unrelated transaction intent ID in a record.
    pub fn new(
        sequence: u64,
        previous_state_id: StateId,
        transaction_bytes: Vec<u8>,
        resulting_state_id: StateId,
    ) -> Result<Self, RecordError> {
        validate_transaction_bytes(&transaction_bytes)?;
        let transaction =
            decode_transaction(&transaction_bytes).map_err(RecordError::Transaction)?;
        let transaction_intent_id =
            transaction_intent_id(&transaction).map_err(RecordError::Transaction)?;
        let record_hash = hash_record(
            sequence,
            previous_state_id,
            &transaction_bytes,
            transaction_intent_id,
            resulting_state_id,
        );
        Ok(Self {
            sequence,
            previous_state_id,
            transaction_bytes,
            transaction_intent_id,
            resulting_state_id,
            record_hash,
        })
    }

    /// Monotonically increasing position in a state record chain.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// State identifier the transaction claims to extend.
    pub const fn previous_state_id(&self) -> StateId {
        self.previous_state_id
    }

    /// Strictly canonical transaction wire bytes.
    pub fn transaction_bytes(&self) -> &[u8] {
        &self.transaction_bytes
    }

    /// Non-self-referential identity computed from the transaction intent.
    pub const fn transaction_intent_id(&self) -> TransactionIntentId {
        self.transaction_intent_id
    }

    /// State identifier produced after applying the transaction.
    pub const fn resulting_state_id(&self) -> StateId {
        self.resulting_state_id
    }

    /// SHA-256 identifier computed over all wire fields excluding itself.
    pub const fn record_hash(&self) -> RecordHash {
        self.record_hash
    }

    /// Encodes the one accepted byte representation of this record.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            RECORD_FIXED_PREFIX_BYTES + self.transaction_bytes.len() + RECORD_FIXED_SUFFIX_BYTES,
        );
        bytes.extend_from_slice(&RECORD_MAGIC);
        bytes.extend_from_slice(&RECORD_FORMAT_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&self.previous_state_id.0);
        bytes.extend_from_slice(&(self.transaction_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.transaction_bytes);
        bytes.extend_from_slice(&self.transaction_intent_id.0);
        bytes.extend_from_slice(&self.resulting_state_id.0);
        bytes.extend_from_slice(&self.record_hash.0);
        bytes
    }

    /// Decodes exactly one strict record and verifies its transaction and hash.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut reader = Reader::new(bytes);
        if reader.read_array::<4>()? != RECORD_MAGIC {
            return Err(RecordError::InvalidMagic);
        }
        let version = reader.read_u16()?;
        if version != RECORD_FORMAT_VERSION {
            return Err(RecordError::UnsupportedFormatVersion(version));
        }
        let sequence = reader.read_u64()?;
        let previous_state_id = StateId::new(reader.read_array()?);
        let transaction_length = reader.read_u32()?;
        if transaction_length > MAX_RECORD_TRANSACTION_BYTES {
            return Err(RecordError::TransactionBytesTooLarge {
                actual: transaction_length as usize,
                maximum: MAX_RECORD_TRANSACTION_BYTES,
            });
        }
        let transaction_bytes = reader.read_exact(transaction_length as usize)?.to_vec();
        let stored_transaction_intent_id = TransactionIntentId::new(reader.read_array()?);
        let resulting_state_id = StateId::new(reader.read_array()?);
        let record_hash = RecordHash(reader.read_array()?);
        reader.finish()?;

        validate_transaction_bytes(&transaction_bytes)?;
        let decoded_transaction =
            decode_transaction(&transaction_bytes).map_err(RecordError::Transaction)?;
        let calculated_intent_id =
            transaction_intent_id(&decoded_transaction).map_err(RecordError::Transaction)?;
        if calculated_intent_id != stored_transaction_intent_id {
            return Err(RecordError::TransactionIntentIdMismatch {
                record: stored_transaction_intent_id,
                transaction: calculated_intent_id,
            });
        }
        let expected_hash = hash_record(
            sequence,
            previous_state_id,
            &transaction_bytes,
            stored_transaction_intent_id,
            resulting_state_id,
        );
        if record_hash != expected_hash {
            return Err(RecordError::RecordHashMismatch);
        }
        Ok(Self {
            sequence,
            previous_state_id,
            transaction_bytes,
            transaction_intent_id: stored_transaction_intent_id,
            resulting_state_id,
            record_hash,
        })
    }
}

/// Mutable verifier for one ordered state-transition record chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordChain {
    next_sequence: u64,
    current_state_id: StateId,
}

impl RecordChain {
    /// Starts a chain at a caller-defined genesis state identifier.
    pub const fn new(genesis_state_id: StateId) -> Self {
        Self {
            next_sequence: 1,
            current_state_id: genesis_state_id,
        }
    }

    /// Sequence number required for the next record.
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// State identifier required as the next record's predecessor.
    pub const fn current_state_id(&self) -> StateId {
        self.current_state_id
    }

    /// Sequence number of the current state. Genesis is sequence zero.
    pub const fn current_sequence(&self) -> u64 {
        self.next_sequence - 1
    }

    /// Validates one link then advances the chain to the record's result.
    pub fn apply(&mut self, record: &TransactionRecord) -> Result<(), RecordError> {
        if record.sequence != self.next_sequence {
            return Err(RecordError::UnexpectedSequence {
                expected: self.next_sequence,
                actual: record.sequence,
            });
        }
        if record.previous_state_id != self.current_state_id {
            return Err(RecordError::PreviousStateMismatch {
                expected: self.current_state_id,
                actual: record.previous_state_id,
            });
        }
        let next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(RecordError::SequenceOverflow)?;
        self.current_state_id = record.resulting_state_id;
        self.next_sequence = next_sequence;
        Ok(())
    }
}

fn validate_transaction_bytes(bytes: &[u8]) -> Result<(), RecordError> {
    if bytes.len() > MAX_RECORD_TRANSACTION_BYTES as usize {
        return Err(RecordError::TransactionBytesTooLarge {
            actual: bytes.len(),
            maximum: MAX_RECORD_TRANSACTION_BYTES,
        });
    }
    let transaction = decode_transaction(bytes).map_err(RecordError::Transaction)?;
    let canonical = encode_transaction(&transaction).map_err(RecordError::Transaction)?;
    if canonical != bytes {
        return Err(RecordError::NonCanonicalTransaction);
    }
    Ok(())
}

fn hash_record(
    sequence: u64,
    previous_state_id: StateId,
    transaction_bytes: &[u8],
    transaction_intent_id: TransactionIntentId,
    resulting_state_id: StateId,
) -> RecordHash {
    let mut hasher = Sha256::new();
    hasher.update(RECORD_HASH_DOMAIN);
    hasher.update(RECORD_FORMAT_VERSION.to_be_bytes());
    hasher.update(sequence.to_be_bytes());
    hasher.update(previous_state_id.0);
    hasher.update((transaction_bytes.len() as u32).to_be_bytes());
    hasher.update(transaction_bytes);
    hasher.update(transaction_intent_id.0);
    hasher.update(resulting_state_id.0);
    RecordHash(hasher.finalize().into())
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_u16(&mut self) -> Result<u16, RecordError> {
        Ok(u16::from_be_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> Result<u32, RecordError> {
        Ok(u32::from_be_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> Result<u64, RecordError> {
        Ok(u64::from_be_bytes(self.read_array()?))
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], RecordError> {
        self.read_exact(N)?
            .try_into()
            .map_err(|_| RecordError::UnexpectedEnd {
                offset: self.offset,
            })
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], RecordError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(RecordError::LengthOverflow)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(RecordError::UnexpectedEnd {
                offset: self.offset,
            })?;
        self.offset = end;
        Ok(slice)
    }

    fn finish(self) -> Result<(), RecordError> {
        let remaining = self.bytes.len().saturating_sub(self.offset);
        if remaining == 0 {
            Ok(())
        } else {
            Err(RecordError::TrailingBytes { count: remaining })
        }
    }
}

/// Reasons a record cannot be encoded, decoded, or linked safely.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordError {
    InvalidMagic,
    UnsupportedFormatVersion(u16),
    UnexpectedEnd {
        offset: usize,
    },
    TrailingBytes {
        count: usize,
    },
    LengthOverflow,
    TransactionBytesTooLarge {
        actual: usize,
        maximum: u32,
    },
    Transaction(CodecError),
    NonCanonicalTransaction,
    TransactionIntentIdMismatch {
        record: TransactionIntentId,
        transaction: TransactionIntentId,
    },
    RecordHashMismatch,
    UnexpectedSequence {
        expected: u64,
        actual: u64,
    },
    PreviousStateMismatch {
        expected: StateId,
        actual: StateId,
    },
    SequenceOverflow,
}

impl fmt::Display for RecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => formatter.write_str("invalid record magic bytes"),
            Self::UnsupportedFormatVersion(version) => {
                write!(formatter, "unsupported record format version {version}")
            }
            Self::UnexpectedEnd { offset } => {
                write!(formatter, "unexpected end of record at byte {offset}")
            }
            Self::TrailingBytes { count } => {
                write!(formatter, "record has {count} trailing byte(s)")
            }
            Self::LengthOverflow => formatter.write_str("record length overflows platform bounds"),
            Self::TransactionBytesTooLarge { actual, maximum } => write!(
                formatter,
                "transaction byte length {actual} exceeds record maximum {maximum}"
            ),
            Self::Transaction(error) => write!(formatter, "invalid transaction bytes: {error}"),
            Self::NonCanonicalTransaction => {
                formatter.write_str("transaction bytes are not canonical")
            }
            Self::TransactionIntentIdMismatch { .. } => {
                formatter.write_str("record transaction intent ID does not match transaction bytes")
            }
            Self::RecordHashMismatch => {
                formatter.write_str("record hash does not match record fields")
            }
            Self::UnexpectedSequence { expected, actual } => {
                write!(
                    formatter,
                    "expected record sequence {expected}, received {actual}"
                )
            }
            Self::PreviousStateMismatch { .. } => {
                formatter.write_str("record does not extend the current state identifier")
            }
            Self::SequenceOverflow => {
                formatter.write_str("record sequence cannot advance past u64::MAX")
            }
        }
    }
}

impl std::error::Error for RecordError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transaction(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use noxis_crypto::{CryptoSuite, Proof};
    use noxis_ledger::{Operation, Transaction, Transfer};
    use noxis_types::{AssetId, Commitment, Nullifier, TransactionId};

    use super::*;

    fn transaction_bytes(id: u8) -> Vec<u8> {
        let transaction = Transaction {
            id: TransactionId::new([id; 32]),
            suite: CryptoSuite::RESEARCH_V1,
            operation: Operation::Transfer(Transfer {
                asset_id: AssetId::new([2; 32]),
                input_nullifiers: vec![Nullifier::new([3; 32])],
                output_commitments: vec![Commitment::new([4; 32])],
                proof: Proof {
                    suite_version: 1,
                    bytes: vec![5],
                },
            }),
        };
        encode_transaction(&transaction).unwrap()
    }

    fn record(sequence: u64, previous: u8, resulting: u8, transaction: u8) -> TransactionRecord {
        TransactionRecord::new(
            sequence,
            StateId::new([previous; 32]),
            transaction_bytes(transaction),
            StateId::new([resulting; 32]),
        )
        .unwrap()
    }

    #[test]
    fn record_round_trip_is_exact_and_hash_is_stable() {
        let record = record(1, 0, 1, 9);
        let encoded = record.encode();
        let decoded = TransactionRecord::decode(&encoded).unwrap();
        assert_eq!(decoded, record);
        assert_eq!(decoded.encode(), encoded);
        assert_eq!(decoded.record_hash(), record.record_hash());
    }

    #[test]
    fn rejects_tampered_transaction_intent_id_hash_and_trailing_bytes() {
        let record = record(1, 0, 1, 9);
        let mut wrong_id = record.encode();
        let id_offset = RECORD_FIXED_PREFIX_BYTES + record.transaction_bytes().len();
        wrong_id[id_offset] ^= 1;
        assert!(matches!(
            TransactionRecord::decode(&wrong_id),
            Err(RecordError::TransactionIntentIdMismatch { .. })
        ));

        let mut wrong_hash = record.encode();
        let hash_offset = wrong_hash.len() - 1;
        wrong_hash[hash_offset] ^= 1;
        assert_eq!(
            TransactionRecord::decode(&wrong_hash),
            Err(RecordError::RecordHashMismatch)
        );

        let mut trailing = record.encode();
        trailing.push(0);
        assert_eq!(
            TransactionRecord::decode(&trailing),
            Err(RecordError::TrailingBytes { count: 1 })
        );
    }

    #[test]
    fn rejects_oversized_length_before_allocation() {
        let mut encoded = record(1, 0, 1, 9).encode();
        let length_offset = 4 + 2 + 8 + 32;
        encoded[length_offset..length_offset + 4]
            .copy_from_slice(&(MAX_RECORD_TRANSACTION_BYTES + 1).to_be_bytes());
        assert_eq!(
            TransactionRecord::decode(&encoded),
            Err(RecordError::TransactionBytesTooLarge {
                actual: (MAX_RECORD_TRANSACTION_BYTES + 1) as usize,
                maximum: MAX_RECORD_TRANSACTION_BYTES,
            })
        );
    }

    #[test]
    fn chain_requires_contiguous_sequence_and_state() {
        let mut chain = RecordChain::new(StateId::new([0; 32]));
        let first = record(1, 0, 1, 10);
        chain.apply(&first).unwrap();
        let second = record(2, 1, 2, 11);
        chain.apply(&second).unwrap();
        assert_eq!(chain.current_state_id(), StateId::new([2; 32]));

        assert_eq!(
            chain.apply(&record(4, 2, 3, 12)),
            Err(RecordError::UnexpectedSequence {
                expected: 3,
                actual: 4,
            })
        );
        assert_eq!(
            chain.apply(&record(3, 99, 3, 12)),
            Err(RecordError::PreviousStateMismatch {
                expected: StateId::new([2; 32]),
                actual: StateId::new([99; 32]),
            })
        );
    }

    #[test]
    fn rejects_unknown_record_version() {
        let mut encoded = record(1, 0, 1, 9).encode();
        encoded[4] = 0;
        encoded[5] = 2;
        assert_eq!(
            TransactionRecord::decode(&encoded),
            Err(RecordError::UnsupportedFormatVersion(2))
        );
    }
}
