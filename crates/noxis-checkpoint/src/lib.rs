//! Canonical, self-validating Noxis ledger checkpoints.
//!
//! `NXCP` stores a complete logical [`LedgerSnapshot`] at one specific `NXRC`
//! record. It detects accidental corruption and mismatched deployment identity;
//! it is not an authenticated history attestation. Storage recovery therefore
//! must not skip validation of the preceding record history merely because an
//! `NXCP` file exists.

use std::fmt;

use noxis_ledger::{LedgerSnapshot, LedgerSnapshotError, LedgerState};
use noxis_record_chain::RecordHash;
use noxis_types::{
    Amount, AssetDefinition, AssetId, AssetKind, ChainAnchor, Commitment, GenesisId, Nullifier,
    StateId, TransactionId, ValidationContextId,
};
use sha2::{Digest, Sha256};

/// Magic bytes identifying a Noxis checkpoint.
pub const CHECKPOINT_MAGIC: [u8; 4] = *b"NXCP";
/// The only checkpoint layout supported by this release.
pub const CHECKPOINT_FORMAT_VERSION: u16 = 1;
/// The only canonical snapshot layout carried by this checkpoint format.
pub const SNAPSHOT_FORMAT_VERSION: u16 = 1;
/// Largest accepted checkpoint snapshot, before any dynamic allocation.
pub const MAX_SNAPSHOT_BYTES: u32 = 128 * 1024 * 1024;
/// Largest complete checkpoint file, including fixed headers and hashes.
pub const MAX_CHECKPOINT_BYTES: usize =
    HEADER_BYTES + MAX_SNAPSHOT_BYTES as usize + CHECKPOINT_HASH_BYTES;
/// Largest number of registered assets in one checkpoint.
pub const MAX_SNAPSHOT_ASSETS: u32 = 4_096;
/// Largest number of entries in one identifier collection.
pub const MAX_SNAPSHOT_IDENTIFIERS: u32 = noxis_merkle::MAX_COMMITMENTS as u32;

const SNAPSHOT_HASH_DOMAIN: &[u8] = b"NOXIS/CHECKPOINT/V1/SNAPSHOT\0";
const CHECKPOINT_HASH_DOMAIN: &[u8] = b"NOXIS/CHECKPOINT/V1\0";
const HEADER_BYTES: usize = 180;
const CHECKPOINT_HASH_BYTES: usize = 32;
const MAX_TICKER_BYTES: usize = 16;

/// Complete, immutable state captured at a specific durable record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    genesis_id: GenesisId,
    validation_context_id: ValidationContextId,
    sequence: u64,
    state_id: StateId,
    terminal_record_hash: RecordHash,
    snapshot: LedgerSnapshot,
}

impl Checkpoint {
    /// Captures a state that was just known to follow `terminal_record_hash`.
    ///
    /// Checkpoints at genesis are intentionally unsupported because no
    /// terminal transition record exists to bind them to the durable history.
    pub fn from_snapshot(
        anchor: ChainAnchor,
        sequence: u64,
        terminal_record_hash: RecordHash,
        snapshot: LedgerSnapshot,
    ) -> Result<Self, CheckpointError> {
        if sequence == 0 {
            return Err(CheckpointError::GenesisCheckpointUnsupported);
        }
        if snapshot.accepted_transactions().len() as u64 != sequence {
            return Err(CheckpointError::SnapshotSequenceMismatch {
                sequence,
                accepted_transactions: snapshot.accepted_transactions().len(),
            });
        }
        validate_snapshot_bounds(&snapshot)?;
        let state = LedgerState::from_snapshot(snapshot.clone())
            .map_err(CheckpointError::InvalidSnapshot)?;
        let state_id = state.state_id(anchor.genesis_id);
        Ok(Self {
            genesis_id: anchor.genesis_id,
            validation_context_id: anchor.validation_context_id,
            sequence,
            state_id,
            terminal_record_hash,
            snapshot,
        })
    }

    /// Restores the complete state after checking this checkpoint's deployment
    /// identity and deterministic state identifier.
    pub fn restore_state(&self, anchor: ChainAnchor) -> Result<LedgerState, CheckpointError> {
        if self.genesis_id != anchor.genesis_id
            || self.validation_context_id != anchor.validation_context_id
        {
            return Err(CheckpointError::AnchorMismatch(Box::new(
                CheckpointAnchorMismatch {
                    checkpoint_genesis: self.genesis_id,
                    configured_genesis: anchor.genesis_id,
                    checkpoint_context: self.validation_context_id,
                    configured_context: anchor.validation_context_id,
                },
            )));
        }
        let state = LedgerState::from_snapshot(self.snapshot.clone())
            .map_err(CheckpointError::InvalidSnapshot)?;
        let computed = state.state_id(anchor.genesis_id);
        if computed != self.state_id {
            return Err(CheckpointError::StateIdMismatch {
                encoded: self.state_id,
                computed,
            });
        }
        Ok(state)
    }

    pub const fn genesis_id(&self) -> GenesisId {
        self.genesis_id
    }

    pub const fn validation_context_id(&self) -> ValidationContextId {
        self.validation_context_id
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn state_id(&self) -> StateId {
        self.state_id
    }

    pub const fn terminal_record_hash(&self) -> RecordHash {
        self.terminal_record_hash
    }

    pub fn snapshot(&self) -> &LedgerSnapshot {
        &self.snapshot
    }

    /// Encodes the sole accepted `NXCP` representation.
    pub fn encode(&self) -> Vec<u8> {
        let snapshot_bytes = encode_snapshot(&self.snapshot)
            .expect("checkpoint construction validates all snapshot limits");
        let snapshot_hash = hash_snapshot(&snapshot_bytes);
        let mut bytes =
            Vec::with_capacity(HEADER_BYTES + snapshot_bytes.len() + CHECKPOINT_HASH_BYTES);
        bytes.extend_from_slice(&CHECKPOINT_MAGIC);
        bytes.extend_from_slice(&CHECKPOINT_FORMAT_VERSION.to_be_bytes());
        bytes.extend_from_slice(&SNAPSHOT_FORMAT_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.genesis_id.0);
        bytes.extend_from_slice(&self.validation_context_id.0);
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&self.state_id.0);
        bytes.extend_from_slice(&self.terminal_record_hash.as_bytes());
        bytes.extend_from_slice(&(snapshot_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&snapshot_hash);
        bytes.extend_from_slice(&snapshot_bytes);
        bytes.extend_from_slice(&hash_checkpoint(&bytes));
        bytes
    }

    /// Decodes, bounds-checks and fully reconstructs one canonical checkpoint.
    pub fn decode(bytes: &[u8]) -> Result<Self, CheckpointError> {
        if bytes.len() < HEADER_BYTES + CHECKPOINT_HASH_BYTES {
            return Err(CheckpointError::UnexpectedEnd {
                offset: bytes.len(),
            });
        }
        let (without_hash, encoded_hash) = bytes.split_at(bytes.len() - CHECKPOINT_HASH_BYTES);
        let encoded_hash: [u8; CHECKPOINT_HASH_BYTES] = encoded_hash
            .try_into()
            .expect("split checkpoint hash has fixed length");
        let computed_hash = hash_checkpoint(without_hash);
        if encoded_hash != computed_hash {
            return Err(CheckpointError::CheckpointHashMismatch);
        }

        let mut reader = Reader::new(without_hash);
        if reader.read_array::<4>()? != CHECKPOINT_MAGIC {
            return Err(CheckpointError::InvalidMagic);
        }
        let format_version = reader.read_u16()?;
        if format_version != CHECKPOINT_FORMAT_VERSION {
            return Err(CheckpointError::UnsupportedFormatVersion(format_version));
        }
        let snapshot_version = reader.read_u16()?;
        if snapshot_version != SNAPSHOT_FORMAT_VERSION {
            return Err(CheckpointError::UnsupportedSnapshotVersion(
                snapshot_version,
            ));
        }
        let genesis_id = GenesisId::new(reader.read_array()?);
        let validation_context_id = ValidationContextId::new(reader.read_array()?);
        let sequence = reader.read_u64()?;
        if sequence == 0 {
            return Err(CheckpointError::GenesisCheckpointUnsupported);
        }
        let state_id = StateId::new(reader.read_array()?);
        let terminal_record_hash = RecordHash::from_bytes(reader.read_array()?);
        let snapshot_length = reader.read_u32()?;
        if snapshot_length > MAX_SNAPSHOT_BYTES {
            return Err(CheckpointError::SnapshotTooLarge {
                actual: snapshot_length as usize,
                maximum: MAX_SNAPSHOT_BYTES,
            });
        }
        let encoded_snapshot_hash = reader.read_array::<32>()?;
        let snapshot_bytes = reader.read_exact(snapshot_length as usize)?;
        if encoded_snapshot_hash != hash_snapshot(snapshot_bytes) {
            return Err(CheckpointError::SnapshotHashMismatch);
        }
        reader.finish()?;
        let snapshot = decode_snapshot(snapshot_bytes)?;
        if snapshot.accepted_transactions().len() as u64 != sequence {
            return Err(CheckpointError::SnapshotSequenceMismatch {
                sequence,
                accepted_transactions: snapshot.accepted_transactions().len(),
            });
        }
        let state = LedgerState::from_snapshot(snapshot.clone())
            .map_err(CheckpointError::InvalidSnapshot)?;
        let computed_state_id = state.state_id(genesis_id);
        if computed_state_id != state_id {
            return Err(CheckpointError::StateIdMismatch {
                encoded: state_id,
                computed: computed_state_id,
            });
        }
        let checkpoint = Self {
            genesis_id,
            validation_context_id,
            sequence,
            state_id,
            terminal_record_hash,
            snapshot,
        };
        if checkpoint.encode() != bytes {
            return Err(CheckpointError::NonCanonicalEncoding);
        }
        Ok(checkpoint)
    }
}

fn encode_snapshot(snapshot: &LedgerSnapshot) -> Result<Vec<u8>, CheckpointError> {
    validate_snapshot_bounds(snapshot)?;
    let mut bytes = Vec::new();
    bytes.push(snapshot.tree_depth());
    write_count(&mut bytes, snapshot.assets().len())?;
    for asset in snapshot.assets() {
        bytes.extend_from_slice(&asset.id.0);
        bytes.push(encode_asset_kind(asset.kind));
        bytes.push(asset.ticker.len() as u8);
        bytes.extend_from_slice(asset.ticker.as_bytes());
    }
    write_count(&mut bytes, snapshot.commitments().len())?;
    for commitment in snapshot.commitments() {
        bytes.extend_from_slice(&commitment.0);
    }
    write_count(&mut bytes, snapshot.spent_nullifiers().len())?;
    for nullifier in snapshot.spent_nullifiers() {
        bytes.extend_from_slice(&nullifier.0);
    }
    write_count(&mut bytes, snapshot.issued_supply().len())?;
    for (asset_id, amount) in snapshot.issued_supply() {
        bytes.extend_from_slice(&asset_id.0);
        bytes.extend_from_slice(&amount.units().to_be_bytes());
    }
    write_count(&mut bytes, snapshot.accepted_transactions().len())?;
    for transaction_id in snapshot.accepted_transactions() {
        bytes.extend_from_slice(&transaction_id.0);
    }
    if bytes.len() > MAX_SNAPSHOT_BYTES as usize {
        return Err(CheckpointError::SnapshotTooLarge {
            actual: bytes.len(),
            maximum: MAX_SNAPSHOT_BYTES,
        });
    }
    Ok(bytes)
}

fn decode_snapshot(bytes: &[u8]) -> Result<LedgerSnapshot, CheckpointError> {
    let mut reader = SnapshotReader::new(bytes);
    let tree_depth = reader.read_u8()?;
    let asset_count = reader.read_count(MAX_SNAPSHOT_ASSETS)?;
    let mut assets = Vec::with_capacity(asset_count);
    for index in 0..asset_count {
        let id = AssetId::new(reader.read_array()?);
        let kind = decode_asset_kind(reader.read_u8()?)?;
        let ticker_length = reader.read_u8()? as usize;
        if ticker_length > MAX_TICKER_BYTES {
            return Err(CheckpointError::Snapshot(SnapshotError::TickerTooLong {
                index,
                actual: ticker_length,
            }));
        }
        let ticker = std::str::from_utf8(reader.read_exact(ticker_length)?).map_err(|_| {
            CheckpointError::Snapshot(SnapshotError::InvalidTickerEncoding { index })
        })?;
        let asset = AssetDefinition::new(id, ticker, kind).map_err(|source| {
            CheckpointError::Snapshot(SnapshotError::InvalidAsset { index, source })
        })?;
        assets.push(asset);
    }
    let commitments = read_identifiers(&mut reader, Commitment::new)?;
    let spent_nullifiers = read_identifiers(&mut reader, Nullifier::new)?;
    let supply_count = reader.read_count(MAX_SNAPSHOT_ASSETS)?;
    let mut issued_supply = Vec::with_capacity(supply_count);
    for _ in 0..supply_count {
        let asset_id = AssetId::new(reader.read_array()?);
        let amount = Amount::new(u128::from_be_bytes(reader.read_array()?))
            .ok_or(CheckpointError::Snapshot(SnapshotError::ZeroSupply))?;
        issued_supply.push((asset_id, amount));
    }
    let accepted_transactions = read_identifiers(&mut reader, TransactionId::new)?;
    reader.finish()?;
    LedgerSnapshot::from_canonical_parts(
        tree_depth,
        assets,
        commitments,
        spent_nullifiers,
        issued_supply,
        accepted_transactions,
    )
    .map_err(CheckpointError::InvalidSnapshot)
}

fn read_identifiers<T>(
    reader: &mut SnapshotReader<'_>,
    construct: impl Fn([u8; 32]) -> T,
) -> Result<Vec<T>, CheckpointError> {
    let count = reader.read_count(MAX_SNAPSHOT_IDENTIFIERS)?;
    let mut identifiers = Vec::with_capacity(count);
    for _ in 0..count {
        identifiers.push(construct(reader.read_array()?));
    }
    Ok(identifiers)
}

fn validate_snapshot_bounds(snapshot: &LedgerSnapshot) -> Result<(), CheckpointError> {
    ensure_count(snapshot.assets().len(), MAX_SNAPSHOT_ASSETS)?;
    ensure_count(snapshot.commitments().len(), MAX_SNAPSHOT_IDENTIFIERS)?;
    ensure_count(snapshot.spent_nullifiers().len(), MAX_SNAPSHOT_IDENTIFIERS)?;
    ensure_count(snapshot.issued_supply().len(), MAX_SNAPSHOT_ASSETS)?;
    ensure_count(
        snapshot.accepted_transactions().len(),
        MAX_SNAPSHOT_IDENTIFIERS,
    )?;
    Ok(())
}

fn ensure_count(actual: usize, maximum: u32) -> Result<(), CheckpointError> {
    if actual > maximum as usize {
        return Err(CheckpointError::CollectionTooLarge { actual, maximum });
    }
    Ok(())
}

fn write_count(bytes: &mut Vec<u8>, count: usize) -> Result<(), CheckpointError> {
    let count = u32::try_from(count).map_err(|_| CheckpointError::CollectionTooLarge {
        actual: count,
        maximum: u32::MAX,
    })?;
    bytes.extend_from_slice(&count.to_be_bytes());
    Ok(())
}

fn encode_asset_kind(kind: AssetKind) -> u8 {
    match kind {
        AssetKind::NativeBacked => 1,
        AssetKind::Synthetic => 2,
    }
}

fn decode_asset_kind(tag: u8) -> Result<AssetKind, CheckpointError> {
    match tag {
        1 => Ok(AssetKind::NativeBacked),
        2 => Ok(AssetKind::Synthetic),
        _ => Err(CheckpointError::Snapshot(SnapshotError::UnknownAssetKind(
            tag,
        ))),
    }
}

fn hash_snapshot(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SNAPSHOT_HASH_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn hash_checkpoint(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CHECKPOINT_HASH_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().into()
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_u16(&mut self) -> Result<u16, CheckpointError> {
        Ok(u16::from_be_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> Result<u32, CheckpointError> {
        Ok(u32::from_be_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> Result<u64, CheckpointError> {
        Ok(u64::from_be_bytes(self.read_array()?))
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], CheckpointError> {
        self.read_exact(N)?
            .try_into()
            .map_err(|_| CheckpointError::UnexpectedEnd {
                offset: self.offset,
            })
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], CheckpointError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(CheckpointError::LengthOverflow)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(CheckpointError::UnexpectedEnd {
                offset: self.offset,
            })?;
        self.offset = end;
        Ok(bytes)
    }

    fn finish(self) -> Result<(), CheckpointError> {
        let count = self.bytes.len().saturating_sub(self.offset);
        if count == 0 {
            Ok(())
        } else {
            Err(CheckpointError::TrailingBytes { count })
        }
    }
}

struct SnapshotReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SnapshotReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, CheckpointError> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u32(&mut self) -> Result<u32, CheckpointError> {
        Ok(u32::from_be_bytes(self.read_array()?))
    }

    fn read_count(&mut self, maximum: u32) -> Result<usize, CheckpointError> {
        let count = self.read_u32()?;
        if count > maximum {
            return Err(CheckpointError::Snapshot(
                SnapshotError::CollectionTooLarge {
                    actual: count,
                    maximum,
                },
            ));
        }
        Ok(count as usize)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], CheckpointError> {
        self.read_exact(N)?.try_into().map_err(|_| {
            CheckpointError::Snapshot(SnapshotError::UnexpectedEnd {
                offset: self.offset,
            })
        })
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], CheckpointError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(CheckpointError::LengthOverflow)?;
        let bytes = self.bytes.get(self.offset..end).ok_or({
            CheckpointError::Snapshot(SnapshotError::UnexpectedEnd {
                offset: self.offset,
            })
        })?;
        self.offset = end;
        Ok(bytes)
    }

    fn finish(self) -> Result<(), CheckpointError> {
        let count = self.bytes.len().saturating_sub(self.offset);
        if count == 0 {
            Ok(())
        } else {
            Err(CheckpointError::Snapshot(SnapshotError::TrailingBytes {
                count,
            }))
        }
    }
}

/// A reason a snapshot payload is not canonical or safe to reconstruct.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotError {
    UnexpectedEnd {
        offset: usize,
    },
    TrailingBytes {
        count: usize,
    },
    CollectionTooLarge {
        actual: u32,
        maximum: u32,
    },
    UnknownAssetKind(u8),
    TickerTooLong {
        index: usize,
        actual: usize,
    },
    InvalidTickerEncoding {
        index: usize,
    },
    InvalidAsset {
        index: usize,
        source: noxis_types::AssetError,
    },
    ZeroSupply,
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEnd { offset } => {
                write!(formatter, "checkpoint snapshot ends at byte {offset}")
            }
            Self::TrailingBytes { count } => {
                write!(formatter, "checkpoint snapshot has {count} trailing bytes")
            }
            Self::CollectionTooLarge { actual, maximum } => write!(
                formatter,
                "checkpoint collection has {actual} entries; maximum is {maximum}"
            ),
            Self::UnknownAssetKind(tag) => write!(
                formatter,
                "checkpoint snapshot has unknown asset kind {tag}"
            ),
            Self::TickerTooLong { index, actual } => write!(
                formatter,
                "checkpoint asset {index} ticker has {actual} bytes"
            ),
            Self::InvalidTickerEncoding { index } => {
                write!(formatter, "checkpoint asset {index} ticker is not UTF-8")
            }
            Self::InvalidAsset { index, source } => {
                write!(formatter, "checkpoint asset {index} is invalid: {source}")
            }
            Self::ZeroSupply => formatter.write_str("checkpoint snapshot contains zero supply"),
        }
    }
}

impl std::error::Error for SnapshotError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidAsset { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// A reason an `NXCP` file or checkpoint value cannot be trusted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CheckpointError {
    InvalidMagic,
    UnsupportedFormatVersion(u16),
    UnsupportedSnapshotVersion(u16),
    UnexpectedEnd {
        offset: usize,
    },
    TrailingBytes {
        count: usize,
    },
    LengthOverflow,
    SnapshotTooLarge {
        actual: usize,
        maximum: u32,
    },
    CollectionTooLarge {
        actual: usize,
        maximum: u32,
    },
    SnapshotHashMismatch,
    CheckpointHashMismatch,
    GenesisCheckpointUnsupported,
    SnapshotSequenceMismatch {
        sequence: u64,
        accepted_transactions: usize,
    },
    InvalidSnapshot(LedgerSnapshotError),
    Snapshot(SnapshotError),
    StateIdMismatch {
        encoded: StateId,
        computed: StateId,
    },
    AnchorMismatch(Box<CheckpointAnchorMismatch>),
    NonCanonicalEncoding,
}

/// The detailed identities involved in a checkpoint deployment mismatch.
///
/// This is boxed by [`CheckpointError`] so routine result values remain small
/// even though the diagnostic retains all four 32-byte identifiers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointAnchorMismatch {
    checkpoint_genesis: GenesisId,
    configured_genesis: GenesisId,
    checkpoint_context: ValidationContextId,
    configured_context: ValidationContextId,
}

impl fmt::Display for CheckpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => formatter.write_str("invalid checkpoint magic"),
            Self::UnsupportedFormatVersion(version) => {
                write!(formatter, "unsupported checkpoint format version {version}")
            }
            Self::UnsupportedSnapshotVersion(version) => write!(
                formatter,
                "unsupported checkpoint snapshot version {version}"
            ),
            Self::UnexpectedEnd { offset } => write!(formatter, "checkpoint ends at byte {offset}"),
            Self::TrailingBytes { count } => {
                write!(formatter, "checkpoint has {count} trailing bytes")
            }
            Self::LengthOverflow => {
                formatter.write_str("checkpoint length overflows addressable memory")
            }
            Self::SnapshotTooLarge { actual, maximum } => write!(
                formatter,
                "checkpoint snapshot has {actual} bytes; maximum is {maximum}"
            ),
            Self::CollectionTooLarge { actual, maximum } => write!(
                formatter,
                "checkpoint collection has {actual} entries; maximum is {maximum}"
            ),
            Self::SnapshotHashMismatch => {
                formatter.write_str("checkpoint snapshot hash does not match")
            }
            Self::CheckpointHashMismatch => formatter.write_str("checkpoint hash does not match"),
            Self::GenesisCheckpointUnsupported => formatter
                .write_str("a checkpoint cannot represent genesis without a terminal record"),
            Self::SnapshotSequenceMismatch {
                sequence,
                accepted_transactions,
            } => write!(
                formatter,
                "checkpoint sequence {sequence} does not match {accepted_transactions} accepted transactions"
            ),
            Self::InvalidSnapshot(error) => {
                write!(formatter, "invalid checkpoint snapshot: {error}")
            }
            Self::Snapshot(error) => {
                write!(formatter, "invalid checkpoint snapshot encoding: {error}")
            }
            Self::StateIdMismatch { .. } => {
                formatter.write_str("checkpoint state identifier does not match its snapshot")
            }
            Self::AnchorMismatch(_) => formatter.write_str(
                "checkpoint deployment identity does not match the configured chain anchor",
            ),
            Self::NonCanonicalEncoding => {
                formatter.write_str("checkpoint encoding is not canonical")
            }
        }
    }
}

impl std::error::Error for CheckpointError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidSnapshot(error) => Some(error),
            Self::Snapshot(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noxis_types::{MintPolicyId, ProofVerifierId};

    fn anchor() -> ChainAnchor {
        ChainAnchor::new(
            GenesisId::new([1; 32]),
            ValidationContextId::new([2; 32]),
            ProofVerifierId::new([3; 32]),
            MintPolicyId::new([4; 32]),
            StateId::new([5; 32]),
        )
    }

    fn snapshot() -> LedgerSnapshot {
        LedgerSnapshot::from_canonical_parts(
            8,
            vec![
                AssetDefinition::new(AssetId::new([9; 32]), "USDX", AssetKind::Synthetic).unwrap(),
            ],
            vec![Commitment::new([10; 32])],
            vec![Nullifier::new([11; 32])],
            vec![(AssetId::new([9; 32]), Amount::new(1).unwrap())],
            vec![TransactionId::new([12; 32])],
        )
        .unwrap()
    }

    fn checkpoint() -> Checkpoint {
        Checkpoint::from_snapshot(anchor(), 1, RecordHash::from_bytes([13; 32]), snapshot())
            .unwrap()
    }

    #[test]
    fn round_trip_is_exact_and_restores_the_same_state() {
        let checkpoint = checkpoint();
        let encoded = checkpoint.encode();
        let decoded = Checkpoint::decode(&encoded).unwrap();
        assert_eq!(decoded, checkpoint);
        assert_eq!(decoded.encode(), encoded);
        assert_eq!(
            decoded
                .restore_state(anchor())
                .unwrap()
                .state_id(anchor().genesis_id),
            checkpoint.state_id()
        );
    }

    #[test]
    fn hash_or_anchor_changes_are_rejected() {
        let mut encoded = checkpoint().encode();
        encoded[10] ^= 1;
        assert_eq!(
            Checkpoint::decode(&encoded),
            Err(CheckpointError::CheckpointHashMismatch)
        );

        let checkpoint = checkpoint();
        let mut changed_anchor = anchor();
        changed_anchor.genesis_id = GenesisId::new([99; 32]);
        assert!(matches!(
            checkpoint.restore_state(changed_anchor),
            Err(CheckpointError::AnchorMismatch(_))
        ));
    }

    #[test]
    fn decoders_reject_changed_headers_and_trailing_bytes() {
        let mut encoded = checkpoint().encode();
        encoded[0] = b'X';
        let hash_start = encoded.len() - CHECKPOINT_HASH_BYTES;
        let hash = hash_checkpoint(&encoded[..hash_start]);
        encoded[hash_start..].copy_from_slice(&hash);
        assert_eq!(
            Checkpoint::decode(&encoded),
            Err(CheckpointError::InvalidMagic)
        );

        let mut encoded = checkpoint().encode();
        encoded.push(0);
        assert_eq!(
            Checkpoint::decode(&encoded),
            Err(CheckpointError::CheckpointHashMismatch)
        );
    }
}
