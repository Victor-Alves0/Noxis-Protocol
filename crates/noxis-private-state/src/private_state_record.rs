//! Canonical in-memory `NXPR v1` record for candidate private-ledger state.
//!
//! This is a strict snapshot codec, not a filesystem persistence mechanism.
//! Decoding rebuilds the note snapshot, sparse nullifier tree and typed anchor
//! instead of trusting their serialized derived values.

use std::fmt;

use noxis_nullifier_tree_state::NullifierSparseTreeStateV1;
use noxis_poseidon2_reference::Poseidon2P24Reference;
use noxis_privacy_types::{NoteCommitmentV2, NullifierV2, TreeParametersId, TreeParametersV2};
use noxis_types::{AssetDefinition, AssetId, AssetKind, GenesisId, StateId, ValidationContextId};
use sha2::{Digest, Sha256};

use crate::{
    CandidatePrivateLedgerError, CandidatePrivateLedgerStateV1, CandidatePrivateStateSnapshotV1,
};

/// Magic of a candidate private-ledger state record.
pub const PRIVATE_STATE_RECORD_MAGIC: [u8; 4] = *b"NXPR";
/// Only supported candidate private-ledger state-record version.
pub const PRIVATE_STATE_RECORD_VERSION: u16 = 1;
/// SHA-256 domain for an `NXPR v1` record checksum.
pub const PRIVATE_STATE_RECORD_CHECKSUM_DOMAIN: &[u8] = b"NOXIS/PRIVATE-STATE-RECORD/V1\0";
/// Bounded number of public asset definitions retained by one record.
pub const PRIVATE_STATE_RECORD_MAX_ASSETS: usize = 4_096;
/// Candidate snapshot nullifier bound, separate from the note-count limit.
pub const PRIVATE_STATE_RECORD_MAX_NULLIFIERS: usize = 2_048;
/// Largest possible complete `NXPR v1` record under its declared limits.
pub const PRIVATE_STATE_RECORD_MAX_BYTES: usize = HEADER_LENGTH
    + crate::CANDIDATE_PRIVATE_STATE_MAX_NOTES * 64
    + PRIVATE_STATE_RECORD_MAX_NULLIFIERS * 64
    + PRIVATE_STATE_RECORD_MAX_ASSETS * (32 + 1 + 1 + 16)
    + CHECKSUM_LENGTH;

const HEADER_LENGTH: usize = 4 + 2 + 2 + 32 + 32 + 32 + 32 + 4 + 4 + 2;
const CHECKSUM_LENGTH: usize = 32;

/// Encodes the complete candidate private ledger state in canonical `NXPR v1`.
pub fn encode_candidate_private_ledger_state(
    state: &CandidatePrivateLedgerStateV1,
) -> Result<Vec<u8>, CandidatePrivateStateRecordError> {
    let commitments = state.snapshot().commitments();
    let nullifiers = state.snapshot().spent_nullifiers();
    let assets = state.assets();
    if nullifiers.len() > PRIVATE_STATE_RECORD_MAX_NULLIFIERS {
        return Err(CandidatePrivateStateRecordError::TooManyNullifiers(
            nullifiers.len(),
        ));
    }
    if assets.len() > PRIVATE_STATE_RECORD_MAX_ASSETS {
        return Err(CandidatePrivateStateRecordError::TooManyAssets(
            assets.len(),
        ));
    }
    let mut bytes = Vec::with_capacity(
        HEADER_LENGTH
            + commitments.len() * 64
            + nullifiers.len() * 64
            + assets.len() * 50
            + CHECKSUM_LENGTH,
    );
    bytes.extend_from_slice(&PRIVATE_STATE_RECORD_MAGIC);
    bytes.extend_from_slice(&PRIVATE_STATE_RECORD_VERSION.to_be_bytes());
    bytes.extend_from_slice(&[0; 2]);
    bytes.extend_from_slice(&state.anchor().genesis_id().0);
    bytes.extend_from_slice(&state.anchor().validation_context_id().0);
    bytes.extend_from_slice(&state.anchor().note_tree_parameters().id().as_bytes());
    bytes.extend_from_slice(&state.anchor().state_id().0);
    put_u32(&mut bytes, commitments.len())?;
    put_u32(&mut bytes, nullifiers.len())?;
    put_u16(&mut bytes, assets.len())?;
    for commitment in commitments {
        bytes.extend_from_slice(&commitment.as_bytes());
    }
    for nullifier in nullifiers {
        bytes.extend_from_slice(&nullifier.as_bytes());
    }
    for asset in assets {
        bytes.extend_from_slice(&asset.id.0);
        bytes.push(asset_kind_tag(asset.kind));
        bytes.push(u8::try_from(asset.ticker.len()).expect("AssetDefinition bounds ticker length"));
        bytes.extend_from_slice(asset.ticker.as_bytes());
    }
    bytes.extend_from_slice(&checksum(&bytes));
    Ok(bytes)
}

/// Decodes and completely rebuilds candidate private-ledger state from `NXPR v1`.
pub fn decode_candidate_private_ledger_state(
    bytes: &[u8],
) -> Result<CandidatePrivateLedgerStateV1, CandidatePrivateStateRecordError> {
    if bytes.len() < HEADER_LENGTH + CHECKSUM_LENGTH {
        return Err(CandidatePrivateStateRecordError::Truncated);
    }
    let (body, actual_checksum) = bytes.split_at(bytes.len() - CHECKSUM_LENGTH);
    if checksum(body) != actual_checksum {
        return Err(CandidatePrivateStateRecordError::ChecksumMismatch);
    }
    let mut reader = Reader::new(body);
    if reader.array::<4>()? != PRIVATE_STATE_RECORD_MAGIC {
        return Err(CandidatePrivateStateRecordError::Magic);
    }
    if reader.u16()? != PRIVATE_STATE_RECORD_VERSION {
        return Err(CandidatePrivateStateRecordError::Version);
    }
    if reader.array::<2>()? != [0; 2] {
        return Err(CandidatePrivateStateRecordError::Reserved);
    }
    let genesis_id = GenesisId::new(reader.array()?);
    let validation_context_id = ValidationContextId::new(reader.array()?);
    let tree_parameters = TreeParametersV2::new(TreeParametersId::new(reader.array()?));
    let encoded_state_id = StateId::new(reader.array()?);
    let commitment_count = bounded(
        reader.u32()? as usize,
        crate::CANDIDATE_PRIVATE_STATE_MAX_NOTES,
        "commitments",
    )?;
    let nullifier_count = bounded(
        reader.u32()? as usize,
        PRIVATE_STATE_RECORD_MAX_NULLIFIERS,
        "nullifiers",
    )?;
    let asset_count = bounded(
        reader.u16()? as usize,
        PRIVATE_STATE_RECORD_MAX_ASSETS,
        "assets",
    )?;
    let commitments = (0..commitment_count)
        .map(|_| {
            NoteCommitmentV2::new(reader.array()?)
                .map_err(CandidatePrivateStateRecordError::Privacy)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let nullifiers = (0..nullifier_count)
        .map(|_| {
            NullifierV2::new(reader.array()?).map_err(CandidatePrivateStateRecordError::Privacy)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut assets = Vec::with_capacity(asset_count);
    let mut previous_asset = None;
    for _ in 0..asset_count {
        let id = AssetId::new(reader.array()?);
        if previous_asset.is_some_and(|previous| previous >= id) {
            return Err(CandidatePrivateStateRecordError::AssetOrder);
        }
        previous_asset = Some(id);
        let kind = decode_asset_kind(reader.u8()?)?;
        let ticker_length = reader.u8()? as usize;
        if !(1..=16).contains(&ticker_length) {
            return Err(CandidatePrivateStateRecordError::TickerLength(
                ticker_length,
            ));
        }
        let ticker = std::str::from_utf8(reader.bytes(ticker_length)?)
            .map_err(|_| CandidatePrivateStateRecordError::TickerUtf8)?;
        assets.push(
            AssetDefinition::new(id, ticker, kind)
                .map_err(CandidatePrivateStateRecordError::Asset)?,
        );
    }
    reader.finish()?;
    let reference = Poseidon2P24Reference::load_candidate()
        .map_err(CandidatePrivateStateRecordError::Reference)?;
    let snapshot = CandidatePrivateStateSnapshotV1::new(commitments, nullifiers, &reference)
        .map_err(CandidatePrivateStateRecordError::Snapshot)?;
    let mut tree = NullifierSparseTreeStateV1::new_candidate()
        .map_err(CandidatePrivateStateRecordError::Tree)?;
    for nullifier in snapshot.spent_nullifiers() {
        tree.mark_spent(*nullifier)
            .map_err(CandidatePrivateStateRecordError::Tree)?;
    }
    let mut state = CandidatePrivateLedgerStateV1::new(
        genesis_id,
        validation_context_id,
        tree_parameters,
        snapshot,
        tree,
    )
    .map_err(CandidatePrivateStateRecordError::Ledger)?;
    if state.anchor().state_id() != encoded_state_id {
        return Err(CandidatePrivateStateRecordError::StateIdMismatch {
            encoded: encoded_state_id,
            rebuilt: state.anchor().state_id(),
        });
    }
    for asset in assets {
        state
            .register_asset(asset)
            .map_err(CandidatePrivateStateRecordError::Ledger)?;
    }
    if encode_candidate_private_ledger_state(&state)? != bytes {
        return Err(CandidatePrivateStateRecordError::NonCanonical);
    }
    Ok(state)
}

fn checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PRIVATE_STATE_RECORD_CHECKSUM_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn put_u32(bytes: &mut Vec<u8>, value: usize) -> Result<(), CandidatePrivateStateRecordError> {
    let value =
        u32::try_from(value).map_err(|_| CandidatePrivateStateRecordError::LengthOverflow)?;
    bytes.extend_from_slice(&value.to_be_bytes());
    Ok(())
}
fn put_u16(bytes: &mut Vec<u8>, value: usize) -> Result<(), CandidatePrivateStateRecordError> {
    let value =
        u16::try_from(value).map_err(|_| CandidatePrivateStateRecordError::LengthOverflow)?;
    bytes.extend_from_slice(&value.to_be_bytes());
    Ok(())
}
fn bounded(
    value: usize,
    maximum: usize,
    field: &'static str,
) -> Result<usize, CandidatePrivateStateRecordError> {
    if value > maximum {
        Err(CandidatePrivateStateRecordError::Count {
            field,
            value,
            maximum,
        })
    } else {
        Ok(value)
    }
}
fn asset_kind_tag(kind: AssetKind) -> u8 {
    match kind {
        AssetKind::NativeBacked => 1,
        AssetKind::Synthetic => 2,
    }
}
fn decode_asset_kind(tag: u8) -> Result<AssetKind, CandidatePrivateStateRecordError> {
    match tag {
        1 => Ok(AssetKind::NativeBacked),
        2 => Ok(AssetKind::Synthetic),
        _ => Err(CandidatePrivateStateRecordError::AssetKind(tag)),
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn bytes(&mut self, length: usize) -> Result<&'a [u8], CandidatePrivateStateRecordError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(CandidatePrivateStateRecordError::Truncated)?;
        let result = self
            .bytes
            .get(self.offset..end)
            .ok_or(CandidatePrivateStateRecordError::Truncated)?;
        self.offset = end;
        Ok(result)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], CandidatePrivateStateRecordError> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| CandidatePrivateStateRecordError::Truncated)
    }
    fn u16(&mut self) -> Result<u16, CandidatePrivateStateRecordError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, CandidatePrivateStateRecordError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u8(&mut self) -> Result<u8, CandidatePrivateStateRecordError> {
        Ok(self.array::<1>()?[0])
    }
    fn finish(self) -> Result<(), CandidatePrivateStateRecordError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(CandidatePrivateStateRecordError::TrailingBytes)
        }
    }
}

/// Fail-closed parsing and reconstruction errors for `NXPR v1`.
#[derive(Debug)]
pub enum CandidatePrivateStateRecordError {
    Truncated,
    Magic,
    Version,
    Reserved,
    ChecksumMismatch,
    TrailingBytes,
    NonCanonical,
    LengthOverflow,
    TooManyAssets(usize),
    TooManyNullifiers(usize),
    Count {
        field: &'static str,
        value: usize,
        maximum: usize,
    },
    AssetOrder,
    AssetKind(u8),
    TickerLength(usize),
    TickerUtf8,
    Privacy(noxis_privacy_types::PrivacyTypesError),
    Asset(noxis_types::AssetError),
    Reference(noxis_poseidon2_reference::Poseidon2P24ReferenceError),
    Tree(noxis_nullifier_tree_state::NullifierSparseTreeStateError),
    Snapshot(crate::CandidatePrivateStateError),
    Ledger(CandidatePrivateLedgerError),
    StateIdMismatch {
        encoded: StateId,
        rebuilt: StateId,
    },
}
impl fmt::Display for CandidatePrivateStateRecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "candidate private-state record error: {self:?}")
    }
}
impl std::error::Error for CandidatePrivateStateRecordError {}

#[cfg(test)]
mod tests {
    use super::*;
    fn value(value: u32) -> NoteCommitmentV2 {
        NoteCommitmentV2::from_elements([value; 16]).unwrap()
    }
    fn nullifier(value: u32) -> NullifierV2 {
        NullifierV2::from_elements([value; 16]).unwrap()
    }
    fn state() -> CandidatePrivateLedgerStateV1 {
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        let snapshot = CandidatePrivateStateSnapshotV1::new(
            vec![value(1), value(2)],
            vec![nullifier(9), nullifier(3)],
            &reference,
        )
        .unwrap();
        let mut tree = NullifierSparseTreeStateV1::new_candidate().unwrap();
        for spent in snapshot.spent_nullifiers() {
            tree.mark_spent(*spent).unwrap();
        }
        let mut state = CandidatePrivateLedgerStateV1::new(
            GenesisId::new([1; 32]),
            ValidationContextId::new([2; 32]),
            TreeParametersV2::new(TreeParametersId::new([3; 32])),
            snapshot,
            tree,
        )
        .unwrap();
        state
            .register_asset(
                AssetDefinition::new(AssetId::new([4; 32]), "NOX", AssetKind::Synthetic).unwrap(),
            )
            .unwrap();
        state
            .register_asset(
                AssetDefinition::new(AssetId::new([5; 32]), "BTC", AssetKind::NativeBacked)
                    .unwrap(),
            )
            .unwrap();
        state
    }
    #[test]
    fn nxpr_round_trips_and_rebuilds_the_typed_state() {
        let state = state();
        let bytes = encode_candidate_private_ledger_state(&state).unwrap();
        let restored = decode_candidate_private_ledger_state(&bytes).unwrap();
        assert_eq!(restored.anchor(), state.anchor());
        assert_eq!(restored.snapshot(), state.snapshot());
        assert_eq!(
            restored.nullifier_tree().root(),
            state.nullifier_tree().root()
        );
        assert_eq!(
            restored.assets().collect::<Vec<_>>(),
            state.assets().collect::<Vec<_>>()
        );
        assert_eq!(
            encode_candidate_private_ledger_state(&restored).unwrap(),
            bytes
        );
    }
    #[test]
    fn nxpr_rejects_tampering_and_trailing_bytes() {
        let bytes = encode_candidate_private_ledger_state(&state()).unwrap();
        let mut tampered = bytes.clone();
        tampered[20] ^= 1;
        assert!(matches!(
            decode_candidate_private_ledger_state(&tampered),
            Err(CandidatePrivateStateRecordError::ChecksumMismatch)
        ));
        let mut trailing = bytes;
        trailing.push(0);
        assert!(matches!(
            decode_candidate_private_ledger_state(&trailing),
            Err(CandidatePrivateStateRecordError::ChecksumMismatch)
        ));
    }
}
