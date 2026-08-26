use noxis_record_chain::RecordHash;
use noxis_types::{
    BlockId, ConsensusConfigId, GenesisId, StateId, ValidationContextId, ValidatorSetId,
};

use crate::{ConsensusConfig, ConsensusError, codec, hash};

/// Absolute bound used before a configuration is available.
pub const MAX_BLOCK_RECORDS: usize = 1_000_000;

/// Hash commitment to the ordered NXRC record hashes included in one block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordCommitment([u8; 32]);

impl RecordCommitment {
    /// Computes the commitment from records in their proposed order.
    pub fn from_record_hashes(record_hashes: &[RecordHash]) -> Result<Self, ConsensusError> {
        if record_hashes.len() > MAX_BLOCK_RECORDS {
            return Err(ConsensusError::TooManyCommittedRecords {
                actual: record_hashes.len(),
                maximum: MAX_BLOCK_RECORDS,
            });
        }
        let mut bytes = Vec::with_capacity(4 + (record_hashes.len() * 32));
        bytes.extend_from_slice(&(record_hashes.len() as u32).to_be_bytes());
        for record_hash in record_hashes {
            bytes.extend_from_slice(&record_hash.as_bytes());
        }
        Ok(Self(hash::record_commitment(&bytes)))
    }

    /// Reconstructs a commitment already stored in a verified block header.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// All material used to construct a deterministic block header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockHeaderInput {
    pub protocol_version: u16,
    pub genesis_id: GenesisId,
    pub validation_context_id: ValidationContextId,
    pub consensus_config_id: ConsensusConfigId,
    pub validator_set_id: ValidatorSetId,
    pub height: u64,
    pub epoch: u64,
    pub round: u32,
    pub parent_block_id: Option<BlockId>,
    pub previous_state_id: StateId,
    pub resulting_state_id: StateId,
    pub first_record_sequence: u64,
    pub record_count: u32,
    pub records_commitment: RecordCommitment,
}

/// Canonical description of one proposed state transition batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockHeader {
    input: BlockHeaderInput,
    id: BlockId,
}

impl BlockHeader {
    pub fn new(input: BlockHeaderInput) -> Result<Self, ConsensusError> {
        validate_header_input(&input)?;
        let id = hash::block_id(&codec::encode_block_header_fields(&input));
        Ok(Self { input, id })
    }

    pub const fn id(&self) -> BlockId {
        self.id
    }

    pub const fn protocol_version(&self) -> u16 {
        self.input.protocol_version
    }

    pub const fn genesis_id(&self) -> GenesisId {
        self.input.genesis_id
    }

    pub const fn validation_context_id(&self) -> ValidationContextId {
        self.input.validation_context_id
    }

    pub const fn consensus_config_id(&self) -> ConsensusConfigId {
        self.input.consensus_config_id
    }

    pub const fn validator_set_id(&self) -> ValidatorSetId {
        self.input.validator_set_id
    }

    pub const fn height(&self) -> u64 {
        self.input.height
    }

    pub const fn epoch(&self) -> u64 {
        self.input.epoch
    }

    pub const fn round(&self) -> u32 {
        self.input.round
    }

    pub const fn parent_block_id(&self) -> Option<BlockId> {
        self.input.parent_block_id
    }

    pub const fn previous_state_id(&self) -> StateId {
        self.input.previous_state_id
    }

    pub const fn resulting_state_id(&self) -> StateId {
        self.input.resulting_state_id
    }

    pub const fn first_record_sequence(&self) -> u64 {
        self.input.first_record_sequence
    }

    pub const fn record_count(&self) -> u32 {
        self.input.record_count
    }

    /// Last included record sequence, or `None` when this is an empty block.
    pub fn last_record_sequence(&self) -> Result<Option<u64>, ConsensusError> {
        if self.input.record_count == 0 {
            return Ok(None);
        }
        self.input
            .first_record_sequence
            .checked_add(u64::from(self.input.record_count) - 1)
            .map(Some)
            .ok_or(ConsensusError::RecordSequenceOverflow)
    }

    pub const fn records_commitment(&self) -> RecordCommitment {
        self.input.records_commitment
    }

    /// Verifies that concrete records exactly match the count and commitment
    /// sealed in this header. Their sequence and state-link continuity remain
    /// the responsibility of `noxis-record-chain` and the consensus chain
    /// validator that will be added next.
    pub fn validate_record_hashes(
        &self,
        record_hashes: &[RecordHash],
    ) -> Result<(), ConsensusError> {
        if record_hashes.len() != self.record_count() as usize {
            return Err(ConsensusError::RecordCountMismatch {
                expected: self.record_count(),
                actual: record_hashes.len(),
            });
        }
        if RecordCommitment::from_record_hashes(record_hashes)? != self.records_commitment() {
            return Err(ConsensusError::RecordCommitmentMismatch);
        }
        Ok(())
    }

    /// Checks the immutable configuration bindings and configured block size.
    pub fn validate_against_config(&self, config: &ConsensusConfig) -> Result<(), ConsensusError> {
        if self.protocol_version() != config.protocol_version() {
            return Err(ConsensusError::BlockFormatMismatch);
        }
        if self.consensus_config_id() != config.id() {
            return Err(ConsensusError::ConsensusConfigMismatch);
        }
        if self.validator_set_id() != config.validator_set().id() {
            return Err(ConsensusError::ValidatorSetMismatch);
        }
        if self.record_count() > config.maximum_block_records() {
            return Err(ConsensusError::RecordCountExceedsConfiguredMaximum {
                actual: self.record_count(),
                maximum: config.maximum_block_records(),
            });
        }
        Ok(())
    }

    pub(crate) const fn input(&self) -> &BlockHeaderInput {
        &self.input
    }
}

fn validate_header_input(input: &BlockHeaderInput) -> Result<(), ConsensusError> {
    if input.protocol_version == 0 {
        return Err(ConsensusError::InvalidProtocolVersion);
    }
    if input.height == 0 {
        return Err(ConsensusError::InvalidBlockHeight);
    }
    if input.height == 1 && input.parent_block_id.is_some() {
        return Err(ConsensusError::UnexpectedParentBlock);
    }
    if input.height > 1 && input.parent_block_id.is_none() {
        return Err(ConsensusError::MissingParentBlock);
    }
    if input.first_record_sequence == 0 {
        return Err(ConsensusError::InvalidFirstRecordSequence);
    }
    if input.record_count as usize > MAX_BLOCK_RECORDS {
        return Err(ConsensusError::TooManyCommittedRecords {
            actual: input.record_count as usize,
            maximum: MAX_BLOCK_RECORDS,
        });
    }
    if input.record_count > 0 {
        input
            .first_record_sequence
            .checked_add(u64::from(input.record_count) - 1)
            .ok_or(ConsensusError::RecordSequenceOverflow)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use noxis_types::{ConsensusConfigId, GenesisId, StateId, ValidationContextId, ValidatorSetId};

    use super::*;

    fn input(height: u64, parent_block_id: Option<BlockId>) -> BlockHeaderInput {
        BlockHeaderInput {
            protocol_version: 1,
            genesis_id: GenesisId::new([1; 32]),
            validation_context_id: ValidationContextId::new([2; 32]),
            consensus_config_id: ConsensusConfigId::new([3; 32]),
            validator_set_id: ValidatorSetId::new([4; 32]),
            height,
            epoch: 0,
            round: 0,
            parent_block_id,
            previous_state_id: StateId::new([5; 32]),
            resulting_state_id: StateId::new([6; 32]),
            first_record_sequence: 1,
            record_count: 1,
            records_commitment: RecordCommitment::from_bytes([7; 32]),
        }
    }

    #[test]
    fn initial_block_cannot_claim_parent() {
        assert_eq!(
            BlockHeader::new(input(1, Some(BlockId::new([9; 32])))),
            Err(ConsensusError::UnexpectedParentBlock)
        );
        assert_eq!(
            BlockHeader::new(input(2, None)),
            Err(ConsensusError::MissingParentBlock)
        );
    }

    #[test]
    fn record_commitment_depends_on_order_count_and_accepts_empty_blocks() {
        let first = RecordHash::from_bytes([1; 32]);
        let second = RecordHash::from_bytes([2; 32]);
        assert_ne!(
            RecordCommitment::from_record_hashes(&[first, second]).unwrap(),
            RecordCommitment::from_record_hashes(&[second, first]).unwrap()
        );
        assert_ne!(
            RecordCommitment::from_record_hashes(&[]).unwrap(),
            RecordCommitment::from_record_hashes(&[first]).unwrap()
        );

        let mut empty = input(1, None);
        empty.record_count = 0;
        empty.records_commitment = RecordCommitment::from_record_hashes(&[]).unwrap();
        let header = BlockHeader::new(empty).unwrap();
        assert_eq!(header.last_record_sequence().unwrap(), None);
        header.validate_record_hashes(&[]).unwrap();
    }
}
