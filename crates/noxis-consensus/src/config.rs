use noxis_types::{
    ConsensusConfigId, GenesisId, StateId, ValidationContextId, ValidatorId, ValidatorSetId,
};

use crate::{BlockHeader, ConsensusError, MAX_BLOCK_RECORDS, codec, hash};

/// Hard decoding bound independent of network configuration.
pub const MAX_VALIDATORS: usize = 10_000;
/// Hard decoder bound for one validator's public verification key.
pub const MAX_VALIDATOR_PUBLIC_KEY_BYTES: usize = 8 * 1024;
/// Absolute bound on canonical transaction bytes accepted in one execution block.
pub const MAX_BLOCK_TRANSACTION_BYTES: u32 = 64 * 1024 * 1024;

/// Canonically committed public verification material for one validator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatorVerificationKey {
    signature_scheme: u16,
    bytes: Vec<u8>,
}

impl ValidatorVerificationKey {
    pub fn new(signature_scheme: u16, bytes: Vec<u8>) -> Result<Self, ConsensusError> {
        if signature_scheme == 0 {
            return Err(ConsensusError::InvalidSignatureScheme);
        }
        if bytes.is_empty() {
            return Err(ConsensusError::EmptyValidatorKey);
        }
        if bytes.len() > MAX_VALIDATOR_PUBLIC_KEY_BYTES {
            return Err(ConsensusError::ValidatorKeyTooLarge {
                actual: bytes.len(),
                maximum: MAX_VALIDATOR_PUBLIC_KEY_BYTES,
            });
        }
        Ok(Self {
            signature_scheme,
            bytes,
        })
    }

    pub const fn signature_scheme(&self) -> u16 {
        self.signature_scheme
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// One known validator and its positive voting power.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Validator {
    id: ValidatorId,
    voting_power: u64,
    verification_key: ValidatorVerificationKey,
}

impl Validator {
    pub fn new(
        id: ValidatorId,
        voting_power: u64,
        verification_key: ValidatorVerificationKey,
    ) -> Result<Self, ConsensusError> {
        if voting_power == 0 {
            return Err(ConsensusError::ZeroVotingPower);
        }
        Ok(Self {
            id,
            voting_power,
            verification_key,
        })
    }

    pub const fn id(&self) -> ValidatorId {
        self.id
    }

    pub const fn voting_power(&self) -> u64 {
        self.voting_power
    }

    pub const fn verification_key(&self) -> &ValidatorVerificationKey {
        &self.verification_key
    }
}

/// A canonical, weighted validator set.
///
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatorSet {
    validators: Vec<Validator>,
    total_voting_power: u64,
    id: ValidatorSetId,
}

impl ValidatorSet {
    /// Creates a set and canonicalizes its entries by validator ID.
    pub fn new(mut validators: Vec<Validator>) -> Result<Self, ConsensusError> {
        validators.sort_unstable_by_key(|validator| validator.id);
        Self::from_canonical(validators)
    }

    pub(crate) fn from_canonical(validators: Vec<Validator>) -> Result<Self, ConsensusError> {
        validate_validators(&validators, true)?;
        let total_voting_power = validators.iter().try_fold(0_u64, |total, validator| {
            total
                .checked_add(validator.voting_power)
                .ok_or(ConsensusError::VotingPowerOverflow)
        })?;
        let id = hash::validator_set_id(&codec::encode_validator_set_entries(&validators));
        Ok(Self {
            validators,
            total_voting_power,
            id,
        })
    }

    pub fn validators(&self) -> &[Validator] {
        &self.validators
    }

    pub const fn total_voting_power(&self) -> u64 {
        self.total_voting_power
    }

    /// Strictly-more-than-two-thirds threshold, computed without overflow.
    pub const fn quorum_voting_power(&self) -> u64 {
        let thirds = self.total_voting_power / 3;
        let remainder = self.total_voting_power % 3;
        (thirds * 2) + ((remainder * 2) / 3) + 1
    }

    pub const fn id(&self) -> ValidatorSetId {
        self.id
    }

    pub fn voting_power_of(&self, id: ValidatorId) -> Option<u64> {
        self.validators
            .binary_search_by_key(&id, |validator| validator.id)
            .ok()
            .map(|index| self.validators[index].voting_power)
    }
}

/// Immutable parameters a block header must bind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsensusConfig {
    protocol_version: u16,
    maximum_block_records: u32,
    maximum_block_transaction_bytes: u32,
    maximum_byzantine_voting_power: u64,
    validator_set: ValidatorSet,
    id: ConsensusConfigId,
}

impl ConsensusConfig {
    pub fn new(
        protocol_version: u16,
        maximum_block_records: u32,
        maximum_block_transaction_bytes: u32,
        maximum_byzantine_voting_power: u64,
        validator_set: ValidatorSet,
    ) -> Result<Self, ConsensusError> {
        if protocol_version == 0 {
            return Err(ConsensusError::InvalidProtocolVersion);
        }
        if maximum_block_records == 0 {
            return Err(ConsensusError::InvalidMaximumBlockRecords);
        }
        if maximum_block_records as usize > MAX_BLOCK_RECORDS {
            return Err(ConsensusError::RecordCountExceedsConfiguredMaximum {
                actual: maximum_block_records,
                maximum: MAX_BLOCK_RECORDS as u32,
            });
        }
        if maximum_block_transaction_bytes == 0
            || maximum_block_transaction_bytes > MAX_BLOCK_TRANSACTION_BYTES
        {
            return Err(ConsensusError::InvalidMaximumBlockTransactionBytes {
                actual: maximum_block_transaction_bytes,
                maximum: MAX_BLOCK_TRANSACTION_BYTES,
            });
        }
        let maximum_safe_fault_power = (validator_set.total_voting_power() - 1) / 3;
        if maximum_byzantine_voting_power > maximum_safe_fault_power {
            return Err(ConsensusError::ByzantineFaultPowerExceedsSafetyLimit {
                declared: maximum_byzantine_voting_power,
                maximum: maximum_safe_fault_power,
            });
        }
        let id = hash::config_id(&codec::encode_config_fields(
            protocol_version,
            maximum_block_records,
            maximum_block_transaction_bytes,
            maximum_byzantine_voting_power,
            &validator_set,
        ));
        Ok(Self {
            protocol_version,
            maximum_block_records,
            maximum_block_transaction_bytes,
            maximum_byzantine_voting_power,
            validator_set,
            id,
        })
    }

    pub const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub const fn maximum_block_records(&self) -> u32 {
        self.maximum_block_records
    }

    /// Total canonical transaction bytes permitted in one execution block.
    pub const fn maximum_block_transaction_bytes(&self) -> u32 {
        self.maximum_block_transaction_bytes
    }

    /// Declared maximum Byzantine voting power, necessarily below one third.
    pub const fn maximum_byzantine_voting_power(&self) -> u64 {
        self.maximum_byzantine_voting_power
    }

    pub const fn validator_set(&self) -> &ValidatorSet {
        &self.validator_set
    }

    pub const fn id(&self) -> ConsensusConfigId {
        self.id
    }
}

/// Immutable network domain expected by a consensus client or validator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsensusAnchor {
    genesis_id: GenesisId,
    validation_context_id: ValidationContextId,
    consensus_config_id: ConsensusConfigId,
    genesis_state_id: StateId,
    engine_network_id: [u8; 32],
}

impl ConsensusAnchor {
    pub const fn new(
        genesis_id: GenesisId,
        validation_context_id: ValidationContextId,
        consensus_config_id: ConsensusConfigId,
        genesis_state_id: StateId,
        engine_network_id: [u8; 32],
    ) -> Self {
        Self {
            genesis_id,
            validation_context_id,
            consensus_config_id,
            genesis_state_id,
            engine_network_id,
        }
    }

    pub fn validate_header(
        &self,
        header: &BlockHeader,
        config: &ConsensusConfig,
    ) -> Result<(), ConsensusError> {
        header.validate_against_config(config)?;
        if header.genesis_id() != self.genesis_id {
            return Err(ConsensusError::GenesisMismatch);
        }
        if header.validation_context_id() != self.validation_context_id {
            return Err(ConsensusError::ValidationContextMismatch);
        }
        if config.id() != self.consensus_config_id {
            return Err(ConsensusError::ConsensusConfigMismatch);
        }
        if header.height() == 1 && header.previous_state_id() != self.genesis_state_id {
            return Err(ConsensusError::GenesisStateMismatch);
        }
        Ok(())
    }

    pub const fn genesis_id(&self) -> GenesisId {
        self.genesis_id
    }

    pub const fn validation_context_id(&self) -> ValidationContextId {
        self.validation_context_id
    }

    pub const fn consensus_config_id(&self) -> ConsensusConfigId {
        self.consensus_config_id
    }

    pub const fn genesis_state_id(&self) -> StateId {
        self.genesis_state_id
    }

    /// CometBFT network identity commitment, or all zeroes for an explicitly
    /// engine-neutral genesis that cannot run the Comet ABCI adapter.
    pub const fn engine_network_id(&self) -> [u8; 32] {
        self.engine_network_id
    }
}

fn validate_validators(
    validators: &[Validator],
    require_canonical_order: bool,
) -> Result<(), ConsensusError> {
    if validators.is_empty() {
        return Err(ConsensusError::EmptyValidatorSet);
    }
    if validators.len() > MAX_VALIDATORS {
        return Err(ConsensusError::TooManyValidators {
            actual: validators.len(),
            maximum: MAX_VALIDATORS,
        });
    }
    for (index, validator) in validators.iter().enumerate() {
        if validator.voting_power == 0 {
            return Err(ConsensusError::ZeroVotingPower);
        }
        if let Some(previous) = index
            .checked_sub(1)
            .and_then(|previous| validators.get(previous))
        {
            if previous.id == validator.id {
                return Err(ConsensusError::DuplicateValidator);
            }
            if require_canonical_order && previous.id > validator.id {
                return Err(ConsensusError::NonCanonicalValidatorOrder);
            }
        }
    }
    Ok(())
}
