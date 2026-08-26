use noxis_types::{
    BlockId, ConsensusConfigId, GenesisId, StateId, ValidationContextId, ValidatorId,
    ValidatorSetId,
};

use crate::{
    BlockHeader, BlockHeaderInput, ConsensusConfig, ConsensusError, FinalityCertificate,
    FinalityTarget, RecordCommitment, Validator, ValidatorSet, ValidatorVerificationKey,
    VoteEvidence, finality::MAX_SIGNATURE_BYTES, hash::CONSENSUS_FORMAT_VERSION,
};

const CONFIG_MAGIC: [u8; 4] = *b"NXCG";
const HEADER_MAGIC: [u8; 4] = *b"NXBH";
const CERTIFICATE_MAGIC: [u8; 4] = *b"NXFC";
const PRECOMMIT_SIGNING_DOMAIN: &[u8] = b"NOXIS/CONSENSUS/V1/PRECOMMIT";

pub fn encode_consensus_config(config: &ConsensusConfig) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(28 + config.validator_set().validators().len() * 44);
    bytes.extend_from_slice(&CONFIG_MAGIC);
    bytes.extend_from_slice(&CONSENSUS_FORMAT_VERSION.to_be_bytes());
    bytes.extend_from_slice(&encode_config_fields(
        config.protocol_version(),
        config.maximum_block_records(),
        config.maximum_block_transaction_bytes(),
        config.maximum_byzantine_voting_power(),
        config.validator_set(),
    ));
    bytes
}

pub fn decode_consensus_config(bytes: &[u8]) -> Result<ConsensusConfig, ConsensusError> {
    let mut reader = Reader::new(bytes);
    read_magic_and_version(&mut reader, CONFIG_MAGIC)?;
    let protocol_version = reader.read_u16()?;
    let maximum_block_records = reader.read_u32()?;
    let maximum_block_transaction_bytes = reader.read_u32()?;
    let maximum_byzantine_voting_power = reader.read_u64()?;
    let validator_count = reader.read_u32()? as usize;
    if validator_count > crate::MAX_VALIDATORS {
        return Err(ConsensusError::TooManyValidators {
            actual: validator_count,
            maximum: crate::MAX_VALIDATORS,
        });
    }
    let mut validators = Vec::with_capacity(validator_count);
    for _ in 0..validator_count {
        validators.push(Validator::new(
            ValidatorId::new(reader.read_array()?),
            reader.read_u64()?,
            ValidatorVerificationKey::new(
                reader.read_u16()?,
                read_validator_key_bytes(&mut reader)?,
            )?,
        )?);
    }
    reader.finish()?;
    ConsensusConfig::new(
        protocol_version,
        maximum_block_records,
        maximum_block_transaction_bytes,
        maximum_byzantine_voting_power,
        ValidatorSet::from_canonical(validators)?,
    )
}

pub fn encode_block_header(header: &BlockHeader) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(4 + 2 + BLOCK_HEADER_FIELDS_LENGTH);
    bytes.extend_from_slice(&HEADER_MAGIC);
    bytes.extend_from_slice(&CONSENSUS_FORMAT_VERSION.to_be_bytes());
    bytes.extend_from_slice(&encode_block_header_fields(header.input()));
    bytes
}

pub fn decode_block_header(bytes: &[u8]) -> Result<BlockHeader, ConsensusError> {
    let mut reader = Reader::new(bytes);
    read_magic_and_version(&mut reader, HEADER_MAGIC)?;
    let protocol_version = reader.read_u16()?;
    let genesis_id = GenesisId::new(reader.read_array()?);
    let validation_context_id = ValidationContextId::new(reader.read_array()?);
    let consensus_config_id = ConsensusConfigId::new(reader.read_array()?);
    let validator_set_id = ValidatorSetId::new(reader.read_array()?);
    let height = reader.read_u64()?;
    let epoch = reader.read_u64()?;
    let round = reader.read_u32()?;
    let parent_is_present = reader.read_u8()?;
    let parent_bytes = reader.read_array::<32>()?;
    let parent_block_id = match parent_is_present {
        0 => {
            if parent_bytes != [0; 32] {
                return Err(ConsensusError::UnexpectedParentBlock);
            }
            None
        }
        1 => Some(BlockId::new(parent_bytes)),
        _ => return Err(ConsensusError::InvalidMagic),
    };
    let previous_state_id = StateId::new(reader.read_array()?);
    let resulting_state_id = StateId::new(reader.read_array()?);
    let first_record_sequence = reader.read_u64()?;
    let record_count = reader.read_u32()?;
    let records_commitment = RecordCommitment::from_bytes(reader.read_array()?);
    reader.finish()?;
    BlockHeader::new(BlockHeaderInput {
        protocol_version,
        genesis_id,
        validation_context_id,
        consensus_config_id,
        validator_set_id,
        height,
        epoch,
        round,
        parent_block_id,
        previous_state_id,
        resulting_state_id,
        first_record_sequence,
        record_count,
        records_commitment,
    })
}

pub fn encode_finality_certificate(certificate: &FinalityCertificate) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&CERTIFICATE_MAGIC);
    bytes.extend_from_slice(&CONSENSUS_FORMAT_VERSION.to_be_bytes());
    bytes.extend_from_slice(&encode_finality_certificate_fields(
        certificate.target(),
        certificate.votes(),
    ));
    bytes
}

pub fn decode_finality_certificate(bytes: &[u8]) -> Result<FinalityCertificate, ConsensusError> {
    let mut reader = Reader::new(bytes);
    read_magic_and_version(&mut reader, CERTIFICATE_MAGIC)?;
    let target = decode_finality_target(&mut reader)?;
    let vote_count = reader.read_u32()? as usize;
    if vote_count > crate::MAX_VALIDATORS {
        return Err(ConsensusError::TooManyVotes {
            actual: vote_count,
            maximum: crate::MAX_VALIDATORS,
        });
    }
    let mut votes = Vec::with_capacity(vote_count);
    for _ in 0..vote_count {
        let validator_id = ValidatorId::new(reader.read_array()?);
        let signature_length = reader.read_u16()? as usize;
        if signature_length > MAX_SIGNATURE_BYTES {
            return Err(ConsensusError::SignatureTooLarge {
                actual: signature_length,
                maximum: MAX_SIGNATURE_BYTES,
            });
        }
        votes.push(VoteEvidence::new(
            validator_id,
            reader.read_exact(signature_length)?.to_vec(),
        )?);
    }
    reader.finish()?;
    FinalityCertificate::from_canonical(target, votes)
}

pub(crate) fn encode_validator_set_entries(validators: &[Validator]) -> Vec<u8> {
    let key_bytes: usize = validators
        .iter()
        .map(|validator| validator.verification_key().bytes().len())
        .sum();
    let mut bytes = Vec::with_capacity(4 + validators.len() * 44 + key_bytes);
    bytes.extend_from_slice(&(validators.len() as u32).to_be_bytes());
    for validator in validators {
        bytes.extend_from_slice(&validator.id().0);
        bytes.extend_from_slice(&validator.voting_power().to_be_bytes());
        bytes.extend_from_slice(
            &validator
                .verification_key()
                .signature_scheme()
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&(validator.verification_key().bytes().len() as u16).to_be_bytes());
        bytes.extend_from_slice(validator.verification_key().bytes());
    }
    bytes
}

pub(crate) fn encode_config_fields(
    protocol_version: u16,
    maximum_block_records: u32,
    maximum_block_transaction_bytes: u32,
    maximum_byzantine_voting_power: u64,
    validator_set: &ValidatorSet,
) -> Vec<u8> {
    let validator_entries = encode_validator_set_entries(validator_set.validators());
    let mut bytes = Vec::with_capacity(22 + validator_entries.len());
    bytes.extend_from_slice(&protocol_version.to_be_bytes());
    bytes.extend_from_slice(&maximum_block_records.to_be_bytes());
    bytes.extend_from_slice(&maximum_block_transaction_bytes.to_be_bytes());
    bytes.extend_from_slice(&maximum_byzantine_voting_power.to_be_bytes());
    bytes.extend_from_slice(&validator_entries);
    bytes
}

pub(crate) const BLOCK_HEADER_FIELDS_LENGTH: usize = 2 + (32 * 8) + 8 + 8 + 4 + 1 + 8 + 4;

pub(crate) fn encode_block_header_fields(input: &BlockHeaderInput) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(BLOCK_HEADER_FIELDS_LENGTH);
    bytes.extend_from_slice(&input.protocol_version.to_be_bytes());
    bytes.extend_from_slice(&input.genesis_id.0);
    bytes.extend_from_slice(&input.validation_context_id.0);
    bytes.extend_from_slice(&input.consensus_config_id.0);
    bytes.extend_from_slice(&input.validator_set_id.0);
    bytes.extend_from_slice(&input.height.to_be_bytes());
    bytes.extend_from_slice(&input.epoch.to_be_bytes());
    bytes.extend_from_slice(&input.round.to_be_bytes());
    match input.parent_block_id {
        Some(parent_block_id) => {
            bytes.push(1);
            bytes.extend_from_slice(&parent_block_id.0);
        }
        None => {
            bytes.push(0);
            bytes.extend_from_slice(&[0; 32]);
        }
    }
    bytes.extend_from_slice(&input.previous_state_id.0);
    bytes.extend_from_slice(&input.resulting_state_id.0);
    bytes.extend_from_slice(&input.first_record_sequence.to_be_bytes());
    bytes.extend_from_slice(&input.record_count.to_be_bytes());
    bytes.extend_from_slice(&input.records_commitment.as_bytes());
    bytes
}

pub(crate) fn encode_finality_target(target: FinalityTarget) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(PRECOMMIT_SIGNING_DOMAIN.len() + 2 + FINALITY_TARGET_LENGTH);
    bytes.extend_from_slice(PRECOMMIT_SIGNING_DOMAIN);
    bytes.extend_from_slice(&CONSENSUS_FORMAT_VERSION.to_be_bytes());
    bytes.extend_from_slice(&encode_finality_target_fields(target));
    bytes
}

pub(crate) fn encode_finality_certificate_fields(
    target: FinalityTarget,
    votes: &[VoteEvidence],
) -> Vec<u8> {
    let total_signature_bytes: usize = votes.iter().map(|vote| vote.signature().len()).sum();
    let mut bytes =
        Vec::with_capacity(FINALITY_TARGET_LENGTH + 4 + votes.len() * 34 + total_signature_bytes);
    bytes.extend_from_slice(&encode_finality_target_fields(target));
    bytes.extend_from_slice(&(votes.len() as u32).to_be_bytes());
    for vote in votes {
        bytes.extend_from_slice(&vote.validator_id().0);
        bytes.extend_from_slice(&(vote.signature().len() as u16).to_be_bytes());
        bytes.extend_from_slice(vote.signature());
    }
    bytes
}

const FINALITY_TARGET_LENGTH: usize = (32 * 5) + 8 + 8 + 4;

fn encode_finality_target_fields(target: FinalityTarget) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(FINALITY_TARGET_LENGTH);
    bytes.extend_from_slice(&target.genesis_id().0);
    bytes.extend_from_slice(&target.validation_context_id().0);
    bytes.extend_from_slice(&target.consensus_config_id().0);
    bytes.extend_from_slice(&target.validator_set_id().0);
    bytes.extend_from_slice(&target.height().to_be_bytes());
    bytes.extend_from_slice(&target.epoch().to_be_bytes());
    bytes.extend_from_slice(&target.round().to_be_bytes());
    bytes.extend_from_slice(&target.block_id().0);
    bytes
}

fn decode_finality_target(reader: &mut Reader<'_>) -> Result<FinalityTarget, ConsensusError> {
    FinalityTarget::new(
        GenesisId::new(reader.read_array()?),
        ValidationContextId::new(reader.read_array()?),
        ConsensusConfigId::new(reader.read_array()?),
        ValidatorSetId::new(reader.read_array()?),
        reader.read_u64()?,
        reader.read_u64()?,
        reader.read_u32()?,
        BlockId::new(reader.read_array()?),
    )
}

fn read_validator_key_bytes(reader: &mut Reader<'_>) -> Result<Vec<u8>, ConsensusError> {
    let length = reader.read_u16()? as usize;
    if length > crate::MAX_VALIDATOR_PUBLIC_KEY_BYTES {
        return Err(ConsensusError::ValidatorKeyTooLarge {
            actual: length,
            maximum: crate::MAX_VALIDATOR_PUBLIC_KEY_BYTES,
        });
    }
    Ok(reader.read_exact(length)?.to_vec())
}

fn read_magic_and_version(reader: &mut Reader<'_>, magic: [u8; 4]) -> Result<(), ConsensusError> {
    if reader.read_array::<4>()? != magic {
        return Err(ConsensusError::InvalidMagic);
    }
    let version = reader.read_u16()?;
    if version != CONSENSUS_FORMAT_VERSION {
        return Err(ConsensusError::UnsupportedFormatVersion(version));
    }
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, ConsensusError> {
        Ok(self.read_array::<1>()?[0])
    }

    fn read_u16(&mut self) -> Result<u16, ConsensusError> {
        Ok(u16::from_be_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> Result<u32, ConsensusError> {
        Ok(u32::from_be_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> Result<u64, ConsensusError> {
        Ok(u64::from_be_bytes(self.read_array()?))
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], ConsensusError> {
        self.read_exact(N)?
            .try_into()
            .map_err(|_| ConsensusError::UnexpectedEnd {
                offset: self.offset,
            })
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], ConsensusError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ConsensusError::LengthOverflow)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(ConsensusError::UnexpectedEnd {
                offset: self.offset,
            })?;
        self.offset = end;
        Ok(bytes)
    }

    fn finish(self) -> Result<(), ConsensusError> {
        let remaining = self.bytes.len().saturating_sub(self.offset);
        if remaining == 0 {
            Ok(())
        } else {
            Err(ConsensusError::TrailingBytes { count: remaining })
        }
    }
}

#[cfg(test)]
mod tests {
    use noxis_types::ValidatorId;

    use super::*;
    use crate::{Validator, ValidatorSet, ValidatorVerificationKey};

    fn config() -> ConsensusConfig {
        ConsensusConfig::new(
            1,
            100,
            1024,
            0,
            ValidatorSet::new(vec![
                Validator::new(
                    ValidatorId::new([1; 32]),
                    1,
                    ValidatorVerificationKey::new(1, vec![2]).unwrap(),
                )
                .unwrap(),
            ])
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn consensus_config_round_trip_is_exact() {
        let encoded = encode_consensus_config(&config());
        assert_eq!(
            encode_consensus_config(&decode_consensus_config(&encoded).unwrap()),
            encoded
        );
    }

    #[test]
    fn rejects_the_obsolete_version_one_configuration_format() {
        let mut encoded = encode_consensus_config(&config());
        encoded[4..6].copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            decode_consensus_config(&encoded),
            Err(ConsensusError::UnsupportedFormatVersion(1))
        );
    }
}
