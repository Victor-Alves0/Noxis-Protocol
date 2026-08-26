use noxis_types::{
    BlockId, ConsensusConfigId, FinalityCertificateId, GenesisId, ValidationContextId, ValidatorId,
    ValidatorSetId,
};

use crate::{BlockHeader, ConsensusAnchor, ConsensusConfig, ConsensusError, codec, hash};

/// Upper bound checked before allocating a signature received from the network.
pub const MAX_SIGNATURE_BYTES: usize = 16 * 1024;

/// The exact block and consensus domain to which precommit signatures apply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalityTarget {
    genesis_id: GenesisId,
    validation_context_id: ValidationContextId,
    consensus_config_id: ConsensusConfigId,
    validator_set_id: ValidatorSetId,
    height: u64,
    epoch: u64,
    round: u32,
    block_id: BlockId,
}

impl FinalityTarget {
    pub const fn from_header(header: &BlockHeader) -> Self {
        Self {
            genesis_id: header.genesis_id(),
            validation_context_id: header.validation_context_id(),
            consensus_config_id: header.consensus_config_id(),
            validator_set_id: header.validator_set_id(),
            height: header.height(),
            epoch: header.epoch(),
            round: header.round(),
            block_id: header.id(),
        }
    }

    #[allow(clippy::too_many_arguments)] // Exact canonical fields from the decoder; no public builder.
    pub(crate) const fn new(
        genesis_id: GenesisId,
        validation_context_id: ValidationContextId,
        consensus_config_id: ConsensusConfigId,
        validator_set_id: ValidatorSetId,
        height: u64,
        epoch: u64,
        round: u32,
        block_id: BlockId,
    ) -> Result<Self, ConsensusError> {
        if height == 0 {
            return Err(ConsensusError::InvalidBlockHeight);
        }
        Ok(Self {
            genesis_id,
            validation_context_id,
            consensus_config_id,
            validator_set_id,
            height,
            epoch,
            round,
            block_id,
        })
    }

    pub const fn genesis_id(self) -> GenesisId {
        self.genesis_id
    }

    pub const fn validation_context_id(self) -> ValidationContextId {
        self.validation_context_id
    }

    pub const fn consensus_config_id(self) -> ConsensusConfigId {
        self.consensus_config_id
    }

    pub const fn validator_set_id(self) -> ValidatorSetId {
        self.validator_set_id
    }

    pub const fn height(self) -> u64 {
        self.height
    }

    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    pub const fn round(self) -> u32 {
        self.round
    }

    pub const fn block_id(self) -> BlockId {
        self.block_id
    }

    /// Canonical signature transcript. It is distinct from the certificate
    /// encoding so a signature can never be replayed as a different message.
    pub fn signing_bytes(self) -> Vec<u8> {
        codec::encode_finality_target(self)
    }
}

/// One validator's signature over [`FinalityTarget::signing_bytes`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VoteEvidence {
    validator_id: ValidatorId,
    signature: Vec<u8>,
}

impl VoteEvidence {
    pub fn new(validator_id: ValidatorId, signature: Vec<u8>) -> Result<Self, ConsensusError> {
        if signature.len() > MAX_SIGNATURE_BYTES {
            return Err(ConsensusError::SignatureTooLarge {
                actual: signature.len(),
                maximum: MAX_SIGNATURE_BYTES,
            });
        }
        if signature.is_empty() {
            return Err(ConsensusError::EmptySignature);
        }
        Ok(Self {
            validator_id,
            signature,
        })
    }

    pub const fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

/// A structurally canonical collection of precommit evidence.
///
/// Construction and decoding validate bounded lengths and canonical order.
/// They do not validate signatures; callers must use
/// [`FinalityCertificate::verify`] with a concrete verifier before treating
/// the result as final.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalityCertificate {
    target: FinalityTarget,
    votes: Vec<VoteEvidence>,
    id: FinalityCertificateId,
}

impl FinalityCertificate {
    /// Creates a canonical certificate by sorting votes by validator ID.
    pub fn new(
        target: FinalityTarget,
        mut votes: Vec<VoteEvidence>,
    ) -> Result<Self, ConsensusError> {
        votes.sort_unstable_by_key(|vote| vote.validator_id);
        Self::from_canonical(target, votes)
    }

    pub(crate) fn from_canonical(
        target: FinalityTarget,
        votes: Vec<VoteEvidence>,
    ) -> Result<Self, ConsensusError> {
        validate_votes(&votes, true)?;
        let id = hash::certificate_id(&codec::encode_finality_certificate_fields(target, &votes));
        Ok(Self { target, votes, id })
    }

    pub const fn target(&self) -> FinalityTarget {
        self.target
    }

    pub fn votes(&self) -> &[VoteEvidence] {
        &self.votes
    }

    pub const fn id(&self) -> FinalityCertificateId {
        self.id
    }

    /// Verifies target binding, validator membership and the BFT >2/3 quorum.
    /// Signature verification remains intentionally separate.
    pub fn validate_structure(
        &self,
        header: &BlockHeader,
        anchor: &ConsensusAnchor,
        config: &ConsensusConfig,
    ) -> Result<(), ConsensusError> {
        anchor.validate_header(header, config)?;
        if self.target != FinalityTarget::from_header(header) {
            return Err(ConsensusError::CertificateTargetMismatch);
        }
        let validator_set = config.validator_set();
        if self.target.validator_set_id != validator_set.id() {
            return Err(ConsensusError::ValidatorSetMismatch);
        }
        let signed_voting_power = self.votes.iter().try_fold(0_u64, |total, vote| {
            let power = validator_set
                .voting_power_of(vote.validator_id)
                .ok_or(ConsensusError::UnknownValidator)?;
            total
                .checked_add(power)
                .ok_or(ConsensusError::VotingPowerOverflow)
        })?;
        let required = validator_set.quorum_voting_power();
        if signed_voting_power < required {
            return Err(ConsensusError::InsufficientVotingPower {
                signed: signed_voting_power,
                required,
            });
        }
        Ok(())
    }

    /// Validates a certificate completely using the supplied concrete key
    /// verifier and returns a marker accepted by that verifier.
    pub fn verify<V: FinalityVerifier>(
        &self,
        header: &BlockHeader,
        anchor: &ConsensusAnchor,
        config: &ConsensusConfig,
        verifier: &V,
    ) -> Result<VerifiedFinality, ConsensusError> {
        self.validate_structure(header, anchor, config)?;
        let signing_bytes = self.target.signing_bytes();
        for vote in &self.votes {
            let configured_validator = config
                .validator_set()
                .validators()
                .iter()
                .find(|validator| validator.id() == vote.validator_id)
                .ok_or(ConsensusError::UnknownValidator)?;
            verifier
                .verify_precommit(
                    vote.validator_id,
                    &signing_bytes,
                    &vote.signature,
                    configured_validator,
                )
                .map_err(|_| ConsensusError::InvalidSignature {
                    validator: vote.validator_id,
                })?;
        }
        Ok(VerifiedFinality {
            block_id: header.id(),
            height: header.height(),
            certificate_id: self.id,
        })
    }
}

/// Cryptographic boundary supplied by a concrete consensus-engine adapter.
///
/// The adapter must use the supplied canonical signing bytes and configured
/// public key, rejecting unsupported key schemes and invalid signatures.
pub trait FinalityVerifier {
    type Error;

    fn verify_precommit(
        &self,
        validator: ValidatorId,
        signing_bytes: &[u8],
        signature: &[u8],
        configured_validator: &crate::Validator,
    ) -> Result<(), Self::Error>;
}

/// Evidence that passed both BFT quorum checks and concrete signature checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedFinality {
    block_id: BlockId,
    height: u64,
    certificate_id: FinalityCertificateId,
}

impl VerifiedFinality {
    pub const fn block_id(self) -> BlockId {
        self.block_id
    }

    pub const fn height(self) -> u64 {
        self.height
    }

    pub const fn certificate_id(self) -> FinalityCertificateId {
        self.certificate_id
    }
}

fn validate_votes(
    votes: &[VoteEvidence],
    require_canonical_order: bool,
) -> Result<(), ConsensusError> {
    if votes.is_empty() {
        return Err(ConsensusError::EmptyCertificate);
    }
    if votes.len() > crate::MAX_VALIDATORS {
        return Err(ConsensusError::TooManyVotes {
            actual: votes.len(),
            maximum: crate::MAX_VALIDATORS,
        });
    }
    for (index, vote) in votes.iter().enumerate() {
        if vote.signature.len() > MAX_SIGNATURE_BYTES {
            return Err(ConsensusError::SignatureTooLarge {
                actual: vote.signature.len(),
                maximum: MAX_SIGNATURE_BYTES,
            });
        }
        if vote.signature.is_empty() {
            return Err(ConsensusError::EmptySignature);
        }
        if let Some(previous) = index
            .checked_sub(1)
            .and_then(|previous| votes.get(previous))
        {
            if previous.validator_id == vote.validator_id {
                return Err(ConsensusError::DuplicateVote);
            }
            if require_canonical_order && previous.validator_id > vote.validator_id {
                return Err(ConsensusError::NonCanonicalVoteOrder);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use noxis_types::{GenesisId, StateId, ValidationContextId};

    use super::*;
    use crate::{
        BlockHeaderInput, ConsensusAnchor, ConsensusConfig, RecordCommitment, Validator,
        ValidatorSet, ValidatorVerificationKey,
    };

    struct AcceptAll;

    impl FinalityVerifier for AcceptAll {
        type Error = ();

        fn verify_precommit(
            &self,
            _validator: ValidatorId,
            _signing_bytes: &[u8],
            _signature: &[u8],
            _configured_validator: &crate::Validator,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    struct RejectAll;

    impl FinalityVerifier for RejectAll {
        type Error = ();

        fn verify_precommit(
            &self,
            _validator: ValidatorId,
            _signing_bytes: &[u8],
            _signature: &[u8],
            _configured_validator: &crate::Validator,
        ) -> Result<(), Self::Error> {
            Err(())
        }
    }

    fn config() -> ConsensusConfig {
        let validators = ValidatorSet::new(vec![
            Validator::new(
                ValidatorId::new([1; 32]),
                3,
                ValidatorVerificationKey::new(1, vec![1]).unwrap(),
            )
            .unwrap(),
            Validator::new(
                ValidatorId::new([2; 32]),
                1,
                ValidatorVerificationKey::new(1, vec![2]).unwrap(),
            )
            .unwrap(),
        ])
        .unwrap();
        ConsensusConfig::new(1, 100, 1024, 1, validators).unwrap()
    }

    fn header(config: &ConsensusConfig) -> BlockHeader {
        BlockHeader::new(BlockHeaderInput {
            protocol_version: config.protocol_version(),
            genesis_id: GenesisId::new([3; 32]),
            validation_context_id: ValidationContextId::new([4; 32]),
            consensus_config_id: config.id(),
            validator_set_id: config.validator_set().id(),
            height: 1,
            epoch: 0,
            round: 0,
            parent_block_id: None,
            previous_state_id: StateId::new([5; 32]),
            resulting_state_id: StateId::new([6; 32]),
            first_record_sequence: 1,
            record_count: 1,
            records_commitment: RecordCommitment::from_bytes([7; 32]),
        })
        .unwrap()
    }

    fn anchor(config: &ConsensusConfig) -> ConsensusAnchor {
        ConsensusAnchor::new(
            GenesisId::new([3; 32]),
            ValidationContextId::new([4; 32]),
            config.id(),
            StateId::new([5; 32]),
            [0; 32],
        )
    }

    #[test]
    fn a_quorum_and_valid_signatures_create_verified_finality() {
        let config = config();
        let header = header(&config);
        let certificate = FinalityCertificate::new(
            FinalityTarget::from_header(&header),
            vec![VoteEvidence::new(ValidatorId::new([1; 32]), vec![9]).unwrap()],
        )
        .unwrap();

        let verified = certificate
            .verify(&header, &anchor(&config), &config, &AcceptAll)
            .unwrap();
        assert_eq!(verified.block_id(), header.id());
        assert_eq!(verified.height(), 1);
        assert_eq!(
            certificate.verify(&header, &anchor(&config), &config, &RejectAll),
            Err(ConsensusError::InvalidSignature {
                validator: ValidatorId::new([1; 32]),
            })
        );
    }

    #[test]
    fn below_two_thirds_is_not_final() {
        let config = config();
        let header = header(&config);
        let certificate = FinalityCertificate::new(
            FinalityTarget::from_header(&header),
            vec![VoteEvidence::new(ValidatorId::new([2; 32]), vec![9]).unwrap()],
        )
        .unwrap();

        assert_eq!(
            certificate.verify(&header, &anchor(&config), &config, &AcceptAll),
            Err(ConsensusError::InsufficientVotingPower {
                signed: 1,
                required: 3,
            })
        );
    }
}
