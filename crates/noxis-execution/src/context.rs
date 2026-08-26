use std::sync::Arc;

use noxis_consensus::{CometBftGenesis, CometBftNetworkIdentity, ConsensusAnchor, ConsensusConfig};
use noxis_crypto::{ProofVerifier, ValidationContext, ValidationContextError};
use noxis_ledger::MintPolicy;
use noxis_types::ChainAnchor;

use crate::ExecutionError;

/// Immutable dependencies required to deterministically execute one block.
///
/// Dependencies are shared, immutable values. Construction verifies that the
/// proof verifier, mint policy and validation context match the genesis-bound
/// chain anchor before any proposal can be processed. Owning shared references
/// lets a network adapter safely retain one deterministic context.
#[derive(Clone)]
pub struct ExecutionContext {
    chain_anchor: ChainAnchor,
    validation_context: ValidationContext,
    consensus_anchor: ConsensusAnchor,
    consensus_config: Arc<ConsensusConfig>,
    comet_bft_genesis: CometBftGenesis,
    verifier: Arc<dyn ProofVerifier>,
    mint_policy: Arc<dyn MintPolicy>,
}

impl ExecutionContext {
    pub fn new(
        chain_anchor: ChainAnchor,
        validation_context: ValidationContext,
        consensus_anchor: ConsensusAnchor,
        consensus_config: Arc<ConsensusConfig>,
        comet_bft_genesis: CometBftGenesis,
        verifier: Arc<dyn ProofVerifier>,
        mint_policy: Arc<dyn MintPolicy>,
    ) -> Result<Self, ExecutionError> {
        validation_context
            .validate()
            .map_err(ExecutionError::InvalidValidationContext)?;
        if validation_context.id() != chain_anchor.validation_context_id
            || validation_context.proof_verifier_id() != chain_anchor.proof_verifier_id
            || validation_context.mint_policy_id() != chain_anchor.mint_policy_id
        {
            return Err(ExecutionError::ValidationContextAnchorMismatch);
        }
        if consensus_anchor.genesis_id() != chain_anchor.genesis_id
            || consensus_anchor.validation_context_id() != chain_anchor.validation_context_id
            || consensus_anchor.genesis_state_id() != chain_anchor.genesis_state_id
            || consensus_anchor.consensus_config_id() != consensus_config.id()
            || consensus_anchor.engine_network_id() != comet_bft_genesis.id()
        {
            return Err(ExecutionError::ConsensusAnchorMismatch);
        }
        if verifier.proof_verifier_id() != chain_anchor.proof_verifier_id {
            return Err(ExecutionError::ProofVerifierMismatch {
                expected: chain_anchor.proof_verifier_id,
                actual: verifier.proof_verifier_id(),
            });
        }
        if mint_policy.mint_policy_id() != chain_anchor.mint_policy_id {
            return Err(ExecutionError::MintPolicyMismatch {
                expected: chain_anchor.mint_policy_id,
                actual: mint_policy.mint_policy_id(),
            });
        }
        Ok(Self {
            chain_anchor,
            validation_context,
            consensus_anchor,
            consensus_config,
            comet_bft_genesis,
            verifier,
            mint_policy,
        })
    }

    pub const fn chain_anchor(&self) -> ChainAnchor {
        self.chain_anchor
    }

    pub const fn validation_context(&self) -> ValidationContext {
        self.validation_context
    }

    pub const fn consensus_anchor(&self) -> &ConsensusAnchor {
        &self.consensus_anchor
    }

    pub fn consensus_config(&self) -> &ConsensusConfig {
        &self.consensus_config
    }

    /// CometBFT network identity that every executed consensus block must
    /// bind to. It is part of the genesis configuration, not mutable runtime
    /// input.
    pub fn comet_bft_identity(&self) -> &CometBftNetworkIdentity {
        self.comet_bft_genesis.identity()
    }

    /// Complete, genesis-bound CometBFT mapping including the validator set.
    pub fn comet_bft_genesis(&self) -> &CometBftGenesis {
        &self.comet_bft_genesis
    }

    pub fn verifier(&self) -> &dyn ProofVerifier {
        self.verifier.as_ref()
    }

    pub fn mint_policy(&self) -> &dyn MintPolicy {
        self.mint_policy.as_ref()
    }
}

impl From<ValidationContextError> for ExecutionError {
    fn from(value: ValidationContextError) -> Self {
        Self::InvalidValidationContext(value)
    }
}
