//! Domain configuration for a Noxis node.
//!
//! This crate validates values already supplied by application wiring. It does
//! not parse files, read environment variables, touch the filesystem, or start
//! a node. Those boundaries belong to a future application layer.

use std::{
    collections::HashSet,
    fmt,
    path::{Path, PathBuf},
};

use noxis_consensus::{
    CometBftGenesis, CometBftNetworkIdentity, ConsensusAnchor, ConsensusConfig, ConsensusError,
    encode_consensus_config,
};
use noxis_crypto::{ValidationContext, ValidationContextError};
use noxis_ledger::{LedgerError, LedgerState};
use noxis_types::{AssetDefinition, AssetId, ChainAnchor, GenesisId};
use sha2::{Digest, Sha256};

/// Version of the canonical genesis identity encoding.
pub const GENESIS_ID_FORMAT_VERSION: u16 = 5;
/// Version of the currently implemented ledger acceptance rules.
///
/// This must change whenever a consensus-relevant validation rule changes.
pub const PROTOCOL_RULE_SET_VERSION: u16 = 5;
/// Operational bound for consensus configuration embedded in a genesis and
/// its local manifest. It prevents a valid but impractically large generic
/// validator set from becoming a deployable network configuration.
pub const MAX_GENESIS_CONSENSUS_CONFIG_BYTES: usize = 1024 * 1024;

const GENESIS_ID_DOMAIN: &[u8] = b"NOXIS/GENESIS-ID/V1\0";

/// The immutable configuration from which an empty Noxis ledger is created.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenesisConfig {
    tree_depth: u8,
    assets: Vec<AssetDefinition>,
    validation_context: ValidationContext,
    consensus_config: ConsensusConfig,
    comet_bft_genesis: Option<CometBftGenesis>,
}

impl GenesisConfig {
    /// Validates a genesis configuration before it can be used by a node.
    ///
    /// Asset registration is explicit. An empty asset list is valid at this
    /// domain layer, but no transaction can name an asset until a future
    /// governance mechanism registers one.
    pub fn new(
        tree_depth: u8,
        assets: Vec<AssetDefinition>,
        validation_context: ValidationContext,
        consensus_config: ConsensusConfig,
    ) -> Result<Self, ConfigError> {
        Self::new_inner(
            tree_depth,
            assets,
            validation_context,
            consensus_config,
            None,
        )
    }

    /// Creates a genesis explicitly bound to one CometBFT network identity.
    ///
    /// A BFT node must use this constructor. [`Self::new`] remains available
    /// only for engine-neutral local-domain tools and cannot bootstrap the
    /// Comet ABCI application.
    pub fn new_with_comet_bft_identity(
        tree_depth: u8,
        assets: Vec<AssetDefinition>,
        validation_context: ValidationContext,
        consensus_config: ConsensusConfig,
        comet_bft_identity: CometBftNetworkIdentity,
    ) -> Result<Self, ConfigError> {
        Self::new_inner(
            tree_depth,
            assets,
            validation_context,
            consensus_config,
            Some(comet_bft_identity),
        )
    }

    fn new_inner(
        tree_depth: u8,
        assets: Vec<AssetDefinition>,
        validation_context: ValidationContext,
        consensus_config: ConsensusConfig,
        comet_bft_identity: Option<CometBftNetworkIdentity>,
    ) -> Result<Self, ConfigError> {
        validate_tree_depth(tree_depth)?;
        validate_unique_assets(&assets)?;
        validation_context
            .validate()
            .map_err(ConfigError::InvalidValidationContext)?;
        let consensus_config_bytes = encode_consensus_config(&consensus_config);
        if consensus_config_bytes.len() > MAX_GENESIS_CONSENSUS_CONFIG_BYTES {
            return Err(ConfigError::ConsensusConfigTooLarge {
                actual: consensus_config_bytes.len(),
                maximum: MAX_GENESIS_CONSENSUS_CONFIG_BYTES,
            });
        }
        let mut assets = assets;
        assets.sort_unstable_by_key(|asset| asset.id);
        let comet_bft_genesis = comet_bft_identity
            .map(|identity| {
                CometBftGenesis::from_consensus_config(identity, consensus_config.validator_set())
            })
            .transpose()
            .map_err(ConfigError::InvalidCometBftGenesis)?;
        Ok(Self {
            tree_depth,
            assets,
            validation_context,
            consensus_config,
            comet_bft_genesis,
        })
    }

    /// The fixed depth of the commitment tree used by this genesis.
    pub const fn tree_depth(&self) -> u8 {
        self.tree_depth
    }

    /// Registered genesis assets in canonical ascending `AssetId` order.
    pub fn assets(&self) -> &[AssetDefinition] {
        &self.assets
    }

    /// Public identity of the proof verifier and mint policy required by this genesis.
    pub const fn validation_context(&self) -> ValidationContext {
        self.validation_context
    }

    /// Canonical validator, quorum and signature configuration for this network.
    pub const fn consensus_config(&self) -> &ConsensusConfig {
        &self.consensus_config
    }

    /// Immutable CometBFT genesis identity, if this genesis is authorized for
    /// the CometBFT consensus adapter.
    pub fn comet_bft_identity(&self) -> Option<&CometBftNetworkIdentity> {
        self.comet_bft_genesis
            .as_ref()
            .map(CometBftGenesis::identity)
    }

    /// Complete mapped CometBFT genesis, including the validator set that the
    /// engine will receive during `InitChain`.
    pub fn comet_bft_genesis(&self) -> Option<&CometBftGenesis> {
        self.comet_bft_genesis.as_ref()
    }

    /// Builds the corresponding empty ledger state and registers every genesis asset.
    pub fn build_ledger_state(&self) -> Result<LedgerState, ConfigError> {
        let mut state = LedgerState::new(self.tree_depth).map_err(ConfigError::Ledger)?;
        for asset in &self.assets {
            state
                .register_asset(asset.clone())
                .map_err(ConfigError::Ledger)?;
        }
        Ok(state)
    }

    /// Deterministic public identity of this genesis configuration.
    ///
    /// It excludes local paths, secrets, manifest bytes and runtime limits.
    /// The encoding commits to the current rule-set version, tree depth and
    /// canonical asset registry and validation context. Future rule changes
    /// require a new rule-set or genesis-ID format version rather than silently
    /// reusing this identity.
    pub fn genesis_id(&self) -> GenesisId {
        let mut hash = Sha256::new();
        hash.update(GENESIS_ID_DOMAIN);
        hash.update(GENESIS_ID_FORMAT_VERSION.to_be_bytes());
        hash.update(PROTOCOL_RULE_SET_VERSION.to_be_bytes());
        hash.update(self.validation_context.encode());
        let consensus_bytes = encode_consensus_config(&self.consensus_config);
        hash.update((consensus_bytes.len() as u32).to_be_bytes());
        hash.update(consensus_bytes);
        match &self.comet_bft_genesis {
            Some(genesis) => {
                hash.update([1]);
                let comet_identity_bytes = genesis.identity().encode();
                hash.update((comet_identity_bytes.len() as u32).to_be_bytes());
                hash.update(comet_identity_bytes);
                hash.update(genesis.validators().hash());
            }
            None => hash.update([0]),
        }
        hash.update([self.tree_depth]);
        hash.update((self.assets.len() as u32).to_be_bytes());
        for asset in &self.assets {
            hash.update(asset.id.0);
            hash.update([match asset.kind {
                noxis_types::AssetKind::NativeBacked => 1,
                noxis_types::AssetKind::Synthetic => 2,
            }]);
            hash.update([asset.ticker.len() as u8]);
            hash.update(asset.ticker.as_bytes());
        }
        GenesisId::new(hash.finalize().into())
    }

    /// Returns the immutable genesis identity and the matching empty-state ID.
    pub fn chain_anchor(&self) -> Result<ChainAnchor, ConfigError> {
        let genesis_id = self.genesis_id();
        let initial_state = self.build_ledger_state()?;
        let validation_context = self.validation_context;
        Ok(ChainAnchor::new(
            genesis_id,
            validation_context.id(),
            validation_context.proof_verifier_id(),
            validation_context.mint_policy_id(),
            initial_state.state_id(genesis_id),
        ))
    }

    /// Returns the immutable network domain required to accept consensus data.
    pub fn consensus_anchor(&self) -> Result<ConsensusAnchor, ConfigError> {
        let chain_anchor = self.chain_anchor()?;
        Ok(ConsensusAnchor::new(
            chain_anchor.genesis_id,
            chain_anchor.validation_context_id,
            self.consensus_config.id(),
            chain_anchor.genesis_state_id,
            self.comet_bft_genesis
                .as_ref()
                .map_or([0; 32], CometBftGenesis::id),
        ))
    }
}

/// Node-local configuration assembled from a validated genesis and a log path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeConfig {
    genesis: GenesisConfig,
    transaction_log_path: PathBuf,
}

impl NodeConfig {
    /// Creates a node configuration without opening or creating its log file.
    pub fn new(
        genesis: GenesisConfig,
        transaction_log_path: impl Into<PathBuf>,
    ) -> Result<Self, ConfigError> {
        let transaction_log_path = transaction_log_path.into();
        if transaction_log_path.as_os_str().is_empty() {
            return Err(ConfigError::EmptyTransactionLogPath);
        }
        Ok(Self {
            genesis,
            transaction_log_path,
        })
    }

    /// The validated genesis settings for this node.
    pub fn genesis(&self) -> &GenesisConfig {
        &self.genesis
    }

    /// Path where a future persistence layer will store the transaction log.
    pub fn transaction_log_path(&self) -> &Path {
        &self.transaction_log_path
    }

    /// Builds a new empty ledger from this node's configured genesis.
    pub fn build_ledger_state(&self) -> Result<LedgerState, ConfigError> {
        self.genesis.build_ledger_state()
    }

    /// Returns the genesis-bound state-chain anchor for this configuration.
    pub fn chain_anchor(&self) -> Result<ChainAnchor, ConfigError> {
        self.genesis.chain_anchor()
    }
}

fn validate_tree_depth(tree_depth: u8) -> Result<(), ConfigError> {
    // LedgerState is the single source of truth for Merkle-depth limits.
    LedgerState::new(tree_depth)
        .map(|_| ())
        .map_err(ConfigError::Ledger)
}

fn validate_unique_assets(assets: &[AssetDefinition]) -> Result<(), ConfigError> {
    let mut ids = HashSet::with_capacity(assets.len());
    for asset in assets {
        if !ids.insert(asset.id) {
            return Err(ConfigError::DuplicateGenesisAsset(asset.id));
        }
    }
    Ok(())
}

/// A reason node configuration cannot establish an unambiguous genesis state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigError {
    /// Tree depth is outside the range accepted by the ledger's Merkle tree.
    Ledger(LedgerError),
    /// The same asset identifier appeared more than once in the genesis list.
    DuplicateGenesisAsset(AssetId),
    /// The declared cryptographic-suite roles are invalid for this genesis.
    InvalidValidationContext(ValidationContextError),
    /// Consensus parameters must be valid before becoming part of genesis.
    InvalidConsensusConfig(ConsensusError),
    /// A deployable genesis must have a bounded consensus configuration.
    ConsensusConfigTooLarge { actual: usize, maximum: usize },
    /// The configured generic validator set cannot be mapped safely to the
    /// pinned CometBFT engine representation.
    InvalidCometBftGenesis(noxis_consensus::EngineIdentityError),
    /// A log path must identify a path, not an empty string.
    EmptyTransactionLogPath,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ledger(error) => {
                write!(formatter, "invalid genesis ledger configuration: {error}")
            }
            Self::DuplicateGenesisAsset(asset_id) => {
                write!(
                    formatter,
                    "genesis registers asset {asset_id} more than once"
                )
            }
            Self::InvalidValidationContext(error) => {
                write!(formatter, "invalid genesis validation context: {error}")
            }
            Self::InvalidConsensusConfig(error) => {
                write!(
                    formatter,
                    "invalid genesis consensus configuration: {error}"
                )
            }
            Self::ConsensusConfigTooLarge { actual, maximum } => write!(
                formatter,
                "genesis consensus configuration has {actual} bytes, above operational maximum {maximum}"
            ),
            Self::InvalidCometBftGenesis(error) => {
                write!(formatter, "invalid CometBFT genesis mapping: {error}")
            }
            Self::EmptyTransactionLogPath => {
                formatter.write_str("transaction log path cannot be empty")
            }
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Ledger(error) => Some(error),
            Self::InvalidValidationContext(error) => Some(error),
            Self::InvalidConsensusConfig(error) => Some(error),
            Self::InvalidCometBftGenesis(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use noxis_consensus::{
        CometBftNetworkIdentity, ConsensusConfig, Validator, ValidatorSet, ValidatorVerificationKey,
    };
    use noxis_crypto::{AlgorithmId, CryptoSuite, CryptoSuiteError, ValidationContext};
    use noxis_types::{AssetKind, MintPolicyId, ProofVerifierId, ValidatorId};

    use super::*;

    fn asset(id: u8, ticker: &str) -> AssetDefinition {
        AssetDefinition::new(AssetId::new([id; 32]), ticker, AssetKind::Synthetic).unwrap()
    }

    fn validation_context() -> ValidationContext {
        ValidationContext::new(
            CryptoSuite::RESEARCH_V1,
            ProofVerifierId::new([1; 32]),
            MintPolicyId::new([2; 32]),
        )
    }

    fn consensus_config() -> ConsensusConfig {
        ConsensusConfig::new(
            1,
            100,
            1024,
            0,
            ValidatorSet::new(vec![
                Validator::new(
                    ValidatorId::new([1; 32]),
                    1,
                    ValidatorVerificationKey::new(1, vec![1; 32]).unwrap(),
                )
                .unwrap(),
            ])
            .unwrap(),
        )
        .unwrap()
    }

    fn comet_identity(parameter_byte: u8) -> CometBftNetworkIdentity {
        CometBftNetworkIdentity::new(
            "noxis-config-test",
            1,
            "cometbft-0.38",
            [parameter_byte; 32],
        )
        .unwrap()
    }

    #[test]
    fn genesis_builds_an_empty_ledger_with_its_registered_assets() {
        let usdx = asset(1, "USDX");
        let genesis = GenesisConfig::new(
            4,
            vec![usdx.clone(), asset(2, "EURX")],
            validation_context(),
            consensus_config(),
        )
        .unwrap();
        let mut state = genesis.build_ledger_state().unwrap();

        assert_eq!(state.merkle_root().depth(), 4);
        assert_eq!(state.commitment_count(), 0);
        assert!(state.issued_supply(AssetId::new([1; 32])).is_none());
        assert!(matches!(
            state.register_asset(usdx),
            Err(LedgerError::AssetAlreadyRegistered(_))
        ));
    }

    #[test]
    fn rejects_an_invalid_tree_depth() {
        let error =
            GenesisConfig::new(0, vec![], validation_context(), consensus_config()).unwrap_err();
        assert!(matches!(error, ConfigError::Ledger(_)));
    }

    #[test]
    fn rejects_duplicate_asset_identifiers_even_with_different_metadata() {
        let duplicate_id = AssetId::new([7; 32]);
        let first = AssetDefinition::new(duplicate_id, "USDX", AssetKind::Synthetic).unwrap();
        let second = AssetDefinition::new(duplicate_id, "NATV", AssetKind::NativeBacked).unwrap();

        assert_eq!(
            GenesisConfig::new(
                4,
                vec![first, second],
                validation_context(),
                consensus_config()
            ),
            Err(ConfigError::DuplicateGenesisAsset(duplicate_id))
        );
    }

    #[test]
    fn rejects_a_genesis_with_an_invalid_cryptographic_suite_description() {
        let invalid_context = ValidationContext::new(
            CryptoSuite {
                hash: AlgorithmId::Ed25519,
                ..CryptoSuite::RESEARCH_V1
            },
            ProofVerifierId::new([1; 32]),
            MintPolicyId::new([2; 32]),
        );
        assert!(matches!(
            GenesisConfig::new(3, vec![], invalid_context, consensus_config()),
            Err(ConfigError::InvalidValidationContext(
                noxis_crypto::ValidationContextError::InvalidCryptoSuite(
                    CryptoSuiteError::AlgorithmRoleMismatch { .. }
                )
            ))
        ));
    }

    #[test]
    fn node_config_keeps_the_explicit_log_path_and_constructs_its_genesis() {
        let genesis = GenesisConfig::new(
            3,
            vec![asset(3, "GOLD")],
            validation_context(),
            consensus_config(),
        )
        .unwrap();
        let config = NodeConfig::new(genesis, "data/noxis.log").unwrap();

        assert_eq!(config.transaction_log_path(), Path::new("data/noxis.log"));
        assert_eq!(
            config.build_ledger_state().unwrap().merkle_root().depth(),
            3
        );
    }

    #[test]
    fn canonical_genesis_identity_ignores_input_asset_order_and_changes_with_rules() {
        let first = GenesisConfig::new(
            3,
            vec![asset(2, "EURX"), asset(1, "USDX")],
            validation_context(),
            consensus_config(),
        )
        .unwrap();
        let second = GenesisConfig::new(
            3,
            vec![asset(1, "USDX"), asset(2, "EURX")],
            validation_context(),
            consensus_config(),
        )
        .unwrap();
        assert_eq!(first.assets(), second.assets());
        assert_eq!(first.genesis_id(), second.genesis_id());
        assert_ne!(
            first.genesis_id(),
            GenesisConfig::new(
                4,
                vec![asset(1, "USDX")],
                validation_context(),
                consensus_config()
            )
            .unwrap()
            .genesis_id()
        );
        let anchor = first.chain_anchor().unwrap();
        assert_eq!(anchor.genesis_id, first.genesis_id());
        assert_eq!(
            anchor.genesis_state_id,
            first
                .build_ledger_state()
                .unwrap()
                .state_id(anchor.genesis_id)
        );
    }

    #[test]
    fn genesis_identity_commits_to_each_validation_component() {
        let assets = vec![asset(1, "USDX")];
        let baseline =
            GenesisConfig::new(3, assets.clone(), validation_context(), consensus_config())
                .unwrap();
        let changed_verifier = GenesisConfig::new(
            3,
            assets.clone(),
            ValidationContext::new(
                CryptoSuite::RESEARCH_V1,
                ProofVerifierId::new([7; 32]),
                MintPolicyId::new([2; 32]),
            ),
            consensus_config(),
        )
        .unwrap();
        let changed_mint_policy = GenesisConfig::new(
            3,
            assets.clone(),
            ValidationContext::new(
                CryptoSuite::RESEARCH_V1,
                ProofVerifierId::new([1; 32]),
                MintPolicyId::new([8; 32]),
            ),
            consensus_config(),
        )
        .unwrap();
        let changed_consensus = GenesisConfig::new(
            3,
            assets,
            validation_context(),
            ConsensusConfig::new(
                2,
                100,
                1024,
                0,
                ValidatorSet::new(vec![
                    Validator::new(
                        ValidatorId::new([1; 32]),
                        1,
                        ValidatorVerificationKey::new(1, vec![1]).unwrap(),
                    )
                    .unwrap(),
                ])
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();

        assert_ne!(baseline.genesis_id(), changed_verifier.genesis_id());
        assert_ne!(baseline.genesis_id(), changed_mint_policy.genesis_id());
        assert_ne!(baseline.genesis_id(), changed_consensus.genesis_id());
        assert_ne!(
            baseline.validation_context().id(),
            changed_verifier.validation_context().id()
        );
        assert_ne!(
            baseline.validation_context().id(),
            changed_mint_policy.validation_context().id()
        );
    }

    #[test]
    fn engine_bound_genesis_identity_commits_to_every_comet_identity_field() {
        let baseline = GenesisConfig::new_with_comet_bft_identity(
            3,
            vec![asset(1, "USDX")],
            validation_context(),
            consensus_config(),
            comet_identity(7),
        )
        .unwrap();
        let changed_parameters = GenesisConfig::new_with_comet_bft_identity(
            3,
            vec![asset(1, "USDX")],
            validation_context(),
            consensus_config(),
            comet_identity(8),
        )
        .unwrap();
        assert_ne!(baseline.genesis_id(), changed_parameters.genesis_id());
        assert!(baseline.comet_bft_identity().is_some());
        assert!(
            GenesisConfig::new(3, vec![], validation_context(), consensus_config())
                .unwrap()
                .comet_bft_identity()
                .is_none()
        );
    }

    #[test]
    fn comet_genesis_rejects_a_generic_validator_key_that_cannot_run_comet_v038() {
        let incompatible_consensus = ConsensusConfig::new(
            1,
            100,
            1024,
            0,
            ValidatorSet::new(vec![
                Validator::new(
                    ValidatorId::new([1; 32]),
                    1,
                    ValidatorVerificationKey::new(1, vec![1]).unwrap(),
                )
                .unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            GenesisConfig::new_with_comet_bft_identity(
                3,
                vec![],
                validation_context(),
                incompatible_consensus,
                comet_identity(7),
            ),
            Err(ConfigError::InvalidCometBftGenesis(_))
        ));
    }

    #[test]
    fn node_config_rejects_an_empty_log_path() {
        let genesis =
            GenesisConfig::new(3, vec![], validation_context(), consensus_config()).unwrap();
        assert_eq!(
            NodeConfig::new(genesis, PathBuf::new()),
            Err(ConfigError::EmptyTransactionLogPath)
        );
    }
}
