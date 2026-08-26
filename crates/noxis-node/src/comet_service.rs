//! Composition root for a genesis-bound, loopback-only CometBFT ABCI service.
//!
//! The local node API persists independent `NXRF` transitions. This service
//! instead owns an `NXCB` block journal, so both modes are explicitly recorded
//! in the runtime manifest and cannot accidentally share one data directory.

use std::{
    fmt,
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
};

use noxis_comet_abci::{CometAbciServer, CometAbciServerError, NoxisCometCore};
use noxis_config::{ConfigError, GenesisConfig};
use noxis_crypto::ProofVerifier;
use noxis_execution::{ExecutionContext, ExecutionError};
use noxis_ledger::MintPolicy;
use noxis_runtime::{DataDirectory, NodeRuntime, RuntimeError, StorageMode};
use noxis_storage::{PersistentExecution, PersistentExecutionError};

/// One validated TCP endpoint for the local, unauthenticated ABCI protocol.
///
/// CometBFT and the application must run under the same local security
/// boundary. ABCI socket traffic is not authenticated, so publicly reachable
/// addresses are deliberately rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalAbciEndpoint(SocketAddr);

impl LocalAbciEndpoint {
    /// Validates an endpoint after normal address resolution.
    pub fn resolve(address: impl ToSocketAddrs) -> Result<Self, LocalAbciEndpointError> {
        let addresses = address
            .to_socket_addrs()
            .map_err(LocalAbciEndpointError::Resolve)?;
        let endpoint = addresses
            .into_iter()
            .next()
            .ok_or(LocalAbciEndpointError::NoResolvedAddress)?;
        Self::new(endpoint)
    }

    /// Accepts only a loopback socket address.
    pub const fn new(address: SocketAddr) -> Result<Self, LocalAbciEndpointError> {
        if address.ip().is_loopback() {
            Ok(Self(address))
        } else {
            Err(LocalAbciEndpointError::NotLoopback(address))
        }
    }

    pub const fn socket_addr(self) -> SocketAddr {
        self.0
    }
}

/// Static service inputs assembled by an operator-controlled configuration layer.
#[derive(Clone, Debug)]
pub struct CometNodeServiceConfig {
    data_directory: DataDirectory,
    genesis: GenesisConfig,
    abci_endpoint: LocalAbciEndpoint,
}

impl CometNodeServiceConfig {
    pub const fn new(
        data_directory: DataDirectory,
        genesis: GenesisConfig,
        abci_endpoint: LocalAbciEndpoint,
    ) -> Self {
        Self {
            data_directory,
            genesis,
            abci_endpoint,
        }
    }

    pub const fn data_directory(&self) -> &DataDirectory {
        &self.data_directory
    }

    pub const fn genesis(&self) -> &GenesisConfig {
        &self.genesis
    }

    pub const fn abci_endpoint(&self) -> LocalAbciEndpoint {
        self.abci_endpoint
    }
}

/// One initialized CometBFT application service.
///
/// The caller must supply the concrete proof verifier and mint policy. This
/// crate intentionally provides no permissive fallback, no private validator
/// key handling and no public-network listener.
pub struct CometNodeService {
    runtime: NodeRuntime,
    abci: CometAbciServer,
}

impl CometNodeService {
    /// Initializes the immutable directory identity, replays the authoritative
    /// block journal, then binds a loopback-only ABCI listener.
    pub fn open<V, P>(
        config: CometNodeServiceConfig,
        verifier: V,
        mint_policy: P,
    ) -> Result<Self, CometNodeServiceError>
    where
        V: ProofVerifier + 'static,
        P: MintPolicy + 'static,
    {
        let comet_genesis = config
            .genesis
            .comet_bft_genesis()
            .cloned()
            .ok_or(CometNodeServiceError::EngineNeutralGenesis)?;
        let chain_anchor = config
            .genesis
            .chain_anchor()
            .map_err(CometNodeServiceError::Config)?;
        let consensus_anchor = config
            .genesis
            .consensus_anchor()
            .map_err(CometNodeServiceError::Config)?;
        let initial_state = config
            .genesis
            .build_ledger_state()
            .map_err(CometNodeServiceError::Config)?;
        let context = ExecutionContext::new(
            chain_anchor,
            config.genesis.validation_context(),
            consensus_anchor,
            Arc::new(config.genesis.consensus_config().clone()),
            comet_genesis,
            Arc::new(verifier),
            Arc::new(mint_policy),
        )
        .map_err(CometNodeServiceError::Execution)?;
        let runtime = NodeRuntime::open_or_initialize_with_storage_mode(
            config.data_directory,
            config.genesis,
            StorageMode::CometBlockJournalV1,
        )
        .map_err(CometNodeServiceError::Runtime)?;
        let execution =
            PersistentExecution::open(runtime.block_journal_path(), initial_state, context)
                .map_err(CometNodeServiceError::PersistentExecution)?;
        let abci = CometAbciServer::bind(
            config.abci_endpoint.socket_addr(),
            NoxisCometCore::new(execution),
        )
        .map_err(CometNodeServiceError::Abci)?;
        Ok(Self { runtime, abci })
    }

    /// Address selected for the local ABCI listener.
    pub fn local_addr(&self) -> Result<SocketAddr, CometNodeServiceError> {
        self.abci.local_addr().map_err(CometNodeServiceError::Abci)
    }

    /// Serves CometBFT's concurrent local ABCI connections until listener failure.
    pub fn serve(&self) -> Result<(), CometNodeServiceError> {
        self.abci.serve().map_err(CometNodeServiceError::Abci)
    }

    /// Asks the serving loop to stop accepting new ABCI connections.
    ///
    /// The caller remains responsible for joining the thread running
    /// [`Self::serve`]. Existing connections finish or expire under the
    /// server's bounded idle timeout.
    pub fn request_shutdown(&self) {
        self.abci.request_shutdown();
    }

    /// Returns the held runtime, including its immutable storage-mode manifest.
    pub fn runtime(&self) -> &NodeRuntime {
        &self.runtime
    }
}

/// A supplied address cannot safely host the local ABCI protocol.
#[derive(Debug)]
pub enum LocalAbciEndpointError {
    Resolve(std::io::Error),
    NoResolvedAddress,
    NotLoopback(SocketAddr),
}

impl fmt::Display for LocalAbciEndpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolve(error) => {
                write!(formatter, "cannot resolve local ABCI endpoint: {error}")
            }
            Self::NoResolvedAddress => {
                formatter.write_str("local ABCI endpoint resolved to no address")
            }
            Self::NotLoopback(address) => write!(
                formatter,
                "ABCI endpoint {address} is not loopback; the unauthenticated protocol must stay local"
            ),
        }
    }
}

impl std::error::Error for LocalAbciEndpointError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Resolve(error) => Some(error),
            Self::NoResolvedAddress | Self::NotLoopback(_) => None,
        }
    }
}

/// A failure while composing the local CometBFT service.
#[derive(Debug)]
pub enum CometNodeServiceError {
    EngineNeutralGenesis,
    Config(ConfigError),
    Runtime(RuntimeError),
    Execution(ExecutionError),
    PersistentExecution(PersistentExecutionError),
    Abci(CometAbciServerError),
}

impl fmt::Display for CometNodeServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EngineNeutralGenesis => formatter.write_str(
                "CometBFT service requires a genesis with an explicit CometBFT identity and validator mapping",
            ),
            Self::Config(error) => write!(formatter, "invalid CometBFT service genesis: {error}"),
            Self::Runtime(error) => write!(formatter, "cannot establish CometBFT service runtime: {error}"),
            Self::Execution(error) => write!(formatter, "cannot establish deterministic execution: {error}"),
            Self::PersistentExecution(error) => write!(formatter, "cannot recover consensus block journal: {error}"),
            Self::Abci(error) => write!(formatter, "cannot serve local ABCI: {error}"),
        }
    }
}

impl std::error::Error for CometNodeServiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            Self::Runtime(error) => Some(error),
            Self::Execution(error) => Some(error),
            Self::PersistentExecution(error) => Some(error),
            Self::Abci(error) => Some(error),
            Self::EngineNeutralGenesis => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noxis_consensus::{
        CometBftNetworkIdentity, ConsensusConfig, Validator, ValidatorSet, ValidatorVerificationKey,
    };
    use noxis_crypto::{
        CryptoSuite, Proof, TransferStatement, ValidationContext, VerificationError,
    };
    use noxis_ledger::DenyAllMints;
    use noxis_types::{
        AssetDefinition, AssetId, AssetKind, MintPolicyId, ProofVerifierId, ValidatorId,
    };
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static TEMPORARY_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TemporaryDirectory(PathBuf);

    impl TemporaryDirectory {
        fn new() -> Self {
            let sequence = TEMPORARY_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("current time is after the Unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "noxis-comet-node-service-test-{}-{nanos}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("test directory can be created");
            Self(path)
        }
    }

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct AcceptingVerifier;

    impl ProofVerifier for AcceptingVerifier {
        fn proof_verifier_id(&self) -> ProofVerifierId {
            ProofVerifierId::new([1; 32])
        }

        fn verify_transfer(
            &self,
            _: &TransferStatement,
            _: &Proof,
        ) -> Result<(), VerificationError> {
            Ok(())
        }
    }

    struct WrongVerifier;

    impl ProofVerifier for WrongVerifier {
        fn proof_verifier_id(&self) -> ProofVerifierId {
            ProofVerifierId::new([9; 32])
        }

        fn verify_transfer(
            &self,
            _: &TransferStatement,
            _: &Proof,
        ) -> Result<(), VerificationError> {
            Ok(())
        }
    }

    fn comet_genesis() -> GenesisConfig {
        let asset =
            AssetDefinition::new(AssetId::new([2; 32]), "USDX", AssetKind::Synthetic).unwrap();
        GenesisConfig::new_with_comet_bft_identity(
            4,
            vec![asset],
            ValidationContext::new(
                CryptoSuite::RESEARCH_V1,
                ProofVerifierId::new([1; 32]),
                MintPolicyId::new([0; 32]),
            ),
            ConsensusConfig::new(
                1,
                100,
                1_024,
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
            .unwrap(),
            CometBftNetworkIdentity::new("noxis-node-test", 1, "cometbft-0.38", [7; 32]).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn rejects_a_non_loopback_abci_listener() {
        let error = LocalAbciEndpoint::new("0.0.0.0:26658".parse().unwrap()).unwrap_err();
        assert!(matches!(error, LocalAbciEndpointError::NotLoopback(_)));
    }

    #[test]
    fn opens_a_loopback_service_with_a_dedicated_block_journal() {
        let workspace = TemporaryDirectory::new();
        let data_directory = DataDirectory::new(workspace.0.join("comet-node")).unwrap();
        let service = CometNodeService::open(
            CometNodeServiceConfig::new(
                data_directory.clone(),
                comet_genesis(),
                LocalAbciEndpoint::new("127.0.0.1:0".parse().unwrap()).unwrap(),
            ),
            AcceptingVerifier,
            DenyAllMints,
        )
        .unwrap();

        assert!(service.local_addr().unwrap().ip().is_loopback());
        assert_eq!(
            service.runtime().storage_mode(),
            StorageMode::CometBlockJournalV1
        );
        assert!(data_directory.block_journal_path().is_file());
        assert!(!data_directory.ledger_path().exists());
    }

    #[test]
    fn refuses_wrong_crypto_components_before_creating_node_data() {
        let workspace = TemporaryDirectory::new();
        let data_directory = DataDirectory::new(workspace.0.join("uncreated-comet-node")).unwrap();
        let result = CometNodeService::open(
            CometNodeServiceConfig::new(
                data_directory.clone(),
                comet_genesis(),
                LocalAbciEndpoint::new("127.0.0.1:0".parse().unwrap()).unwrap(),
            ),
            WrongVerifier,
            DenyAllMints,
        );

        assert!(matches!(result, Err(CometNodeServiceError::Execution(_))));
        assert!(!data_directory.path().exists());
    }

    #[test]
    fn refuses_engine_neutral_genesis_before_creating_node_data() {
        let workspace = TemporaryDirectory::new();
        let data_directory = DataDirectory::new(workspace.0.join("uncreated-comet-node")).unwrap();
        let asset =
            AssetDefinition::new(AssetId::new([2; 32]), "USDX", AssetKind::Synthetic).unwrap();
        let genesis = GenesisConfig::new(
            4,
            vec![asset],
            ValidationContext::new(
                CryptoSuite::RESEARCH_V1,
                ProofVerifierId::new([1; 32]),
                MintPolicyId::new([0; 32]),
            ),
            ConsensusConfig::new(
                1,
                100,
                1_024,
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
            .unwrap(),
        )
        .unwrap();

        let result = CometNodeService::open(
            CometNodeServiceConfig::new(
                data_directory.clone(),
                genesis,
                LocalAbciEndpoint::new("127.0.0.1:0".parse().unwrap()).unwrap(),
            ),
            AcceptingVerifier,
            DenyAllMints,
        );

        assert!(matches!(
            result,
            Err(CometNodeServiceError::EngineNeutralGenesis)
        ));
        assert!(!data_directory.path().exists());
    }
}
