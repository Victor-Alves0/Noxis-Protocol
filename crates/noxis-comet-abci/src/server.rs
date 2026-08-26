//! Blocking TCP implementation of the CometBFT v0.38 ABCI socket protocol.
//!
//! Networking is deliberately thin: protobuf framing and request decoding live
//! in `wire`, while every stateful decision is delegated to `NoxisCometCore`.
//! A single mutex serializes calls across Comet's multiple ABCI connections,
//! preserving the lifecycle invariant that only `Commit` mutates durable state.

use std::{
    fmt, io,
    net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    sync::{Arc, Mutex, MutexGuard},
    thread,
};

use noxis_consensus::{CometBftDecision, CometBftValidator};
use sha2::{Digest, Sha256};

use crate::{
    CometAbciError, InitChainRequest, NoxisCometCore, ProposalStatus,
    wire::{self, InitValidatorUpdate, Request, Response, WireError},
};

/// A TCP listener serving the reviewed CometBFT v0.38 ABCI socket subset.
///
/// The listener is intentionally not a P2P or public client endpoint. It must
/// be bound to a local, access-controlled address managed together with the
/// CometBFT process that owns consensus transport and validator keys.
pub struct CometAbciServer {
    listener: TcpListener,
    core: Arc<Mutex<NoxisCometCore>>,
}

impl CometAbciServer {
    /// Binds one local ABCI listener around a replay-verified application core.
    pub fn bind(
        address: impl ToSocketAddrs,
        core: NoxisCometCore,
    ) -> Result<Self, CometAbciServerError> {
        let listener = TcpListener::bind(address).map_err(|source| CometAbciServerError::Io {
            operation: "bind ABCI TCP listener",
            source,
        })?;
        Ok(Self {
            listener,
            core: Arc::new(Mutex::new(core)),
        })
    }

    /// Address chosen by the operating system after binding, useful for local
    /// integration tests and service discovery wiring.
    pub fn local_addr(&self) -> Result<SocketAddr, CometAbciServerError> {
        self.listener
            .local_addr()
            .map_err(|source| CometAbciServerError::Io {
                operation: "read ABCI listener address",
                source,
            })
    }

    /// Accepts and serves exactly one ABCI TCP connection to completion.
    ///
    /// This makes test orchestration deterministic. Production startup should
    /// normally call [`Self::serve`] on a dedicated service thread.
    pub fn serve_one(&self) -> Result<(), CometAbciServerError> {
        let (stream, _) = self
            .listener
            .accept()
            .map_err(|source| CometAbciServerError::Io {
                operation: "accept ABCI TCP connection",
                source,
            })?;
        self.serve_connection(stream)
    }

    /// Serves successive CometBFT ABCI connections until the listener fails.
    ///
    /// Each connection receives an independent reader loop because CometBFT
    /// keeps its consensus, mempool and info connections open concurrently.
    /// The application core remains serialized by its mutex.
    pub fn serve(&self) -> Result<(), CometAbciServerError> {
        loop {
            let (stream, _) =
                self.listener
                    .accept()
                    .map_err(|source| CometAbciServerError::Io {
                        operation: "accept ABCI TCP connection",
                        source,
                    })?;
            let core = Arc::clone(&self.core);
            thread::spawn(move || {
                // A peer-level failure closes only that peer. Listener failure
                // is still returned by the accepting loop above for supervision.
                let _ = serve_socket(&core, stream);
            });
        }
    }

    /// Serves an already accepted stream. It is public for embedders that own
    /// socket acceptance separately, while retaining the same strict parser.
    pub fn serve_connection(&self, stream: TcpStream) -> Result<(), CometAbciServerError> {
        serve_socket(&self.core, stream)
    }
}

fn serve_socket(
    shared_core: &Arc<Mutex<NoxisCometCore>>,
    mut stream: TcpStream,
) -> Result<(), CometAbciServerError> {
    loop {
        let request = match wire::read_request(&mut stream) {
            Ok(Some(request)) => request,
            Ok(None) => return Ok(()),
            Err(error) => {
                let _ = wire::write_response(&mut stream, &Response::Exception(error.to_string()));
                return Err(CometAbciServerError::Wire(error));
            }
        };
        let response = match dispatch(shared_core, request) {
            Ok(response) => response,
            Err(error) => {
                let _ = wire::write_response(&mut stream, &Response::Exception(error.to_string()));
                return Err(error);
            }
        };
        wire::write_response(&mut stream, &response).map_err(CometAbciServerError::Wire)?;
    }
}

fn dispatch(
    shared_core: &Arc<Mutex<NoxisCometCore>>,
    request: Request,
) -> Result<Response, CometAbciServerError> {
    let mut core = lock_core(shared_core)?;
    match request {
        Request::Echo(message) => Ok(Response::Echo(message)),
        Request::Flush => Ok(Response::Flush),
        Request::Info => core
            .info()
            .map(Response::Info)
            .map_err(CometAbciServerError::Core),
        Request::InitChain {
            chain_id,
            consensus_parameters,
            validators,
            initial_height,
        } => {
            let validators = map_init_validators(&core, &validators)?;
            let parameters_sha256 = Sha256::digest(consensus_parameters).into();
            core.init_chain(InitChainRequest::new(
                &chain_id,
                initial_height,
                parameters_sha256,
                &validators,
            ))
            .map_err(CometAbciServerError::Core)?;
            Ok(Response::InitChain)
        }
        Request::Query => Ok(Response::QueryUnavailable),
        Request::CheckTx(transaction) => Ok(Response::CheckTx(core.check_tx(&transaction))),
        Request::Commit => core
            .commit()
            .map(|_| Response::Commit)
            .map_err(CometAbciServerError::Core),
        Request::ListSnapshots => Ok(Response::ListSnapshots),
        Request::OfferSnapshot => Ok(Response::OfferSnapshotAbort),
        Request::LoadSnapshotChunk => Ok(Response::LoadSnapshotChunk),
        Request::ApplySnapshotChunk => Ok(Response::ApplySnapshotChunkAbort),
        Request::PrepareProposal {
            maximum_transaction_bytes,
            transactions,
            height,
            next_validators_hash,
        } => core
            .prepare_proposal(
                height,
                maximum_transaction_bytes,
                next_validators_hash,
                &transactions,
            )
            .map(Response::PrepareProposal)
            .map_err(CometAbciServerError::Core),
        Request::ProcessProposal {
            transactions,
            block_hash,
            height,
            next_validators_hash,
        } => Ok(Response::ProcessProposal(
            decision_for(&core, height, block_hash, next_validators_hash)
                .and_then(|decision| core.process_proposal(decision, &transactions))
                .unwrap_or(ProposalStatus::Reject),
        )),
        Request::ExtendVote => Ok(Response::ExtendVote),
        Request::VerifyVoteExtension => Ok(Response::VerifyVoteExtensionReject),
        Request::FinalizeBlock {
            transactions,
            block_hash,
            height,
            next_validators_hash,
        } => {
            let decision = decision_for(&core, height, block_hash, next_validators_hash)?;
            core.finalize_block(decision, &transactions)
                .map(Response::FinalizeBlock)
                .map_err(CometAbciServerError::Core)
        }
    }
}

fn lock_core(
    shared_core: &Arc<Mutex<NoxisCometCore>>,
) -> Result<MutexGuard<'_, NoxisCometCore>, CometAbciServerError> {
    shared_core
        .lock()
        .map_err(|_| CometAbciServerError::CorePoisoned)
}

fn decision_for(
    core: &NoxisCometCore,
    height: i64,
    block_hash: [u8; 32],
    next_validators_hash: [u8; 32],
) -> Result<CometBftDecision, CometAbciError> {
    CometBftDecision::new(
        core.identity().engine_genesis(),
        height,
        block_hash,
        next_validators_hash,
    )
    .map_err(|error| CometAbciError::EngineIdentity(Box::new(error)))
}

fn map_init_validators(
    core: &NoxisCometCore,
    updates: &[InitValidatorUpdate],
) -> Result<Vec<CometBftValidator>, CometAbciServerError> {
    let expected = core.identity().engine_genesis().validators().validators();
    let mut mapped = Vec::with_capacity(updates.len());
    for update in updates {
        let validator = expected
            .iter()
            .find(|validator| validator.public_key() == update.public_key)
            .ok_or(CometAbciServerError::UnknownInitValidator)?;
        if validator.voting_power() != update.voting_power {
            return Err(CometAbciServerError::InitValidatorPowerMismatch);
        }
        mapped.push(
            CometBftValidator::from_comet_ed25519(
                validator.noxis_validator_id(),
                update.public_key,
                update.voting_power,
            )
            .map_err(|error| {
                CometAbciServerError::Core(CometAbciError::EngineIdentity(Box::new(error)))
            })?,
        );
    }
    mapped.sort_unstable_by(|left, right| {
        right
            .voting_power()
            .cmp(&left.voting_power())
            .then_with(|| left.address().cmp(&right.address()))
    });
    Ok(mapped)
}

/// A socket, framing, initialization-mapping or core-lifecycle failure.
#[derive(Debug)]
pub enum CometAbciServerError {
    Io {
        operation: &'static str,
        source: io::Error,
    },
    Wire(WireError),
    Core(CometAbciError),
    CorePoisoned,
    UnknownInitValidator,
    InitValidatorPowerMismatch,
}

impl fmt::Display for CometAbciServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, source } => write!(formatter, "cannot {operation}: {source}"),
            Self::Wire(error) => write!(formatter, "invalid ABCI socket data: {error}"),
            Self::Core(error) => write!(formatter, "ABCI application rejected request: {error}"),
            Self::CorePoisoned => formatter.write_str("ABCI application mutex is poisoned"),
            Self::UnknownInitValidator => {
                formatter.write_str("InitChain contains an unknown CometBFT validator")
            }
            Self::InitValidatorPowerMismatch => {
                formatter.write_str("InitChain validator power differs from genesis")
            }
        }
    }
}

impl std::error::Error for CometAbciServerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Wire(error) => Some(error),
            Self::Core(error) => Some(error),
            Self::CorePoisoned | Self::UnknownInitValidator | Self::InitValidatorPowerMismatch => {
                None
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        fs,
        io::{Read, Write},
        net::TcpStream,
        path::PathBuf,
        sync::Arc,
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };

    use noxis_consensus::{
        CometBftGenesis, CometBftNetworkIdentity, ConsensusAnchor, ConsensusConfig, Validator,
        ValidatorSet, ValidatorVerificationKey,
    };
    use noxis_crypto::{
        CryptoSuite, Proof, ProofVerifier, TransferStatement, ValidationContext, VerificationError,
    };
    use noxis_execution::ExecutionContext;
    use noxis_ledger::{DenyAllMints, LedgerState, MintPolicy};
    use noxis_storage::PersistentExecution;
    use noxis_types::{
        AssetDefinition, AssetId, AssetKind, ChainAnchor, GenesisId, MintPolicyId, ProofVerifierId,
        ValidatorId,
    };

    use super::*;

    const ASSET: AssetId = AssetId::new([1; 32]);
    const GENESIS_ID: GenesisId = GenesisId::new([2; 32]);

    struct AcceptingVerifier;

    impl ProofVerifier for AcceptingVerifier {
        fn proof_verifier_id(&self) -> ProofVerifierId {
            ProofVerifierId::new([3; 32])
        }

        fn verify_transfer(
            &self,
            _statement: &TransferStatement,
            _proof: &Proof,
        ) -> Result<(), VerificationError> {
            Ok(())
        }
    }

    fn test_core(path: PathBuf) -> NoxisCometCore {
        let mut ledger = LedgerState::new(4).unwrap();
        ledger
            .register_asset(AssetDefinition::new(ASSET, "USDX", AssetKind::Synthetic).unwrap())
            .unwrap();
        let verifier = AcceptingVerifier;
        let mint_policy = DenyAllMints;
        let validation_context = ValidationContext::new(
            CryptoSuite::RESEARCH_V1,
            verifier.proof_verifier_id(),
            mint_policy.mint_policy_id(),
        );
        let chain_anchor = ChainAnchor::new(
            GENESIS_ID,
            validation_context.id(),
            validation_context.proof_verifier_id(),
            validation_context.mint_policy_id(),
            ledger.state_id(GENESIS_ID),
        );
        let validators = ValidatorSet::new(vec![
            Validator::new(
                ValidatorId::new([4; 32]),
                1,
                ValidatorVerificationKey::new(1, vec![5; 32]).unwrap(),
            )
            .unwrap(),
        ])
        .unwrap();
        let config = ConsensusConfig::new(1, 10, 4_096, 0, validators).unwrap();
        let identity =
            CometBftNetworkIdentity::new("noxis-server-test", 1, "cometbft-0.38", [7; 32]).unwrap();
        let comet_genesis =
            CometBftGenesis::from_consensus_config(identity, config.validator_set()).unwrap();
        let consensus_anchor = ConsensusAnchor::new(
            chain_anchor.genesis_id,
            chain_anchor.validation_context_id,
            config.id(),
            chain_anchor.genesis_state_id,
            comet_genesis.id(),
        );
        let context = ExecutionContext::new(
            chain_anchor,
            validation_context,
            consensus_anchor,
            Arc::new(config),
            comet_genesis,
            Arc::new(verifier),
            Arc::new(mint_policy),
        )
        .unwrap();
        NoxisCometCore::new(PersistentExecution::open(path, ledger, context).unwrap())
    }

    #[test]
    fn serves_framed_echo_and_info_over_a_real_tcp_socket() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "noxis-comet-abci-server-test-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let server =
            CometAbciServer::bind("127.0.0.1:0", test_core(directory.join("blocks.nxcb"))).unwrap();
        let address = server.local_addr().unwrap();
        let task = thread::spawn(move || server.serve_one());
        let mut client = TcpStream::connect(address).unwrap();

        // Length 4, Request{echo: RequestEcho{message: ""}}.
        client.write_all(&[4, 0x0a, 2, 0x0a, 0]).unwrap();
        assert_eq!(read_frame(&mut client), vec![0x12, 2, 0x0a, 0]);

        // Length 2, Request{info: RequestInfo{}}.
        client.write_all(&[2, 0x1a, 0]).unwrap();
        let info = read_frame(&mut client);
        assert_eq!(info[0], 0x22); // Response.info field number 4.
        drop(client);
        task.join().unwrap().unwrap();
        fs::remove_dir_all(directory).unwrap();
    }

    fn read_frame(stream: &mut TcpStream) -> Vec<u8> {
        let mut length = 0_usize;
        let mut shift = 0;
        loop {
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte).unwrap();
            length |= usize::from(byte[0] & 0x7f) << shift;
            if byte[0] & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        let mut bytes = vec![0; length];
        stream.read_exact(&mut bytes).unwrap();
        bytes
    }
}
