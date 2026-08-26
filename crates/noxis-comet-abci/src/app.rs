use noxis_execution::{BlockProposal, ExecutedBlock, ExecutionReceipt};
use noxis_record_chain::RecordHash;
use noxis_storage::{DurableBlockReceipt, PersistentExecution};
use noxis_types::{AppHash, StateId, TransactionIntentId};

use crate::{CometAbciError, CometBftDecision, CometBftValidator, CometIdentity, MempoolOverlay};

/// Stable outcome returned for a proposal received from CometBFT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProposalStatus {
    Accept,
    Reject,
}

/// Minimal, transport-neutral outcome of `CheckTx`.
///
/// `code` is deliberately stable and does not expose cryptographic failure
/// details to a peer: zero means admitted to the local overlay and one means
/// rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckTxResult {
    pub accepted: bool,
    pub code: u32,
}

/// One deterministic transaction outcome to map into an ABCI event/result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxResult {
    pub code: u32,
    pub transaction_intent_id: TransactionIntentId,
    pub record_hash: RecordHash,
    pub resulting_state_id: StateId,
}

/// The deterministic application commitment and per-transaction outcomes of
/// one finalized Noxis block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizeBlockResult {
    pub app_hash: AppHash,
    pub transaction_results: Vec<TxResult>,
}

/// State reported by `Info`, derived only from the durable journal tip.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppInfo {
    pub last_block_height: i64,
    pub app_hash: Option<AppHash>,
}

/// Canonical subset of a CometBFT v0.38 `InitChain` request that defines the
/// immutable Noxis/Comet boundary.
///
/// The TCP/protobuf adapter must decode the request, compute the canonical
/// parameter-document digest, associate each observed Comet Ed25519 key with
/// its expected Noxis validator ID, and pass the resulting values here. The
/// core then compares every value with the genesis-bound mapping before any
/// block can execute.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitChainRequest<'a> {
    chain_id: &'a str,
    initial_height: i64,
    parameters_sha256: [u8; 32],
    validators: &'a [CometBftValidator],
}

impl<'a> InitChainRequest<'a> {
    pub const fn new(
        chain_id: &'a str,
        initial_height: i64,
        parameters_sha256: [u8; 32],
        validators: &'a [CometBftValidator],
    ) -> Self {
        Self {
            chain_id,
            initial_height,
            parameters_sha256,
            validators,
        }
    }
}

#[derive(Clone, Debug)]
struct PendingFinalization {
    engine_decision: CometBftDecision,
    transactions: Vec<Vec<u8>>,
    executed: ExecutedBlock,
    result: FinalizeBlockResult,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Lifecycle {
    GenesisUnverified,
    Running,
}

/// Stateful, transport-neutral ABCI lifecycle coordinator.
///
/// It owns the sole writable [`PersistentExecution`] instance. Proposal
/// methods work exclusively on discardable state; only [`Self::commit`] can
/// append an `NXCB` frame. A TCP/protobuf adapter must serialize access to one
/// of these cores (or a shared mutex around it) and translate its own request
/// and response types at the boundary.
pub struct NoxisCometCore {
    identity: CometIdentity,
    execution: PersistentExecution,
    mempool: MempoolOverlay,
    pending: Option<PendingFinalization>,
    lifecycle: Lifecycle,
}

impl NoxisCometCore {
    /// Creates a core around an already replay-verified durable journal.
    pub fn new(execution: PersistentExecution) -> Self {
        let identity = CometIdentity::from_genesis(execution.comet_bft_genesis().clone());
        let mempool = MempoolOverlay::new(execution.candidate_execution_state());
        let lifecycle = if execution.committed_state().height() == 0 {
            Lifecycle::GenesisUnverified
        } else {
            Lifecycle::Running
        };
        Self {
            identity,
            execution,
            mempool,
            pending: None,
            // A recovered non-genesis journal has already passed its original
            // bootstrap. A fresh journal must receive a matching InitChain
            // before it is allowed to execute a consensus block.
            lifecycle,
        }
    }

    pub fn identity(&self) -> &CometIdentity {
        &self.identity
    }

    /// Returns only the height and commitment that have completed durability.
    pub fn info(&self) -> Result<AppInfo, CometAbciError> {
        let durable_height = self.execution.committed_state().height();
        let last_block_height = if durable_height == 0 {
            0
        } else {
            self.identity
                .engine_height(durable_height)
                .map_err(CometAbciError::Height)?
        };
        Ok(AppInfo {
            last_block_height,
            app_hash: self.execution.app_hash(),
        })
    }

    /// Validates the immutable identity announced by CometBFT at bootstrap.
    ///
    /// No durable state is created here. Once any Noxis block is durable,
    /// calling `InitChain` is a configuration error.
    pub fn init_chain(&mut self, request: InitChainRequest<'_>) -> Result<(), CometAbciError> {
        if self.execution.committed_state().height() != 0 {
            return Err(CometAbciError::InitChainAfterCommit);
        }
        let genesis = self.identity.engine_genesis();
        if request.chain_id != self.identity.chain_id()
            || request.initial_height != self.identity.initial_height()
            || request.parameters_sha256 != self.identity.parameters_sha256()
            || request.validators != genesis.validators().validators()
        {
            return Err(CometAbciError::InitChainMismatch);
        }
        self.lifecycle = Lifecycle::Running;
        Ok(())
    }

    /// Performs local, non-durable mempool admission.
    ///
    /// The overlay includes earlier admitted transactions, so a second local
    /// transaction that spends an already-pending nullifier is rejected before
    /// proposal construction.
    pub fn check_tx(&mut self, transaction: &[u8]) -> CheckTxResult {
        if self.lifecycle != Lifecycle::Running {
            return CheckTxResult {
                accepted: false,
                code: 1,
            };
        }
        match self.mempool.admit(&self.execution, transaction) {
            Ok(()) => CheckTxResult {
                accepted: true,
                code: 0,
            },
            Err(_) => CheckTxResult {
                accepted: false,
                code: 1,
            },
        }
    }

    /// Selects a valid, stable-order subset within both Comet and Noxis limits.
    ///
    /// Invalid entries are omitted rather than making an honest proposer's
    /// whole candidate unusable. This function neither retains the selection
    /// nor changes durable state.
    pub fn prepare_proposal(
        &self,
        engine_height: i64,
        engine_maximum_transaction_bytes: i64,
        next_validators_hash: [u8; 32],
        transactions: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, CometAbciError> {
        self.ensure_initialized()?;
        self.ensure_next_engine_height(engine_height)?;
        if next_validators_hash != self.identity.engine_genesis().validators().hash() {
            return Err(CometAbciError::UnexpectedNextValidatorsHash);
        }
        let engine_limit = usize::try_from(engine_maximum_transaction_bytes).map_err(|_| {
            CometAbciError::NegativeMaximumTransactionBytes(engine_maximum_transaction_bytes)
        })?;
        let byte_limit =
            engine_limit.min(self.execution.maximum_block_transaction_bytes() as usize);
        let record_limit = self.execution.maximum_block_records() as usize;
        let mut candidate = self.execution.candidate_execution_state();
        let mut selected = Vec::with_capacity(transactions.len().min(record_limit));
        let mut total_bytes = 0_usize;

        for transaction in transactions {
            if selected.len() == record_limit {
                break;
            }
            let Some(next_total) = total_bytes.checked_add(transaction.len()) else {
                continue;
            };
            if next_total > byte_limit {
                continue;
            }
            let mut next_candidate = candidate.clone();
            if self
                .execution
                .simulate_transaction(&mut next_candidate, transaction)
                .is_err()
            {
                continue;
            }
            candidate = next_candidate;
            total_bytes = next_total;
            selected.push(transaction.clone());
        }
        Ok(selected)
    }

    /// Re-executes the exact received proposal without writing it.
    pub fn process_proposal(
        &self,
        engine_decision: CometBftDecision,
        transactions: &[Vec<u8>],
    ) -> Result<ProposalStatus, CometAbciError> {
        self.ensure_initialized()?;
        engine_decision
            .validate_for(
                self.identity.engine_genesis(),
                self.expected_next_noxis_height()?,
            )
            .map_err(|error| CometAbciError::EngineIdentity(Box::new(error)))?;
        match self.execute_for_engine_decision(engine_decision, transactions) {
            Ok(_) => Ok(ProposalStatus::Accept),
            Err(CometAbciError::Storage(noxis_storage::PersistentExecutionError::Execution(_))) => {
                Ok(ProposalStatus::Reject)
            }
            Err(error) => Err(error),
        }
    }

    /// Finalizes one exact proposal in volatile memory and returns its AppHash.
    ///
    /// Repeating the same request is idempotent. Different bytes at the same
    /// pending height are rejected, which prevents accidentally committing a
    /// result that was not returned to CometBFT.
    pub fn finalize_block(
        &mut self,
        engine_decision: CometBftDecision,
        transactions: &[Vec<u8>],
    ) -> Result<FinalizeBlockResult, CometAbciError> {
        self.ensure_initialized()?;
        if let Some(pending) = &self.pending {
            if pending.engine_decision == engine_decision && pending.transactions == transactions {
                return Ok(pending.result.clone());
            }
            return Err(CometAbciError::FinalizeConflict {
                engine_height: engine_decision.height(),
            });
        }
        engine_decision
            .validate_for(
                self.identity.engine_genesis(),
                self.expected_next_noxis_height()?,
            )
            .map_err(|error| CometAbciError::EngineIdentity(Box::new(error)))?;
        let executed = self.execute_for_engine_decision(engine_decision, transactions)?;
        let result = FinalizeBlockResult {
            app_hash: executed.app_hash(),
            transaction_results: executed.receipts().iter().copied().map(tx_result).collect(),
        };
        self.pending = Some(PendingFinalization {
            engine_decision,
            transactions: transactions.to_vec(),
            executed,
            result: result.clone(),
        });
        Ok(result)
    }

    /// Makes the sole finalized candidate durable, then rebuilds the mempool.
    pub fn commit(&mut self) -> Result<DurableBlockReceipt, CometAbciError> {
        self.ensure_initialized()?;
        let pending = self
            .pending
            .as_ref()
            .ok_or(CometAbciError::MissingFinalizedBlock)?;
        let receipt = self
            .execution
            .commit(&pending.executed)
            .map_err(CometAbciError::Storage)?;
        self.pending = None;
        self.mempool
            .reset(self.execution.candidate_execution_state());
        Ok(receipt)
    }

    pub fn admitted_transaction_count(&self) -> usize {
        self.mempool.len()
    }

    fn ensure_next_engine_height(&self, engine_height: i64) -> Result<u64, CometAbciError> {
        let expected_noxis_height = self.expected_next_noxis_height()?;
        let expected_engine_height = self
            .identity
            .engine_height(expected_noxis_height)
            .map_err(CometAbciError::Height)?;
        if engine_height != expected_engine_height {
            return Err(CometAbciError::UnexpectedEngineHeight {
                expected: expected_engine_height,
                actual: engine_height,
            });
        }
        Ok(expected_noxis_height)
    }

    fn expected_next_noxis_height(&self) -> Result<u64, CometAbciError> {
        self.execution
            .committed_state()
            .height()
            .checked_add(1)
            .ok_or(CometAbciError::Height(
                crate::HeightMappingError::HeightOverflow,
            ))
    }

    fn ensure_initialized(&self) -> Result<(), CometAbciError> {
        if self.lifecycle == Lifecycle::Running {
            Ok(())
        } else {
            Err(CometAbciError::ConsensusBeforeInitChain)
        }
    }

    fn execute_for_engine_decision(
        &self,
        engine_decision: CometBftDecision,
        transactions: &[Vec<u8>],
    ) -> Result<ExecutedBlock, CometAbciError> {
        let noxis_height = self.ensure_next_engine_height(engine_decision.height())?;
        self.execution
            .execute(BlockProposal {
                height: noxis_height,
                comet_decision: engine_decision,
                transactions,
            })
            .map_err(CometAbciError::Storage)
    }
}

fn tx_result(receipt: ExecutionReceipt) -> TxResult {
    TxResult {
        code: 0,
        transaction_intent_id: receipt.transaction_intent_id,
        record_hash: receipt.record_hash,
        resulting_state_id: receipt.resulting_state_id,
    }
}
