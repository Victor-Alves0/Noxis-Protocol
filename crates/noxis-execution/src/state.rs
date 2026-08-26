use noxis_ledger::LedgerState;
use noxis_record_chain::{RecordChain, RecordHash};
use noxis_types::{BlockId, ChainAnchor};

use crate::ExecutionError;

/// State known to be committed before the next block is executed.
///
/// `height` counts Noxis execution blocks, not a future engine's height. An
/// ABCI adapter must map engine height explicitly rather than assuming both
/// counters begin at the same value.
#[derive(Clone, Debug)]
pub struct CommittedExecutionState {
    ledger_state: LedgerState,
    record_chain: RecordChain,
    height: u64,
    block_id: Option<BlockId>,
    terminal_record_hash: Option<RecordHash>,
}

impl CommittedExecutionState {
    /// Creates the pre-block state at network genesis.
    pub fn genesis(ledger_state: LedgerState, anchor: ChainAnchor) -> Result<Self, ExecutionError> {
        Self::from_parts(
            ledger_state,
            RecordChain::new(anchor.genesis_state_id),
            0,
            None,
            None,
            anchor,
        )
    }

    /// Constructs a state from verified recovery material inside this crate.
    ///
    /// Raw storage recovery must first prove its block tip and record chain;
    /// callers outside this crate cannot manufacture a committed tip directly.
    pub(crate) fn from_parts(
        ledger_state: LedgerState,
        record_chain: RecordChain,
        height: u64,
        block_id: Option<BlockId>,
        terminal_record_hash: Option<RecordHash>,
        anchor: ChainAnchor,
    ) -> Result<Self, ExecutionError> {
        let computed_state_id = ledger_state.state_id(anchor.genesis_id);
        if computed_state_id != record_chain.current_state_id() {
            return Err(ExecutionError::CommittedStateIdMismatch {
                expected: computed_state_id,
                actual: record_chain.current_state_id(),
            });
        }
        if height == 0 && (block_id.is_some() || terminal_record_hash.is_some()) {
            return Err(ExecutionError::InvalidGenesisExecutionState);
        }
        if height > 0 && block_id.is_none() {
            return Err(ExecutionError::MissingCommittedBlockId);
        }
        Ok(Self {
            ledger_state,
            record_chain,
            height,
            block_id,
            terminal_record_hash,
        })
    }

    pub fn ledger_state(&self) -> &LedgerState {
        &self.ledger_state
    }

    pub const fn record_chain(&self) -> RecordChain {
        self.record_chain
    }

    pub const fn height(&self) -> u64 {
        self.height
    }

    pub const fn block_id(&self) -> Option<BlockId> {
        self.block_id
    }

    pub const fn terminal_record_hash(&self) -> Option<RecordHash> {
        self.terminal_record_hash
    }

    pub(crate) fn from_executed_parts(
        ledger_state: LedgerState,
        record_chain: RecordChain,
        height: u64,
        block_id: BlockId,
        terminal_record_hash: Option<RecordHash>,
    ) -> Self {
        Self {
            ledger_state,
            record_chain,
            height,
            block_id: Some(block_id),
            terminal_record_hash,
        }
    }
}
