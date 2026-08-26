use noxis_ledger::LedgerState;
use noxis_record_chain::RecordChain;

use crate::CommittedExecutionState;

/// Discardable execution overlay used for mempools and proposal selection.
///
/// It has no block height, block identity or persistence authority. A caller
/// must discard it after proposal validation and still execute the final
/// ordered block against [`CommittedExecutionState`] before committing.
#[derive(Clone, Debug)]
pub struct CandidateExecutionState {
    ledger_state: LedgerState,
    record_chain: RecordChain,
}

impl CandidateExecutionState {
    /// Starts a candidate overlay from the current durable execution tip.
    pub fn from_committed(committed: &CommittedExecutionState) -> Self {
        Self {
            ledger_state: committed.ledger_state().clone(),
            record_chain: committed.record_chain(),
        }
    }

    pub fn ledger_state(&self) -> &LedgerState {
        &self.ledger_state
    }

    pub const fn record_chain(&self) -> RecordChain {
        self.record_chain
    }

    pub(crate) fn mutable_parts(&mut self) -> (&mut LedgerState, &mut RecordChain) {
        (&mut self.ledger_state, &mut self.record_chain)
    }
}
