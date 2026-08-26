use noxis_execution::CandidateExecutionState;
use noxis_storage::PersistentExecution;

use crate::CometAbciError;

/// A conservative local cap. The transport integration must also configure
/// Comet's own mempool to no higher than these values before enabling a node.
const MAX_PENDING_TRANSACTIONS: usize = 10_000;
const MAX_PENDING_TRANSACTION_BYTES: usize = 64 * 1024 * 1024;

/// Mutable, non-durable state used solely to reject conflicting mempool items.
#[derive(Clone, Debug)]
pub(crate) struct MempoolOverlay {
    candidate: CandidateExecutionState,
    transactions: Vec<Vec<u8>>,
    total_bytes: usize,
}

impl MempoolOverlay {
    pub(crate) fn new(candidate: CandidateExecutionState) -> Self {
        Self {
            candidate,
            transactions: Vec::new(),
            total_bytes: 0,
        }
    }

    pub(crate) fn reset(&mut self, candidate: CandidateExecutionState) {
        self.candidate = candidate;
        self.transactions.clear();
        self.total_bytes = 0;
    }

    /// Tests a transaction against all earlier locally admitted mempool items.
    /// A failed simulation never changes the overlay.
    pub(crate) fn admit(
        &mut self,
        execution: &PersistentExecution,
        transaction: &[u8],
    ) -> Result<(), CometAbciError> {
        if self.transactions.len() == MAX_PENDING_TRANSACTIONS {
            return Err(CometAbciError::MempoolLimitExceeded);
        }
        let total_bytes = self
            .total_bytes
            .checked_add(transaction.len())
            .filter(|total| *total <= MAX_PENDING_TRANSACTION_BYTES)
            .ok_or(CometAbciError::MempoolLimitExceeded)?;
        let mut next = self.candidate.clone();
        execution
            .simulate_transaction(&mut next, transaction)
            .map_err(CometAbciError::Storage)?;
        self.candidate = next;
        self.transactions.push(transaction.to_vec());
        self.total_bytes = total_bytes;
        Ok(())
    }

    pub(crate) fn len(&self) -> usize {
        self.transactions.len()
    }
}
