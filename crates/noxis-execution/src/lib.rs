//! Deterministic, side-effect-free execution of already ordered Noxis blocks.
//!
//! This crate performs no network, clock, filesystem, mempool, or consensus
//! engine operation. It converts one proposed ordered batch into a candidate
//! ledger state, strict `NXRC` records, and a Noxis block header. A future ABCI
//! adapter may invoke the same executor for proposal validation and final block
//! execution; a separate storage crate must durably commit its output as one
//! logical unit.

mod candidate;
mod context;
mod error;
mod executor;
mod state;

pub use candidate::CandidateExecutionState;
pub use context::ExecutionContext;
pub use error::ExecutionError;
pub use executor::{
    BlockProposal, ExecutedBlock, ExecutionReceipt, execute_block, simulate_transaction,
};
pub use state::CommittedExecutionState;
