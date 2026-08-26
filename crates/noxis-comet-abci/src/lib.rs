//! Deterministic ABCI lifecycle core for a CometBFT-backed Noxis node.
//!
//! This crate deliberately contains no TCP server or protobuf bindings. It
//! implements the stateful contract those bindings must obey: proposal methods
//! are side-effect free, `FinalizeBlock` retains one volatile candidate, and
//! only `Commit` invokes the durable `NXCB` block journal.

mod app;
mod error;
mod heights;
mod mempool;
mod server;
mod wire;

pub use app::{
    AppInfo, CheckTxResult, FinalizeBlockResult, InitChainRequest, NoxisCometCore, ProposalStatus,
    TxResult,
};
pub use error::CometAbciError;
pub use heights::{CometIdentity, HeightMappingError};
pub use noxis_consensus::{
    CometBftDecision, CometBftGenesis, CometBftNetworkIdentity, CometBftValidator,
};
pub use server::{CometAbciServer, CometAbciServerError};
pub use wire::{MAX_ABCI_FRAME_BYTES, WireError, WireType};
