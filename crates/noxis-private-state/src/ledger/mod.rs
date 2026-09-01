//! Candidate private-ledger boundary.
//!
//! Representation, invariants and mutation are kept separate so reviewers can
//! audit what is stored, what must be true, and where state changes happen.

mod error;
mod invariants;
mod model;
mod mutation;

pub use error::{CandidatePrivateLedgerError, CandidatePrivateTransferAuthorizationError};
pub use model::{
    CandidatePrivateLedgerStateV1, CandidatePrivateTransferAdmissionReceiptV1,
    CandidatePrivateTransferAuthorizer, CandidatePrivateTransferRequestV1,
};
