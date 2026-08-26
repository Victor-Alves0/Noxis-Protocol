//! Canonical, engine-neutral BFT consensus primitives for Noxis.
//!
//! This crate intentionally does not gossip messages, manage validator keys,
//! or execute a consensus state machine. It makes the data that a future BFT
//! engine must agree on unambiguous: weighted validator sets, block headers,
//! record commitments, and finality certificates. A certificate is never
//! considered final until both its quorum and every signature are verified by
//! a concrete [`FinalityVerifier`].

mod block;
mod codec;
mod config;
mod engine;
mod error;
mod finality;
mod hash;

pub use block::{BlockHeader, BlockHeaderInput, MAX_BLOCK_RECORDS, RecordCommitment};
pub use codec::{
    decode_block_header, decode_consensus_config, decode_finality_certificate, encode_block_header,
    encode_consensus_config, encode_finality_certificate,
};
pub use config::{
    ConsensusAnchor, ConsensusConfig, MAX_BLOCK_TRANSACTION_BYTES, MAX_VALIDATOR_PUBLIC_KEY_BYTES,
    MAX_VALIDATORS, Validator, ValidatorSet, ValidatorVerificationKey,
};
pub use engine::{
    COMET_BFT_ED25519_PUBLIC_KEY_LENGTH, COMET_BFT_ED25519_SIGNATURE_SCHEME, COMET_BFT_HASH_LENGTH,
    COMET_BFT_MAX_TOTAL_VOTING_POWER, COMET_BFT_NETWORK_IDENTITY_FORMAT_VERSION,
    COMET_BFT_PARAMETERS_SHA256_LENGTH, COMET_BFT_V0_38_COMPATIBILITY_VERSION,
    COMET_BFT_VALIDATOR_ADDRESS_LENGTH, CometBftDecision, CometBftGenesis, CometBftNetworkIdentity,
    CometBftValidator, CometBftValidatorSet, EngineIdentityError, MAX_COMET_BFT_CHAIN_ID_BYTES,
    MAX_COMET_BFT_COMPATIBILITY_VERSION_BYTES, MAX_COMET_BFT_NETWORK_IDENTITY_ENCODED_LENGTH,
    decode_comet_bft_network_identity,
};
pub use error::ConsensusError;
pub use finality::{
    FinalityCertificate, FinalityTarget, FinalityVerifier, MAX_SIGNATURE_BYTES, VerifiedFinality,
    VoteEvidence,
};
