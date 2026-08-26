use noxis_types::{BlockId, ConsensusConfigId, FinalityCertificateId, ValidatorSetId};
use sha2::{Digest, Sha256};

/// All canonical consensus wire formats emitted by this release use version 3.
/// Version 2 did not commit the block-wide transaction-byte limit; older
/// layouts are intentionally rejected rather than heuristically read.
pub(crate) const CONSENSUS_FORMAT_VERSION: u16 = 3;
pub(crate) const CONFIG_ID_DOMAIN: &[u8] = b"NOXIS/CONSENSUS/V1/CONFIG";
pub(crate) const VALIDATOR_SET_ID_DOMAIN: &[u8] = b"NOXIS/CONSENSUS/V1/VALIDATOR-SET";
pub(crate) const BLOCK_ID_DOMAIN: &[u8] = b"NOXIS/CONSENSUS/V1/BLOCK";
pub(crate) const RECORD_COMMITMENT_DOMAIN: &[u8] = b"NOXIS/CONSENSUS/V1/RECORDS";
pub(crate) const CERTIFICATE_ID_DOMAIN: &[u8] = b"NOXIS/CONSENSUS/V1/FINALITY-CERTIFICATE";

pub(crate) fn config_id(bytes: &[u8]) -> ConsensusConfigId {
    ConsensusConfigId::new(hash(CONFIG_ID_DOMAIN, bytes))
}

pub(crate) fn validator_set_id(bytes: &[u8]) -> ValidatorSetId {
    ValidatorSetId::new(hash(VALIDATOR_SET_ID_DOMAIN, bytes))
}

pub(crate) fn block_id(bytes: &[u8]) -> BlockId {
    BlockId::new(hash(BLOCK_ID_DOMAIN, bytes))
}

pub(crate) fn record_commitment(bytes: &[u8]) -> [u8; 32] {
    hash(RECORD_COMMITMENT_DOMAIN, bytes)
}

pub(crate) fn certificate_id(bytes: &[u8]) -> FinalityCertificateId {
    FinalityCertificateId::new(hash(CERTIFICATE_ID_DOMAIN, bytes))
}

fn hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(CONSENSUS_FORMAT_VERSION.to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}
