//! Canonical constraint profile for the unselected private-transfer AIR.
//!
//! `NXAR` fixes which already-defined relations an eventual AIR must express.
//! It is deliberately not an AIR program, a STARK backend, a verifier key, or
//! a proof format.

use std::fmt;

use noxis_nullifier_tree_reference::NULLIFIER_SPARSE_TREE_DEPTH_V1;
use noxis_privacy_types::PRIVATE_TRANSFER_V2_TREE_DEPTH;
use noxis_tree_params::{
    CandidatePoseidon2P24ManifestV2, CandidatePoseidon2P24NullifierSparseManifestV1,
    P24_INTENT_COMMITMENT_INPUT_ELEMENTS, Poseidon2P24CandidateError,
    Poseidon2P24NullifierSparseCandidateError,
};
use sha2::{Digest, Sha256};

use crate::{
    CANDIDATE_PRIVATE_TRANSFER_PROOF_PUBLIC_STATEMENT_ENCODED_LENGTH,
    CandidatePrivateTransferProofDeploymentV1, PrivateTransferProofDeploymentError,
};

/// `BytePack3LE(intent)` and `H_INTENT(intent)` are canonical and equal.
pub const AIR_CONSTRAINT_CANONICAL_INTENT: u16 = 1 << 0;
/// Both private input notes reconstruct their public commitment and note root.
pub const AIR_CONSTRAINT_INPUT_NOTE_MEMBERSHIP: u16 = 1 << 1;
/// Each input key, note and position reconstructs its public nullifier.
pub const AIR_CONSTRAINT_INPUT_NULLIFIER: u16 = 1 << 2;
/// Both output openings reconstruct their public commitments.
pub const AIR_CONSTRAINT_OUTPUT_NOTES: u16 = 1 << 3;
/// The four note values satisfy fixed-width `u128` conservation.
pub const AIR_CONSTRAINT_VALUE_CONSERVATION: u16 = 1 << 4;
/// Canonical ordering and all distinctness requirements hold.
pub const AIR_CONSTRAINT_UNIQUENESS: u16 = 1 << 5;
/// The first nullifier is absent at the public `NXSM` pre-root.
pub const AIR_CONSTRAINT_NXSM_FIRST_ABSENCE: u16 = 1 << 6;
/// The first insertion produces the unique intermediate `NXSM` root.
pub const AIR_CONSTRAINT_NXSM_INTERMEDIATE_ROOT: u16 = 1 << 7;
/// The second absence and insertion produce the public `NXSM` post-root.
pub const AIR_CONSTRAINT_NXSM_POST_ROOT: u16 = 1 << 8;
/// `NXPU` fields cross-bind the note, anchor and nullifier relations.
pub const AIR_CONSTRAINT_PUBLIC_CROSS_BINDINGS: u16 = 1 << 9;

const REQUIRED_CONSTRAINTS: u16 = AIR_CONSTRAINT_CANONICAL_INTENT
    | AIR_CONSTRAINT_INPUT_NOTE_MEMBERSHIP
    | AIR_CONSTRAINT_INPUT_NULLIFIER
    | AIR_CONSTRAINT_OUTPUT_NOTES
    | AIR_CONSTRAINT_VALUE_CONSERVATION
    | AIR_CONSTRAINT_UNIQUENESS
    | AIR_CONSTRAINT_NXSM_FIRST_ABSENCE
    | AIR_CONSTRAINT_NXSM_INTERMEDIATE_ROOT
    | AIR_CONSTRAINT_NXSM_POST_ROOT
    | AIR_CONSTRAINT_PUBLIC_CROSS_BINDINGS;

/// SHA-256 domain for one frozen `NXAR` candidate profile identity.
pub const CANDIDATE_PRIVATE_TRANSFER_AIR_PROFILE_ID_DOMAIN: &[u8] =
    b"NOXIS/PRIVATE-TRANSFER-AIR-PROFILE-ID/V1\0";
/// Exact `NXAR v1` byte length including its checksum.
pub const CANDIDATE_PRIVATE_TRANSFER_AIR_PROFILE_ENCODED_LENGTH: usize = 152;

const MAGIC: [u8; 4] = *b"NXAR";
const VERSION: u16 = 1;
const INPUTS: u8 = 2;
const OUTPUTS: u8 = 2;
const DIGEST_ELEMENTS: u8 = 16;
const PUBLIC_ELEMENTS: u16 = 230;
const VALUE_U32_LIMBS: u8 = 4;
const HEADER_LENGTH: usize = 120;
const CHECKSUM_LENGTH: usize = 32;

/// Frozen shape and relation set for the future 2×2 private-transfer AIR.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CandidatePrivateTransferAirProfileV1;

impl CandidatePrivateTransferAirProfileV1 {
    /// Returns the only current candidate profile. It is intentionally
    /// backend-neutral and cannot select a verifier.
    pub const fn new() -> Self {
        Self
    }

    /// Encodes all profile dimensions, required constraints and candidate
    /// ancestors before appending a domain-separated checksum.
    pub fn encode(
        self,
    ) -> Result<
        [u8; CANDIDATE_PRIVATE_TRANSFER_AIR_PROFILE_ENCODED_LENGTH],
        CandidatePrivateTransferAirProfileError,
    > {
        let p24 = CandidatePoseidon2P24ManifestV2::new().candidate_id()?;
        let nxsm = CandidatePoseidon2P24NullifierSparseManifestV1::new().candidate_id()?;
        let nxpd = CandidatePrivateTransferProofDeploymentV1::new().candidate_id()?;
        let mut output = [0_u8; CANDIDATE_PRIVATE_TRANSFER_AIR_PROFILE_ENCODED_LENGTH];
        output[..4].copy_from_slice(&MAGIC);
        output[4..6].copy_from_slice(&VERSION.to_be_bytes());
        output[6..8].fill(0);
        output[8..10].copy_from_slice(
            &(CANDIDATE_PRIVATE_TRANSFER_PROOF_PUBLIC_STATEMENT_ENCODED_LENGTH as u16)
                .to_be_bytes(),
        );
        output[10..12].copy_from_slice(&PUBLIC_ELEMENTS.to_be_bytes());
        output[12..14]
            .copy_from_slice(&(P24_INTENT_COMMITMENT_INPUT_ELEMENTS as u16).to_be_bytes());
        output[14] = DIGEST_ELEMENTS;
        output[15] = INPUTS;
        output[16] = OUTPUTS;
        output[17] = PRIVATE_TRANSFER_V2_TREE_DEPTH;
        output[18..20].copy_from_slice(&(NULLIFIER_SPARSE_TREE_DEPTH_V1 as u16).to_be_bytes());
        output[20] = VALUE_U32_LIMBS;
        output[21..23].copy_from_slice(&REQUIRED_CONSTRAINTS.to_be_bytes());
        output[23] = 0;
        output[24..56].copy_from_slice(&p24.as_bytes());
        output[56..88].copy_from_slice(&nxsm.as_bytes());
        output[88..120].copy_from_slice(&nxpd.as_bytes());
        let checksum = checksum(&output[..HEADER_LENGTH]);
        output[HEADER_LENGTH..].copy_from_slice(&checksum);
        Ok(output)
    }

    /// Accepts only the exact canonical candidate bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, CandidatePrivateTransferAirProfileError> {
        if bytes.len() != CANDIDATE_PRIVATE_TRANSFER_AIR_PROFILE_ENCODED_LENGTH {
            return Err(CandidatePrivateTransferAirProfileError::InvalidLength {
                actual: bytes.len(),
                expected: CANDIDATE_PRIVATE_TRANSFER_AIR_PROFILE_ENCODED_LENGTH,
            });
        }
        if bytes[..4] != MAGIC {
            return Err(CandidatePrivateTransferAirProfileError::InvalidMagic);
        }
        if bytes[4..6] != VERSION.to_be_bytes() {
            return Err(CandidatePrivateTransferAirProfileError::UnsupportedVersion);
        }
        if bytes[HEADER_LENGTH..] != checksum(&bytes[..HEADER_LENGTH]) {
            return Err(CandidatePrivateTransferAirProfileError::ChecksumMismatch);
        }
        if bytes != Self::new().encode()? {
            return Err(CandidatePrivateTransferAirProfileError::NonCanonicalProfile);
        }
        Ok(Self)
    }

    /// The complete, fixed bit-set an eventual AIR must satisfy.
    pub const fn required_constraints(self) -> u16 {
        let _ = self;
        REQUIRED_CONSTRAINTS
    }

    /// Identifies this exact candidate profile but is never a verifier ID.
    pub fn candidate_id(
        self,
    ) -> Result<CandidatePrivateTransferAirProfileIdV1, CandidatePrivateTransferAirProfileError>
    {
        let mut hasher = Sha256::new();
        hasher.update(CANDIDATE_PRIVATE_TRANSFER_AIR_PROFILE_ID_DOMAIN);
        hasher.update(self.encode()?);
        Ok(CandidatePrivateTransferAirProfileIdV1(
            hasher.finalize().into(),
        ))
    }
}

fn checksum(bytes: &[u8]) -> [u8; CHECKSUM_LENGTH] {
    let mut hasher = Sha256::new();
    hasher.update(b"NOXIS/PRIVATE-TRANSFER-AIR-PROFILE-CHECKSUM/V1\0");
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Candidate identity for the exact frozen `NXAR` profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CandidatePrivateTransferAirProfileIdV1([u8; 32]);

impl CandidatePrivateTransferAirProfileIdV1 {
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Display for CandidatePrivateTransferAirProfileIdV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Fail-closed errors while reading or deriving `NXAR`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CandidatePrivateTransferAirProfileError {
    P24(Poseidon2P24CandidateError),
    Nxsm(Poseidon2P24NullifierSparseCandidateError),
    Deployment(PrivateTransferProofDeploymentError),
    InvalidLength { actual: usize, expected: usize },
    InvalidMagic,
    UnsupportedVersion,
    ChecksumMismatch,
    NonCanonicalProfile,
}

impl From<Poseidon2P24CandidateError> for CandidatePrivateTransferAirProfileError {
    fn from(value: Poseidon2P24CandidateError) -> Self {
        Self::P24(value)
    }
}

impl From<Poseidon2P24NullifierSparseCandidateError> for CandidatePrivateTransferAirProfileError {
    fn from(value: Poseidon2P24NullifierSparseCandidateError) -> Self {
        Self::Nxsm(value)
    }
}

impl From<PrivateTransferProofDeploymentError> for CandidatePrivateTransferAirProfileError {
    fn from(value: PrivateTransferProofDeploymentError) -> Self {
        Self::Deployment(value)
    }
}

impl fmt::Display for CandidatePrivateTransferAirProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "candidate private-transfer AIR profile error: {self:?}"
        )
    }
}

impl std::error::Error for CandidatePrivateTransferAirProfileError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_freezes_every_current_constraint_and_ancestor() {
        let profile = CandidatePrivateTransferAirProfileV1::new();
        let encoded = profile.encode().unwrap();
        assert_eq!(
            encoded.len(),
            CANDIDATE_PRIVATE_TRANSFER_AIR_PROFILE_ENCODED_LENGTH
        );
        assert_eq!(&encoded[..8], b"NXAR\0\x01\0\0");
        assert_eq!(
            CandidatePrivateTransferAirProfileV1::decode(&encoded),
            Ok(profile)
        );
        assert_eq!(profile.required_constraints(), REQUIRED_CONSTRAINTS);
        assert_ne!(profile.candidate_id().unwrap().as_bytes(), [0; 32]);
    }

    #[test]
    fn profile_rejects_changed_framing_constraints_and_ancestors() {
        let canonical = CandidatePrivateTransferAirProfileV1::new()
            .encode()
            .unwrap();
        for index in [0, 4, 8, 12, 17, 19, 21, 24, 56, 88, canonical.len() - 1] {
            let mut changed = canonical;
            changed[index] ^= 1;
            assert!(CandidatePrivateTransferAirProfileV1::decode(&changed).is_err());
        }
    }
}
