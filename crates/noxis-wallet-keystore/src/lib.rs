//! Bounded candidate keystore-container boundary.
//!
//! This crate persists public `NXKS` headers plus opaque synthetic `NXKP`
//! ciphertext only. It has no wallet-root import/export API and no release-mode
//! secret container. Password-based sealing is exercised only against a
//! synthetic root in unit tests. A future reviewed keystore may depend on this
//! crate; wallet, ledger and public-address crates must not own secret files.

use std::fmt;

use rand_core::{OsRng, RngCore as _};
use sha2::{Digest as _, Sha256};

mod candidate_payload;
mod external_anchor;
mod header_store;
mod payload_store;
mod recovery_bundle;

#[cfg(any(test, feature = "research-testing"))]
pub use candidate_payload::ResearchSyntheticPayloadError;
pub use candidate_payload::{
    CandidateKeystorePayloadV1, CandidatePayloadCiphertextIdV1, KEYSTORE_PAYLOAD_MAGIC,
    KEYSTORE_PAYLOAD_V1_LENGTH, KEYSTORE_PAYLOAD_VERSION, KeystorePayloadBindingError,
    KeystorePayloadError,
};
pub use external_anchor::{
    EXTERNAL_ROLLBACK_ANCHOR_MAGIC, EXTERNAL_ROLLBACK_ANCHOR_V1_LENGTH,
    EXTERNAL_ROLLBACK_ANCHOR_VERSION, ExternalRollbackAnchorError, ExternalRollbackAnchorMismatch,
    ExternalRollbackAnchorV1,
};

pub use header_store::{
    CandidateKeystoreHeaderStore, HeaderStoreError, HeaderStoreInitializeOutcome,
    KEYSTORE_HEADER_LOCK_FILE_NAME,
};
#[cfg(feature = "research-testing")]
pub use payload_store::set_research_stop_after_payload_temporary_sync;
pub use payload_store::{
    CandidateKeystorePayloadStore, MAX_SYNTHETIC_PAYLOAD_GENERATIONS, PayloadStoreError,
    PayloadStorePublishOutcome,
};
pub use recovery_bundle::{
    CandidateSyntheticRecoveryBundleV1, RecoveryBundleError, RecoveryRestoreOutcome,
    SYNTHETIC_RECOVERY_BUNDLE_MAGIC, SYNTHETIC_RECOVERY_BUNDLE_V1_LENGTH,
    SYNTHETIC_RECOVERY_BUNDLE_VERSION,
};

/// Candidate keystore-header magic bytes.
pub const KEYSTORE_HEADER_MAGIC: [u8; 4] = *b"NXKS";
/// Only candidate header layout accepted by this crate.
pub const KEYSTORE_HEADER_VERSION: u16 = 2;
/// Exact v2 serialized header size.
pub const KEYSTORE_HEADER_V2_LENGTH: usize = 76;
/// Fixed Argon2id candidate memory cost in KiB (64 MiB).
pub const CANDIDATE_ARGON2_MEMORY_KIB: u32 = 65_536;
/// Fixed Argon2id candidate time cost.
pub const CANDIDATE_ARGON2_TIME_COST: u32 = 3;
/// Fixed Argon2id candidate lane count.
pub const CANDIDATE_ARGON2_LANES: u32 = 4;
pub const CANDIDATE_SALT_LENGTH: usize = 16;
/// SHA-256 domain for the public identity of one exact `NXKS v2` header.
pub const KEYSTORE_HEADER_ID_DOMAIN: &[u8] = b"NOXIS/KEYSTORE-HEADER-ID/V1\0";

const ARGON2ID_KDF_ID: u8 = 1;
const XCHACHA20POLY1305_AEAD_ID: u8 = 1;
const REVOKED_KEYSTORE_HEADER_V1: u16 = 1;

/// Exact public metadata that will become authenticated associated data for a
/// future keystore payload. Its constructor always selects the one candidate
/// profile; a decoder rejects every different algorithm or cost value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeystoreHeaderV2 {
    salt: [u8; CANDIDATE_SALT_LENGTH],
    wallet_id: [u8; 32],
    key_epoch: u64,
}

/// Public SHA-256 identifier of one complete canonical candidate header. It
/// is safe to record outside the keystore directory as an external anchor; it
/// is not a password verifier, signature, recovery secret or rollback proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeystoreHeaderIdV1([u8; 32]);

impl KeystoreHeaderIdV1 {
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl KeystoreHeaderV2 {
    /// Creates a fresh public salt for one candidate header. Every encrypted
    /// payload generation must instead carry its own unique AEAD nonce. The
    /// caller supplies a stable, nonzero public wallet identifier and epoch;
    /// neither is a secret, but both are authenticated later.
    pub fn generate(wallet_id: [u8; 32], key_epoch: u64) -> Result<Self, KeystoreHeaderError> {
        if is_all_zero(&wallet_id) {
            return Err(KeystoreHeaderError::ZeroWalletId);
        }
        let mut salt = [0_u8; CANDIDATE_SALT_LENGTH];
        OsRng.fill_bytes(&mut salt);
        Ok(Self {
            salt,
            wallet_id,
            key_epoch,
        })
    }

    /// Strictly decodes the fixed candidate header and rejects malformed,
    /// unsupported, downgraded and trailing data before exposing metadata.
    pub fn decode(bytes: &[u8]) -> Result<Self, KeystoreHeaderError> {
        if bytes.len() < 6 {
            return Err(KeystoreHeaderError::InvalidLength {
                actual: bytes.len(),
            });
        }
        if bytes[..4] != KEYSTORE_HEADER_MAGIC {
            return Err(KeystoreHeaderError::InvalidMagic);
        }
        let version = u16::from_be_bytes(bytes[4..6].try_into().expect("fixed version slice"));
        if version == REVOKED_KEYSTORE_HEADER_V1 {
            return Err(KeystoreHeaderError::RevokedVersionV1);
        }
        if version != KEYSTORE_HEADER_VERSION {
            return Err(KeystoreHeaderError::UnsupportedVersion);
        }
        if bytes.len() != KEYSTORE_HEADER_V2_LENGTH {
            return Err(KeystoreHeaderError::InvalidLength {
                actual: bytes.len(),
            });
        }
        if bytes[6] != ARGON2ID_KDF_ID || bytes[7] != XCHACHA20POLY1305_AEAD_ID {
            return Err(KeystoreHeaderError::UnsupportedAlgorithm);
        }
        let memory_kib = u32::from_be_bytes(bytes[8..12].try_into().expect("fixed memory slice"));
        let time_cost = u32::from_be_bytes(bytes[12..16].try_into().expect("fixed time slice"));
        let lanes = u32::from_be_bytes(bytes[16..20].try_into().expect("fixed lane slice"));
        if memory_kib != CANDIDATE_ARGON2_MEMORY_KIB
            || time_cost != CANDIDATE_ARGON2_TIME_COST
            || lanes != CANDIDATE_ARGON2_LANES
        {
            return Err(KeystoreHeaderError::UnsupportedCostProfile);
        }
        let salt = bytes[20..36].try_into().expect("fixed salt slice");
        if is_all_zero(&salt) {
            return Err(KeystoreHeaderError::ZeroSalt);
        }
        let wallet_id = bytes[36..68].try_into().expect("fixed wallet ID slice");
        if is_all_zero(&wallet_id) {
            return Err(KeystoreHeaderError::ZeroWalletId);
        }
        let key_epoch = u64::from_be_bytes(bytes[68..76].try_into().expect("fixed epoch slice"));
        Ok(Self {
            salt,
            wallet_id,
            key_epoch,
        })
    }

    /// Canonical header bytes. These exact bytes are the associated data for
    /// the test-only sealing path, so substitution of profile/wallet/epoch
    /// fails authentication.
    pub fn encode(self) -> [u8; KEYSTORE_HEADER_V2_LENGTH] {
        let mut bytes = [0_u8; KEYSTORE_HEADER_V2_LENGTH];
        bytes[..4].copy_from_slice(&KEYSTORE_HEADER_MAGIC);
        bytes[4..6].copy_from_slice(&KEYSTORE_HEADER_VERSION.to_be_bytes());
        bytes[6] = ARGON2ID_KDF_ID;
        bytes[7] = XCHACHA20POLY1305_AEAD_ID;
        bytes[8..12].copy_from_slice(&CANDIDATE_ARGON2_MEMORY_KIB.to_be_bytes());
        bytes[12..16].copy_from_slice(&CANDIDATE_ARGON2_TIME_COST.to_be_bytes());
        bytes[16..20].copy_from_slice(&CANDIDATE_ARGON2_LANES.to_be_bytes());
        bytes[20..36].copy_from_slice(&self.salt);
        bytes[36..68].copy_from_slice(&self.wallet_id);
        bytes[68..76].copy_from_slice(&self.key_epoch.to_be_bytes());
        bytes
    }

    /// Computes the domain-separated public identity of these exact canonical
    /// header bytes. A future backup receipt will bind this value together
    /// with an encrypted-payload generation and ciphertext identifier.
    pub fn id(self) -> KeystoreHeaderIdV1 {
        let mut hash = Sha256::new();
        hash.update(KEYSTORE_HEADER_ID_DOMAIN);
        hash.update(self.encode());
        KeystoreHeaderIdV1(hash.finalize().into())
    }

    pub const fn wallet_id(self) -> [u8; 32] {
        self.wallet_id
    }

    pub const fn key_epoch(self) -> u64 {
        self.key_epoch
    }

    #[cfg(test)]
    pub(crate) const fn with_test_entropy(
        wallet_id: [u8; 32],
        key_epoch: u64,
        salt: [u8; CANDIDATE_SALT_LENGTH],
    ) -> Self {
        Self {
            salt,
            wallet_id,
            key_epoch,
        }
    }

    #[cfg(any(test, feature = "research-testing"))]
    pub(crate) const fn salt_for_test_only_crypto(self) -> [u8; CANDIDATE_SALT_LENGTH] {
        self.salt
    }
}

/// Public header rejection errors. They contain no password, key or plaintext
/// detail and are intentionally separate from future unlock errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeystoreHeaderError {
    InvalidLength { actual: usize },
    InvalidMagic,
    RevokedVersionV1,
    UnsupportedVersion,
    UnsupportedAlgorithm,
    UnsupportedCostProfile,
    ZeroSalt,
    ZeroWalletId,
}

impl fmt::Display for KeystoreHeaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLength { .. } => "candidate keystore header has invalid length",
            Self::InvalidMagic => "candidate keystore header has invalid magic",
            Self::RevokedVersionV1 => "candidate keystore header version 1 is revoked",
            Self::UnsupportedVersion => "candidate keystore header has unsupported version",
            Self::UnsupportedAlgorithm => "candidate keystore header has unsupported algorithm",
            Self::UnsupportedCostProfile => {
                "candidate keystore header has unsupported cost profile"
            }
            Self::ZeroSalt => "candidate keystore header has zero salt",
            Self::ZeroWalletId => "candidate keystore header has zero wallet ID",
        })
    }
}

impl std::error::Error for KeystoreHeaderError {}

const fn is_all_zero<const LENGTH: usize>(bytes: &[u8; LENGTH]) -> bool {
    let mut index = 0;
    let mut value = 0_u8;
    while index < bytes.len() {
        value |= bytes[index];
        index += 1;
    }
    value == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trips_and_rejects_all_structural_mutations() {
        let header = KeystoreHeaderV2::with_test_entropy([7; 32], 42, [8; 16]);
        let bytes = header.encode();
        assert_eq!(KeystoreHeaderV2::decode(&bytes).unwrap(), header);
        assert_eq!(header.id(), KeystoreHeaderV2::decode(&bytes).unwrap().id());
        assert_eq!(
            KeystoreHeaderV2::decode(&bytes[..75]),
            Err(KeystoreHeaderError::InvalidLength { actual: 75 })
        );
        let mut wrong_magic = bytes;
        wrong_magic[0] ^= 1;
        assert_eq!(
            KeystoreHeaderV2::decode(&wrong_magic),
            Err(KeystoreHeaderError::InvalidMagic)
        );
        let mut wrong_profile = bytes;
        wrong_profile[8] ^= 1;
        assert_eq!(
            KeystoreHeaderV2::decode(&wrong_profile),
            Err(KeystoreHeaderError::UnsupportedCostProfile)
        );
        let mut zero_salt = bytes;
        zero_salt[20..36].fill(0);
        assert_eq!(
            KeystoreHeaderV2::decode(&zero_salt),
            Err(KeystoreHeaderError::ZeroSalt)
        );
        assert_eq!(
            KeystoreHeaderV2::decode(b"NXKS\0\x01"),
            Err(KeystoreHeaderError::RevokedVersionV1)
        );
        let changed_epoch = KeystoreHeaderV2::with_test_entropy([7; 32], 43, [8; 16]);
        assert_ne!(header.id(), changed_epoch.id());
    }
}
