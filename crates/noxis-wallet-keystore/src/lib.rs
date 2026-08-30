//! Bounded candidate keystore-container boundary.
//!
//! This crate persists only the exact public `NXKS` header candidate; it has no
//! wallet-root import/export API and no release-mode secret container. It
//! exercises password-based sealing only against a synthetic root in unit
//! tests. A future reviewed keystore may depend on this crate; wallet, ledger
//! and public-address crates must not own secret files.

use std::fmt;

use rand_core::{OsRng, RngCore as _};
use sha2::{Digest as _, Sha256};

mod external_anchor;
mod header_store;

pub use external_anchor::{
    CandidatePayloadCiphertextIdV1, EXTERNAL_ROLLBACK_ANCHOR_MAGIC,
    EXTERNAL_ROLLBACK_ANCHOR_V1_LENGTH, EXTERNAL_ROLLBACK_ANCHOR_VERSION,
    ExternalRollbackAnchorError, ExternalRollbackAnchorMismatch, ExternalRollbackAnchorV1,
};

pub use header_store::{
    CandidateKeystoreHeaderStore, HeaderStoreError, HeaderStoreInitializeOutcome,
    KEYSTORE_HEADER_LOCK_FILE_NAME,
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
#[cfg(test)]
const ROOT_FIXTURE_LENGTH: usize = 64;
#[cfg(test)]
const AEAD_TAG_LENGTH: usize = 16;
#[cfg(test)]
const SEALED_ROOT_FIXTURE_LENGTH: usize = ROOT_FIXTURE_LENGTH + AEAD_TAG_LENGTH;

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
    const fn with_test_entropy(
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
    use argon2::{Algorithm, Argon2, Params, Version};
    use chacha20poly1305::{
        XChaCha20Poly1305, XNonce,
        aead::{Aead as _, KeyInit as _, Payload},
    };
    use zeroize::Zeroize;

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

    #[test]
    fn test_only_root_fixture_requires_exact_password_and_header() {
        let header = KeystoreHeaderV2::with_test_entropy([7; 32], 42, [8; 16]);
        let nonce = [9; 24];
        let mut root = [0xA5; ROOT_FIXTURE_LENGTH];
        let sealed =
            seal_test_only_root_fixture(&header, &nonce, b"correct horse battery staple", &root)
                .unwrap();
        root.zeroize();
        let mut recovered =
            open_test_only_root_fixture(&header, &nonce, b"correct horse battery staple", &sealed)
                .unwrap();
        assert_eq!(recovered, [0xA5; ROOT_FIXTURE_LENGTH]);
        recovered.zeroize();
        let wrong_password =
            open_test_only_root_fixture(&header, &nonce, b"wrong password", &sealed);
        assert_eq!(wrong_password, Err(TestOnlyFixtureError::UnlockFailed));
        let mut tampered_ciphertext = sealed;
        tampered_ciphertext[0] ^= 1;
        assert_eq!(
            open_test_only_root_fixture(
                &header,
                &nonce,
                b"correct horse battery staple",
                &tampered_ciphertext,
            ),
            Err(TestOnlyFixtureError::UnlockFailed)
        );
        let mut substituted = header;
        substituted.key_epoch = 43;
        let substituted_header = open_test_only_root_fixture(
            &substituted,
            &nonce,
            b"correct horse battery staple",
            &sealed,
        );
        assert_eq!(substituted_header, Err(TestOnlyFixtureError::UnlockFailed));

        // A later encrypted payload is required to use a different nonce under
        // the same password-derived key. The nonce belongs to that payload,
        // never to the immutable header.
        let next_nonce = [10; 24];
        let mut next_root = [0xA5; ROOT_FIXTURE_LENGTH];
        let next_sealed = seal_test_only_root_fixture(
            &header,
            &next_nonce,
            b"correct horse battery staple",
            &next_root,
        )
        .unwrap();
        next_root.zeroize();
        assert_ne!(sealed, next_sealed);
        let mut next_recovered = open_test_only_root_fixture(
            &header,
            &next_nonce,
            b"correct horse battery staple",
            &next_sealed,
        )
        .unwrap();
        assert_eq!(next_recovered, [0xA5; ROOT_FIXTURE_LENGTH]);
        next_recovered.zeroize();
    }

    fn seal_test_only_root_fixture(
        header: &KeystoreHeaderV2,
        nonce: &[u8; 24],
        password: &[u8],
        root: &[u8; ROOT_FIXTURE_LENGTH],
    ) -> Result<[u8; SEALED_ROOT_FIXTURE_LENGTH], TestOnlyFixtureError> {
        let mut key = derive_test_only_key(header, password)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key)
            .expect("fixed 32-byte Argon2 output is a valid XChaCha20 key");
        let ciphertext = cipher.encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: root,
                aad: &header.encode(),
            },
        );
        key.zeroize();
        ciphertext
            .map_err(|_| TestOnlyFixtureError::UnlockFailed)?
            .try_into()
            .map_err(|_| TestOnlyFixtureError::UnlockFailed)
    }

    fn open_test_only_root_fixture(
        header: &KeystoreHeaderV2,
        nonce: &[u8; 24],
        password: &[u8],
        sealed: &[u8; SEALED_ROOT_FIXTURE_LENGTH],
    ) -> Result<[u8; ROOT_FIXTURE_LENGTH], TestOnlyFixtureError> {
        let mut key = derive_test_only_key(header, password)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key)
            .expect("fixed 32-byte Argon2 output is a valid XChaCha20 key");
        let plaintext = cipher.decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: sealed,
                aad: &header.encode(),
            },
        );
        key.zeroize();
        let mut plaintext = plaintext.map_err(|_| TestOnlyFixtureError::UnlockFailed)?;
        if plaintext.len() != ROOT_FIXTURE_LENGTH {
            plaintext.zeroize();
            return Err(TestOnlyFixtureError::UnlockFailed);
        }
        let root = plaintext
            .as_slice()
            .try_into()
            .expect("fixed root-fixture length");
        plaintext.zeroize();
        Ok(root)
    }

    fn derive_test_only_key(
        header: &KeystoreHeaderV2,
        password: &[u8],
    ) -> Result<[u8; 32], TestOnlyFixtureError> {
        let parameters = Params::new(
            CANDIDATE_ARGON2_MEMORY_KIB,
            CANDIDATE_ARGON2_TIME_COST,
            CANDIDATE_ARGON2_LANES,
            Some(32),
        )
        .map_err(|_| TestOnlyFixtureError::UnlockFailed)?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, parameters);
        let mut key = [0_u8; 32];
        argon2
            .hash_password_into(password, &header.salt, &mut key)
            .map_err(|_| TestOnlyFixtureError::UnlockFailed)?;
        Ok(key)
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestOnlyFixtureError {
        UnlockFailed,
    }
}
