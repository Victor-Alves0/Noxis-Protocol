//! Bounded candidate keystore-container boundary.
//!
//! This crate intentionally has no filesystem API, no wallet-root import or
//! export API, and no release-mode secret container. It owns the exact public
//! `NXKS` header candidate and exercises password-based sealing only against a
//! synthetic root in unit tests. A future reviewed keystore may depend on this
//! crate; wallet, ledger and public-address crates must not own secret files.

use std::fmt;

use rand_core::{OsRng, RngCore as _};

/// Candidate keystore-header magic bytes.
pub const KEYSTORE_HEADER_MAGIC: [u8; 4] = *b"NXKS";
/// Only candidate header layout accepted by this crate.
pub const KEYSTORE_HEADER_VERSION: u16 = 1;
/// Exact v1 serialized header size.
pub const KEYSTORE_HEADER_V1_LENGTH: usize = 100;
/// Fixed Argon2id candidate memory cost in KiB (64 MiB).
pub const CANDIDATE_ARGON2_MEMORY_KIB: u32 = 65_536;
/// Fixed Argon2id candidate time cost.
pub const CANDIDATE_ARGON2_TIME_COST: u32 = 3;
/// Fixed Argon2id candidate lane count.
pub const CANDIDATE_ARGON2_LANES: u32 = 4;
pub const CANDIDATE_SALT_LENGTH: usize = 16;
pub const CANDIDATE_NONCE_LENGTH: usize = 24;

const ARGON2ID_KDF_ID: u8 = 1;
const XCHACHA20POLY1305_AEAD_ID: u8 = 1;
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
pub struct KeystoreHeaderV1 {
    salt: [u8; CANDIDATE_SALT_LENGTH],
    nonce: [u8; CANDIDATE_NONCE_LENGTH],
    wallet_id: [u8; 32],
    key_epoch: u64,
}

impl KeystoreHeaderV1 {
    /// Creates fresh public salt and nonce for one candidate header. The
    /// caller supplies a stable, nonzero public wallet identifier and epoch;
    /// neither is a secret, but both are authenticated later.
    pub fn generate(wallet_id: [u8; 32], key_epoch: u64) -> Result<Self, KeystoreHeaderError> {
        if is_all_zero(&wallet_id) {
            return Err(KeystoreHeaderError::ZeroWalletId);
        }
        let mut salt = [0_u8; CANDIDATE_SALT_LENGTH];
        let mut nonce = [0_u8; CANDIDATE_NONCE_LENGTH];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        Ok(Self {
            salt,
            nonce,
            wallet_id,
            key_epoch,
        })
    }

    /// Strictly decodes the fixed candidate header and rejects malformed,
    /// unsupported, downgraded and trailing data before exposing metadata.
    pub fn decode(bytes: &[u8]) -> Result<Self, KeystoreHeaderError> {
        if bytes.len() != KEYSTORE_HEADER_V1_LENGTH {
            return Err(KeystoreHeaderError::InvalidLength {
                actual: bytes.len(),
            });
        }
        if bytes[..4] != KEYSTORE_HEADER_MAGIC {
            return Err(KeystoreHeaderError::InvalidMagic);
        }
        if u16::from_be_bytes(bytes[4..6].try_into().expect("fixed version slice"))
            != KEYSTORE_HEADER_VERSION
        {
            return Err(KeystoreHeaderError::UnsupportedVersion);
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
        let nonce = bytes[36..60].try_into().expect("fixed nonce slice");
        if is_all_zero(&salt) {
            return Err(KeystoreHeaderError::ZeroSalt);
        }
        if is_all_zero(&nonce) {
            return Err(KeystoreHeaderError::ZeroNonce);
        }
        let wallet_id = bytes[60..92].try_into().expect("fixed wallet ID slice");
        if is_all_zero(&wallet_id) {
            return Err(KeystoreHeaderError::ZeroWalletId);
        }
        let key_epoch = u64::from_be_bytes(bytes[92..100].try_into().expect("fixed epoch slice"));
        Ok(Self {
            salt,
            nonce,
            wallet_id,
            key_epoch,
        })
    }

    /// Canonical header bytes. These exact bytes are the associated data for
    /// the test-only sealing path, so substitution of profile/wallet/epoch
    /// fails authentication.
    pub fn encode(self) -> [u8; KEYSTORE_HEADER_V1_LENGTH] {
        let mut bytes = [0_u8; KEYSTORE_HEADER_V1_LENGTH];
        bytes[..4].copy_from_slice(&KEYSTORE_HEADER_MAGIC);
        bytes[4..6].copy_from_slice(&KEYSTORE_HEADER_VERSION.to_be_bytes());
        bytes[6] = ARGON2ID_KDF_ID;
        bytes[7] = XCHACHA20POLY1305_AEAD_ID;
        bytes[8..12].copy_from_slice(&CANDIDATE_ARGON2_MEMORY_KIB.to_be_bytes());
        bytes[12..16].copy_from_slice(&CANDIDATE_ARGON2_TIME_COST.to_be_bytes());
        bytes[16..20].copy_from_slice(&CANDIDATE_ARGON2_LANES.to_be_bytes());
        bytes[20..36].copy_from_slice(&self.salt);
        bytes[36..60].copy_from_slice(&self.nonce);
        bytes[60..92].copy_from_slice(&self.wallet_id);
        bytes[92..100].copy_from_slice(&self.key_epoch.to_be_bytes());
        bytes
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
        nonce: [u8; CANDIDATE_NONCE_LENGTH],
    ) -> Self {
        Self {
            salt,
            nonce,
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
    UnsupportedVersion,
    UnsupportedAlgorithm,
    UnsupportedCostProfile,
    ZeroSalt,
    ZeroNonce,
    ZeroWalletId,
}

impl fmt::Display for KeystoreHeaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLength { .. } => "candidate keystore header has invalid length",
            Self::InvalidMagic => "candidate keystore header has invalid magic",
            Self::UnsupportedVersion => "candidate keystore header has unsupported version",
            Self::UnsupportedAlgorithm => "candidate keystore header has unsupported algorithm",
            Self::UnsupportedCostProfile => {
                "candidate keystore header has unsupported cost profile"
            }
            Self::ZeroSalt => "candidate keystore header has zero salt",
            Self::ZeroNonce => "candidate keystore header has zero nonce",
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
        let header = KeystoreHeaderV1::with_test_entropy([7; 32], 42, [8; 16], [9; 24]);
        let bytes = header.encode();
        assert_eq!(KeystoreHeaderV1::decode(&bytes).unwrap(), header);
        assert_eq!(
            KeystoreHeaderV1::decode(&bytes[..99]),
            Err(KeystoreHeaderError::InvalidLength { actual: 99 })
        );
        let mut wrong_magic = bytes;
        wrong_magic[0] ^= 1;
        assert_eq!(
            KeystoreHeaderV1::decode(&wrong_magic),
            Err(KeystoreHeaderError::InvalidMagic)
        );
        let mut wrong_profile = bytes;
        wrong_profile[8] ^= 1;
        assert_eq!(
            KeystoreHeaderV1::decode(&wrong_profile),
            Err(KeystoreHeaderError::UnsupportedCostProfile)
        );
        let mut zero_salt = bytes;
        zero_salt[20..36].fill(0);
        assert_eq!(
            KeystoreHeaderV1::decode(&zero_salt),
            Err(KeystoreHeaderError::ZeroSalt)
        );
        let mut zero_nonce = bytes;
        zero_nonce[36..60].fill(0);
        assert_eq!(
            KeystoreHeaderV1::decode(&zero_nonce),
            Err(KeystoreHeaderError::ZeroNonce)
        );
    }

    #[test]
    fn test_only_root_fixture_requires_exact_password_and_header() {
        let header = KeystoreHeaderV1::with_test_entropy([7; 32], 42, [8; 16], [9; 24]);
        let mut root = [0xA5; ROOT_FIXTURE_LENGTH];
        let sealed =
            seal_test_only_root_fixture(&header, b"correct horse battery staple", &root).unwrap();
        root.zeroize();
        let mut recovered =
            open_test_only_root_fixture(&header, b"correct horse battery staple", &sealed).unwrap();
        assert_eq!(recovered, [0xA5; ROOT_FIXTURE_LENGTH]);
        recovered.zeroize();
        let wrong_password = open_test_only_root_fixture(&header, b"wrong password", &sealed);
        assert_eq!(wrong_password, Err(TestOnlyFixtureError::UnlockFailed));
        let mut tampered_ciphertext = sealed;
        tampered_ciphertext[0] ^= 1;
        assert_eq!(
            open_test_only_root_fixture(
                &header,
                b"correct horse battery staple",
                &tampered_ciphertext,
            ),
            Err(TestOnlyFixtureError::UnlockFailed)
        );
        let mut substituted = header;
        substituted.key_epoch = 43;
        let substituted_header =
            open_test_only_root_fixture(&substituted, b"correct horse battery staple", &sealed);
        assert_eq!(substituted_header, Err(TestOnlyFixtureError::UnlockFailed));
    }

    fn seal_test_only_root_fixture(
        header: &KeystoreHeaderV1,
        password: &[u8],
        root: &[u8; ROOT_FIXTURE_LENGTH],
    ) -> Result<[u8; SEALED_ROOT_FIXTURE_LENGTH], TestOnlyFixtureError> {
        let mut key = derive_test_only_key(header, password)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key)
            .expect("fixed 32-byte Argon2 output is a valid XChaCha20 key");
        let ciphertext = cipher.encrypt(
            XNonce::from_slice(&header.nonce),
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
        header: &KeystoreHeaderV1,
        password: &[u8],
        sealed: &[u8; SEALED_ROOT_FIXTURE_LENGTH],
    ) -> Result<[u8; ROOT_FIXTURE_LENGTH], TestOnlyFixtureError> {
        let mut key = derive_test_only_key(header, password)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key)
            .expect("fixed 32-byte Argon2 output is a valid XChaCha20 key");
        let plaintext = cipher.decrypt(
            XNonce::from_slice(&header.nonce),
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
        header: &KeystoreHeaderV1,
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
