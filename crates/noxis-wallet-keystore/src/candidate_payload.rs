//! Canonical candidate encrypted-payload representation.
//!
//! `NXKP v1` is deliberately limited to a synthetic 64-byte root fixture.
//! Release builds can strictly parse and identify its opaque ciphertext, but
//! they cannot create or decrypt one. This permits review of the bytes bound
//! to backup receipts without creating a real secret-bearing wallet file.

use std::fmt;

use sha2::{Digest as _, Sha256};

use crate::{KeystoreHeaderIdV1, KeystoreHeaderV2};

/// Candidate keystore encrypted-payload magic bytes.
pub const KEYSTORE_PAYLOAD_MAGIC: [u8; 4] = *b"NXKP";
/// Only candidate encrypted-payload layout accepted by this crate.
pub const KEYSTORE_PAYLOAD_VERSION: u16 = 1;
/// Exact synthetic plaintext length used only in unit-test cryptography.
const SYNTHETIC_ROOT_FIXTURE_LENGTH: usize = 64;
const XCHACHA20POLY1305_NONCE_LENGTH: usize = 24;
const XCHACHA20POLY1305_TAG_LENGTH: usize = 16;
const SYNTHETIC_CIPHERTEXT_LENGTH: usize =
    SYNTHETIC_ROOT_FIXTURE_LENGTH + XCHACHA20POLY1305_TAG_LENGTH;
const PAYLOAD_PREFIX_LENGTH: usize = 70;
/// Exact serialized length of `NXKP v1`.
pub const KEYSTORE_PAYLOAD_V1_LENGTH: usize = PAYLOAD_PREFIX_LENGTH + SYNTHETIC_CIPHERTEXT_LENGTH;
/// SHA-256 domain for the external identifier of exact canonical payload bytes.
pub const KEYSTORE_PAYLOAD_CIPHERTEXT_ID_DOMAIN: &[u8] =
    b"NOXIS/KEYSTORE-PAYLOAD-CIPHERTEXT-ID/V1\0";
#[cfg(test)]
const KEYSTORE_PAYLOAD_AAD_DOMAIN: &[u8] = b"NOXIS/KEYSTORE-PAYLOAD-AAD/V1\0";

/// Opaque public identifier of one canonical candidate encrypted payload.
/// It commits to metadata, nonce and ciphertext — never plaintext.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidatePayloadCiphertextIdV1([u8; 32]);

impl CandidatePayloadCiphertextIdV1 {
    /// Validates an externally supplied identifier, such as one decoded from
    /// an external rollback receipt. All-zero is reserved as absent.
    pub fn new(bytes: [u8; 32]) -> Result<Self, KeystorePayloadError> {
        if is_all_zero(&bytes) {
            return Err(KeystorePayloadError::ZeroCiphertextId);
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Exact public/opaque representation of one synthetic encrypted-payload
/// generation. It contains no plaintext and release builds expose no unlock
/// API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateKeystorePayloadV1 {
    header_id: KeystoreHeaderIdV1,
    generation: u64,
    nonce: [u8; XCHACHA20POLY1305_NONCE_LENGTH],
    ciphertext: [u8; SYNTHETIC_CIPHERTEXT_LENGTH],
}

impl CandidateKeystorePayloadV1 {
    /// Strictly decodes exact canonical `NXKP v1` bytes. This structural
    /// boundary does not decrypt and therefore cannot expose a secret.
    pub fn decode(bytes: &[u8]) -> Result<Self, KeystorePayloadError> {
        if bytes.len() != KEYSTORE_PAYLOAD_V1_LENGTH {
            return Err(KeystorePayloadError::InvalidLength {
                actual: bytes.len(),
            });
        }
        if bytes[..4] != KEYSTORE_PAYLOAD_MAGIC {
            return Err(KeystorePayloadError::InvalidMagic);
        }
        if u16::from_be_bytes(bytes[4..6].try_into().expect("fixed version slice"))
            != KEYSTORE_PAYLOAD_VERSION
        {
            return Err(KeystorePayloadError::UnsupportedVersion);
        }
        let generation =
            u64::from_be_bytes(bytes[38..46].try_into().expect("fixed generation slice"));
        if generation == 0 {
            return Err(KeystorePayloadError::ZeroGeneration);
        }
        let nonce = bytes[46..70].try_into().expect("fixed nonce slice");
        if is_all_zero(&nonce) {
            return Err(KeystorePayloadError::ZeroNonce);
        }
        Ok(Self {
            header_id: KeystoreHeaderIdV1::from_bytes(
                bytes[6..38].try_into().expect("fixed header ID slice"),
            ),
            generation,
            nonce,
            ciphertext: bytes[70..150].try_into().expect("fixed ciphertext slice"),
        })
    }

    /// Canonical payload bytes. The ciphertext itself remains opaque here.
    pub fn encode(self) -> [u8; KEYSTORE_PAYLOAD_V1_LENGTH] {
        let mut bytes = [0_u8; KEYSTORE_PAYLOAD_V1_LENGTH];
        bytes[..4].copy_from_slice(&KEYSTORE_PAYLOAD_MAGIC);
        bytes[4..6].copy_from_slice(&KEYSTORE_PAYLOAD_VERSION.to_be_bytes());
        bytes[6..38].copy_from_slice(&self.header_id.as_bytes());
        bytes[38..46].copy_from_slice(&self.generation.to_be_bytes());
        bytes[46..70].copy_from_slice(&self.nonce);
        bytes[70..150].copy_from_slice(&self.ciphertext);
        bytes
    }

    /// Derives the public identifier committed by `NXKA` rollback receipts.
    pub fn ciphertext_id(self) -> CandidatePayloadCiphertextIdV1 {
        let mut hash = Sha256::new();
        hash.update(KEYSTORE_PAYLOAD_CIPHERTEXT_ID_DOMAIN);
        hash.update(self.encode());
        CandidatePayloadCiphertextIdV1::new(hash.finalize().into())
            .expect("SHA-256 output is infeasible to be all zero")
    }

    /// Requires this payload to belong to the exact public `NXKS` header
    /// supplied for its future unlock path.
    pub fn verify_header(
        self,
        header: KeystoreHeaderV2,
    ) -> Result<(), KeystorePayloadBindingError> {
        if self.header_id != header.id() {
            return Err(KeystorePayloadBindingError::HeaderId);
        }
        Ok(())
    }

    pub const fn header_id(self) -> KeystoreHeaderIdV1 {
        self.header_id
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }

    #[cfg(test)]
    fn seal_synthetic_fixture(
        header: KeystoreHeaderV2,
        generation: u64,
        nonce: [u8; XCHACHA20POLY1305_NONCE_LENGTH],
        password: &[u8],
        root: &[u8; SYNTHETIC_ROOT_FIXTURE_LENGTH],
    ) -> Result<Self, TestOnlyPayloadError> {
        use chacha20poly1305::aead::{Aead as _, KeyInit as _};

        if generation == 0 || is_all_zero(&nonce) {
            return Err(TestOnlyPayloadError::InvalidFixtureInput);
        }
        let payload_prefix = Self {
            header_id: header.id(),
            generation,
            nonce,
            ciphertext: [0_u8; SYNTHETIC_CIPHERTEXT_LENGTH],
        };
        let aad = payload_prefix.test_only_aad(header);
        let mut key = derive_test_only_key(header, password)?;
        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&key)
            .expect("fixed 32-byte Argon2 output is a valid XChaCha20 key");
        let ciphertext = cipher.encrypt(
            chacha20poly1305::XNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: root,
                aad: &aad,
            },
        );
        zeroize::Zeroize::zeroize(&mut key);
        let ciphertext = ciphertext
            .map_err(|_| TestOnlyPayloadError::UnlockFailed)?
            .try_into()
            .map_err(|_| TestOnlyPayloadError::UnlockFailed)?;
        Ok(Self {
            ciphertext,
            ..payload_prefix
        })
    }

    #[cfg(test)]
    fn open_synthetic_fixture(
        self,
        header: KeystoreHeaderV2,
        password: &[u8],
    ) -> Result<[u8; SYNTHETIC_ROOT_FIXTURE_LENGTH], TestOnlyPayloadError> {
        use chacha20poly1305::aead::{Aead as _, KeyInit as _};

        self.verify_header(header)
            .map_err(|_| TestOnlyPayloadError::HeaderMismatch)?;
        let aad = self.test_only_aad(header);
        let mut key = derive_test_only_key(header, password)?;
        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&key)
            .expect("fixed 32-byte Argon2 output is a valid XChaCha20 key");
        let plaintext = cipher.decrypt(
            chacha20poly1305::XNonce::from_slice(&self.nonce),
            chacha20poly1305::aead::Payload {
                msg: &self.ciphertext,
                aad: &aad,
            },
        );
        zeroize::Zeroize::zeroize(&mut key);
        let mut plaintext = plaintext.map_err(|_| TestOnlyPayloadError::UnlockFailed)?;
        if plaintext.len() != SYNTHETIC_ROOT_FIXTURE_LENGTH {
            zeroize::Zeroize::zeroize(&mut plaintext);
            return Err(TestOnlyPayloadError::UnlockFailed);
        }
        let root = plaintext
            .as_slice()
            .try_into()
            .expect("fixed synthetic-root fixture length");
        zeroize::Zeroize::zeroize(&mut plaintext);
        Ok(root)
    }

    #[cfg(test)]
    fn test_only_aad(self, header: KeystoreHeaderV2) -> Vec<u8> {
        let payload_bytes = self.encode();
        let mut aad = Vec::with_capacity(
            KEYSTORE_PAYLOAD_AAD_DOMAIN.len()
                + crate::KEYSTORE_HEADER_V2_LENGTH
                + PAYLOAD_PREFIX_LENGTH,
        );
        aad.extend_from_slice(KEYSTORE_PAYLOAD_AAD_DOMAIN);
        aad.extend_from_slice(&header.encode());
        aad.extend_from_slice(&payload_bytes[..PAYLOAD_PREFIX_LENGTH]);
        aad
    }
}

/// Structural decoder rejection for canonical `NXKP v1` bytes or a public
/// ciphertext identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeystorePayloadError {
    InvalidLength { actual: usize },
    InvalidMagic,
    UnsupportedVersion,
    ZeroGeneration,
    ZeroNonce,
    ZeroCiphertextId,
}

impl fmt::Display for KeystorePayloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLength { .. } => "candidate keystore payload has invalid length",
            Self::InvalidMagic => "candidate keystore payload has invalid magic",
            Self::UnsupportedVersion => "candidate keystore payload has unsupported version",
            Self::ZeroGeneration => "candidate keystore payload has zero generation",
            Self::ZeroNonce => "candidate keystore payload has zero nonce",
            Self::ZeroCiphertextId => "candidate payload ciphertext ID is all zero",
        })
    }
}

impl std::error::Error for KeystorePayloadError {}

/// A canonical payload did not bind to the public header presented for it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeystorePayloadBindingError {
    HeaderId,
}

impl fmt::Display for KeystorePayloadBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("candidate keystore payload belongs to another header")
    }
}

impl std::error::Error for KeystorePayloadBindingError {}

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
fn derive_test_only_key(
    header: KeystoreHeaderV2,
    password: &[u8],
) -> Result<[u8; 32], TestOnlyPayloadError> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let parameters = Params::new(
        crate::CANDIDATE_ARGON2_MEMORY_KIB,
        crate::CANDIDATE_ARGON2_TIME_COST,
        crate::CANDIDATE_ARGON2_LANES,
        Some(32),
    )
    .map_err(|_| TestOnlyPayloadError::UnlockFailed)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, parameters);
    let mut key = [0_u8; 32];
    argon2
        .hash_password_into(password, &header.salt_for_test_only_crypto(), &mut key)
        .map_err(|_| TestOnlyPayloadError::UnlockFailed)?;
    Ok(key)
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestOnlyPayloadError {
    HeaderMismatch,
    InvalidFixtureInput,
    UnlockFailed,
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroize as _;

    use crate::{ExternalRollbackAnchorMismatch, ExternalRollbackAnchorV1};

    use super::*;

    fn header() -> KeystoreHeaderV2 {
        KeystoreHeaderV2::with_test_entropy([7; 32], 42, [8; 16])
    }

    #[test]
    fn synthetic_payload_round_trips_and_binds_its_header_and_receipt() {
        let header = header();
        let mut root = [0xA5; SYNTHETIC_ROOT_FIXTURE_LENGTH];
        let payload = CandidateKeystorePayloadV1::seal_synthetic_fixture(
            header,
            7,
            [9; XCHACHA20POLY1305_NONCE_LENGTH],
            b"correct horse battery staple",
            &root,
        )
        .unwrap();
        root.zeroize();

        let decoded = CandidateKeystorePayloadV1::decode(&payload.encode()).unwrap();
        assert_eq!(decoded, payload);
        assert_eq!(decoded.verify_header(header), Ok(()));
        let id = decoded.ciphertext_id();
        let anchor = ExternalRollbackAnchorV1::new(header.id(), decoded.generation(), id).unwrap();
        assert_eq!(anchor.verify(header.id(), decoded.generation(), id), Ok(()));

        let mut recovered = decoded
            .open_synthetic_fixture(header, b"correct horse battery staple")
            .unwrap();
        assert_eq!(recovered, [0xA5; SYNTHETIC_ROOT_FIXTURE_LENGTH]);
        recovered.zeroize();
        assert_eq!(
            decoded.open_synthetic_fixture(header, b"wrong password"),
            Err(TestOnlyPayloadError::UnlockFailed)
        );

        let mut tampered = decoded.encode();
        tampered[70] ^= 1;
        let tampered = CandidateKeystorePayloadV1::decode(&tampered).unwrap();
        assert_eq!(
            tampered.open_synthetic_fixture(header, b"correct horse battery staple"),
            Err(TestOnlyPayloadError::UnlockFailed)
        );

        let changed_header = KeystoreHeaderV2::with_test_entropy([8; 32], 42, [8; 16]);
        assert_eq!(
            decoded.verify_header(changed_header),
            Err(KeystorePayloadBindingError::HeaderId)
        );
        assert_eq!(
            decoded.open_synthetic_fixture(changed_header, b"correct horse battery staple"),
            Err(TestOnlyPayloadError::HeaderMismatch)
        );
    }

    #[test]
    fn later_generation_requires_distinct_nonce_and_changes_the_anchor_id() {
        let header = header();
        let mut root = [0xA5; SYNTHETIC_ROOT_FIXTURE_LENGTH];
        let first = CandidateKeystorePayloadV1::seal_synthetic_fixture(
            header,
            7,
            [9; XCHACHA20POLY1305_NONCE_LENGTH],
            b"correct horse battery staple",
            &root,
        )
        .unwrap();
        let second = CandidateKeystorePayloadV1::seal_synthetic_fixture(
            header,
            8,
            [10; XCHACHA20POLY1305_NONCE_LENGTH],
            b"correct horse battery staple",
            &root,
        )
        .unwrap();
        root.zeroize();
        assert_ne!(first.ciphertext_id(), second.ciphertext_id());

        let anchor =
            ExternalRollbackAnchorV1::new(header.id(), second.generation(), second.ciphertext_id())
                .unwrap();
        assert_eq!(
            anchor.verify(header.id(), first.generation(), first.ciphertext_id()),
            Err(ExternalRollbackAnchorMismatch::PayloadGeneration {
                anchored: second.generation(),
                presented: first.generation(),
            })
        );
    }

    #[test]
    fn decoder_rejects_malformed_or_absent_payload_metadata() {
        let header = header();
        let payload = CandidateKeystorePayloadV1::seal_synthetic_fixture(
            header,
            7,
            [9; XCHACHA20POLY1305_NONCE_LENGTH],
            b"correct horse battery staple",
            &[0xA5; SYNTHETIC_ROOT_FIXTURE_LENGTH],
        )
        .unwrap();
        assert_eq!(
            CandidateKeystorePayloadV1::decode(&payload.encode()[..149]),
            Err(KeystorePayloadError::InvalidLength { actual: 149 })
        );
        let mut wrong_magic = payload.encode();
        wrong_magic[0] ^= 1;
        assert_eq!(
            CandidateKeystorePayloadV1::decode(&wrong_magic),
            Err(KeystorePayloadError::InvalidMagic)
        );
        let mut wrong_version = payload.encode();
        wrong_version[5] ^= 1;
        assert_eq!(
            CandidateKeystorePayloadV1::decode(&wrong_version),
            Err(KeystorePayloadError::UnsupportedVersion)
        );
        let mut zero_generation = payload.encode();
        zero_generation[38..46].fill(0);
        assert_eq!(
            CandidateKeystorePayloadV1::decode(&zero_generation),
            Err(KeystorePayloadError::ZeroGeneration)
        );
        let mut zero_nonce = payload.encode();
        zero_nonce[46..70].fill(0);
        assert_eq!(
            CandidateKeystorePayloadV1::decode(&zero_nonce),
            Err(KeystorePayloadError::ZeroNonce)
        );
        assert_eq!(
            CandidatePayloadCiphertextIdV1::new([0; 32]),
            Err(KeystorePayloadError::ZeroCiphertextId)
        );
    }
}
