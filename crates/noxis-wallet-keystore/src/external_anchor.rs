//! Public external rollback-anchor receipt candidate.
//!
//! A caller must retain the canonical bytes outside the wallet directory. This
//! type has no filesystem API because placing the receipt beside the keystore
//! would not create an independent rollback anchor.

use std::fmt;

use crate::{CandidatePayloadCiphertextIdV1, KeystoreHeaderIdV1};

/// Magic for a public external rollback-anchor receipt.
pub const EXTERNAL_ROLLBACK_ANCHOR_MAGIC: [u8; 4] = *b"NXKA";
/// Only candidate receipt layout accepted by this crate.
pub const EXTERNAL_ROLLBACK_ANCHOR_VERSION: u16 = 1;
/// Exact byte length of one `NXKA v1` receipt.
pub const EXTERNAL_ROLLBACK_ANCHOR_V1_LENGTH: usize = 78;

/// Canonical public receipt that a user must retain outside the keystore
/// directory to detect restoration of a different known payload generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExternalRollbackAnchorV1 {
    header_id: KeystoreHeaderIdV1,
    payload_generation: u64,
    ciphertext_id: CandidatePayloadCiphertextIdV1,
}

impl ExternalRollbackAnchorV1 {
    /// Creates one receipt for a complete candidate encrypted-payload
    /// generation. Generation zero is reserved for the pre-payload state and
    /// cannot produce a rollback receipt.
    pub fn new(
        header_id: KeystoreHeaderIdV1,
        payload_generation: u64,
        ciphertext_id: CandidatePayloadCiphertextIdV1,
    ) -> Result<Self, ExternalRollbackAnchorError> {
        if payload_generation == 0 {
            return Err(ExternalRollbackAnchorError::ZeroPayloadGeneration);
        }
        Ok(Self {
            header_id,
            payload_generation,
            ciphertext_id,
        })
    }

    /// Strictly decodes one canonical receipt. The caller is responsible for
    /// ensuring the bytes came from storage independent of the wallet
    /// directory; this type cannot establish that property itself.
    pub fn decode(bytes: &[u8]) -> Result<Self, ExternalRollbackAnchorError> {
        if bytes.len() != EXTERNAL_ROLLBACK_ANCHOR_V1_LENGTH {
            return Err(ExternalRollbackAnchorError::InvalidLength {
                actual: bytes.len(),
            });
        }
        if bytes[..4] != EXTERNAL_ROLLBACK_ANCHOR_MAGIC {
            return Err(ExternalRollbackAnchorError::InvalidMagic);
        }
        if u16::from_be_bytes(bytes[4..6].try_into().expect("fixed version slice"))
            != EXTERNAL_ROLLBACK_ANCHOR_VERSION
        {
            return Err(ExternalRollbackAnchorError::UnsupportedVersion);
        }
        let header_id =
            KeystoreHeaderIdV1::from_bytes(bytes[6..38].try_into().expect("fixed header ID slice"));
        let payload_generation =
            u64::from_be_bytes(bytes[38..46].try_into().expect("fixed generation slice"));
        let ciphertext_id = CandidatePayloadCiphertextIdV1::new(
            bytes[46..78].try_into().expect("fixed ciphertext ID slice"),
        )
        .map_err(|_| ExternalRollbackAnchorError::ZeroCiphertextId)?;
        Self::new(header_id, payload_generation, ciphertext_id)
    }

    /// Canonical receipt bytes suitable for external backup storage.
    pub fn encode(self) -> [u8; EXTERNAL_ROLLBACK_ANCHOR_V1_LENGTH] {
        let mut bytes = [0_u8; EXTERNAL_ROLLBACK_ANCHOR_V1_LENGTH];
        bytes[..4].copy_from_slice(&EXTERNAL_ROLLBACK_ANCHOR_MAGIC);
        bytes[4..6].copy_from_slice(&EXTERNAL_ROLLBACK_ANCHOR_VERSION.to_be_bytes());
        bytes[6..38].copy_from_slice(&self.header_id.as_bytes());
        bytes[38..46].copy_from_slice(&self.payload_generation.to_be_bytes());
        bytes[46..78].copy_from_slice(&self.ciphertext_id.as_bytes());
        bytes
    }

    /// Checks whether public payload metadata matches this external receipt.
    /// A future wallet must fail closed before spend-capable operation whenever
    /// this check fails or no independently retained receipt is present.
    pub fn verify(
        self,
        header_id: KeystoreHeaderIdV1,
        payload_generation: u64,
        ciphertext_id: CandidatePayloadCiphertextIdV1,
    ) -> Result<(), ExternalRollbackAnchorMismatch> {
        if self.header_id != header_id {
            return Err(ExternalRollbackAnchorMismatch::HeaderId);
        }
        if self.payload_generation != payload_generation {
            return Err(ExternalRollbackAnchorMismatch::PayloadGeneration {
                anchored: self.payload_generation,
                presented: payload_generation,
            });
        }
        if self.ciphertext_id != ciphertext_id {
            return Err(ExternalRollbackAnchorMismatch::CiphertextId);
        }
        Ok(())
    }

    pub const fn header_id(self) -> KeystoreHeaderIdV1 {
        self.header_id
    }

    pub const fn payload_generation(self) -> u64 {
        self.payload_generation
    }
}

/// Invalid public receipt input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalRollbackAnchorError {
    InvalidLength { actual: usize },
    InvalidMagic,
    UnsupportedVersion,
    ZeroPayloadGeneration,
    ZeroCiphertextId,
}

impl fmt::Display for ExternalRollbackAnchorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLength { .. } => "external rollback anchor has invalid length",
            Self::InvalidMagic => "external rollback anchor has invalid magic",
            Self::UnsupportedVersion => "external rollback anchor has unsupported version",
            Self::ZeroPayloadGeneration => "external rollback anchor has zero payload generation",
            Self::ZeroCiphertextId => "external rollback anchor has zero ciphertext ID",
        })
    }
}

impl std::error::Error for ExternalRollbackAnchorError {}

/// Public metadata presented by a future keystore did not match its externally
/// retained receipt. This error contains no password, root or plaintext.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalRollbackAnchorMismatch {
    HeaderId,
    PayloadGeneration { anchored: u64, presented: u64 },
    CiphertextId,
}

impl fmt::Display for ExternalRollbackAnchorMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::HeaderId => "external rollback anchor belongs to another header",
            Self::PayloadGeneration { .. } => "external rollback anchor generation differs",
            Self::CiphertextId => "external rollback anchor ciphertext differs",
        })
    }
}

impl std::error::Error for ExternalRollbackAnchorMismatch {}

#[cfg(test)]
mod tests {
    use crate::KeystoreHeaderV2;

    use super::*;

    fn header_id() -> KeystoreHeaderIdV1 {
        KeystoreHeaderV2::generate([7; 32], 42).unwrap().id()
    }

    fn ciphertext_id(byte: u8) -> CandidatePayloadCiphertextIdV1 {
        CandidatePayloadCiphertextIdV1::new([byte; 32]).unwrap()
    }

    #[test]
    fn anchor_round_trips_and_binds_all_public_payload_metadata() {
        let header_id = header_id();
        let anchor = ExternalRollbackAnchorV1::new(header_id, 7, ciphertext_id(9)).unwrap();
        assert_eq!(
            ExternalRollbackAnchorV1::decode(&anchor.encode()).unwrap(),
            anchor
        );
        assert_eq!(anchor.verify(header_id, 7, ciphertext_id(9)), Ok(()));
        assert_eq!(
            anchor.verify(header_id, 6, ciphertext_id(9)),
            Err(ExternalRollbackAnchorMismatch::PayloadGeneration {
                anchored: 7,
                presented: 6,
            })
        );
        assert_eq!(
            anchor.verify(header_id, 7, ciphertext_id(10)),
            Err(ExternalRollbackAnchorMismatch::CiphertextId)
        );
    }

    #[test]
    fn anchor_rejects_noncanonical_or_unanchored_values() {
        let header_id = header_id();
        assert_eq!(
            ExternalRollbackAnchorV1::new(header_id, 0, ciphertext_id(9)),
            Err(ExternalRollbackAnchorError::ZeroPayloadGeneration)
        );
        assert_eq!(
            CandidatePayloadCiphertextIdV1::new([0; 32]),
            Err(crate::KeystorePayloadError::ZeroCiphertextId)
        );
        let anchor = ExternalRollbackAnchorV1::new(header_id, 7, ciphertext_id(9)).unwrap();
        let mut malformed = anchor.encode();
        malformed[0] ^= 1;
        assert_eq!(
            ExternalRollbackAnchorV1::decode(&malformed),
            Err(ExternalRollbackAnchorError::InvalidMagic)
        );
        let mut absent_ciphertext_id = anchor.encode();
        absent_ciphertext_id[46..78].fill(0);
        assert_eq!(
            ExternalRollbackAnchorV1::decode(&absent_ciphertext_id),
            Err(ExternalRollbackAnchorError::ZeroCiphertextId)
        );
        assert_eq!(
            anchor.verify(
                KeystoreHeaderV2::generate([8; 32], 42).unwrap().id(),
                7,
                ciphertext_id(9)
            ),
            Err(ExternalRollbackAnchorMismatch::HeaderId)
        );
    }
}
