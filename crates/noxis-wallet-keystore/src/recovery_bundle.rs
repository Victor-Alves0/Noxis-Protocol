//! Portable synthetic backup bundle with an external rollback-anchor boundary.
//!
//! `NXKB v1` contains only public `NXKS` metadata plus opaque synthetic `NXKP`
//! ciphertext. It deliberately excludes `NXKA`: a receipt kept inside the same
//! backup artifact could not independently detect restoration of an older one.

use std::fmt;

use crate::{
    CandidateKeystoreHeaderStore, CandidateKeystorePayloadV1, ExternalRollbackAnchorMismatch,
    ExternalRollbackAnchorV1, HeaderStoreError, HeaderStoreInitializeOutcome,
    KEYSTORE_HEADER_V2_LENGTH, KEYSTORE_PAYLOAD_V1_LENGTH, KeystoreHeaderError, KeystoreHeaderV2,
    KeystorePayloadBindingError, KeystorePayloadError, PayloadStoreError,
    PayloadStorePublishOutcome,
};

/// Synthetic recovery-bundle magic bytes.
pub const SYNTHETIC_RECOVERY_BUNDLE_MAGIC: [u8; 4] = *b"NXKB";
/// Only synthetic recovery-bundle layout accepted by this crate.
pub const SYNTHETIC_RECOVERY_BUNDLE_VERSION: u16 = 1;
/// Exact serialized length of `NXKB v1`.
pub const SYNTHETIC_RECOVERY_BUNDLE_V1_LENGTH: usize =
    6 + KEYSTORE_HEADER_V2_LENGTH + KEYSTORE_PAYLOAD_V1_LENGTH;

/// Portable pairing of a public header and opaque synthetic payload. It has no
/// plaintext, password, spend key, view key or rollback receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateSyntheticRecoveryBundleV1 {
    header: KeystoreHeaderV2,
    payload: CandidateKeystorePayloadV1,
}

impl CandidateSyntheticRecoveryBundleV1 {
    /// Captures a verified recovery unit from one already-locked candidate
    /// directory. The caller supplies the external `NXKA` receipt separately;
    /// it is checked but never embedded in the returned bundle.
    pub fn capture(
        source: &CandidateKeystoreHeaderStore,
        external_anchor: ExternalRollbackAnchorV1,
    ) -> Result<Self, RecoveryBundleError> {
        let header = source
            .load()
            .map_err(|source| RecoveryBundleError::HeaderStore { source })?;
        let payload = source
            .open_payloads()
            .map_err(|source| RecoveryBundleError::PayloadStore { source })?
            .load_anchored(external_anchor)
            .map_err(|source| RecoveryBundleError::PayloadStore { source })?;
        Self::new(header, payload)
    }

    /// Strictly decodes exact canonical `NXKB v1` bytes. The rollback receipt
    /// is intentionally absent and must be verified later from independent
    /// storage before any target directory is mutated.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecoveryBundleError> {
        if bytes.len() != SYNTHETIC_RECOVERY_BUNDLE_V1_LENGTH {
            return Err(RecoveryBundleError::InvalidLength {
                actual: bytes.len(),
            });
        }
        if bytes[..4] != SYNTHETIC_RECOVERY_BUNDLE_MAGIC {
            return Err(RecoveryBundleError::InvalidMagic);
        }
        if u16::from_be_bytes(bytes[4..6].try_into().expect("fixed version slice"))
            != SYNTHETIC_RECOVERY_BUNDLE_VERSION
        {
            return Err(RecoveryBundleError::UnsupportedVersion);
        }
        let header = KeystoreHeaderV2::decode(&bytes[6..6 + KEYSTORE_HEADER_V2_LENGTH])
            .map_err(|source| RecoveryBundleError::Header { source })?;
        let payload = CandidateKeystorePayloadV1::decode(&bytes[6 + KEYSTORE_HEADER_V2_LENGTH..])
            .map_err(|source| RecoveryBundleError::Payload { source })?;
        Self::new(header, payload)
    }

    /// Canonical public/opaque recovery bytes. `NXKA` is never included.
    pub fn encode(self) -> [u8; SYNTHETIC_RECOVERY_BUNDLE_V1_LENGTH] {
        let mut bytes = [0_u8; SYNTHETIC_RECOVERY_BUNDLE_V1_LENGTH];
        bytes[..4].copy_from_slice(&SYNTHETIC_RECOVERY_BUNDLE_MAGIC);
        bytes[4..6].copy_from_slice(&SYNTHETIC_RECOVERY_BUNDLE_VERSION.to_be_bytes());
        bytes[6..6 + KEYSTORE_HEADER_V2_LENGTH].copy_from_slice(&self.header.encode());
        bytes[6 + KEYSTORE_HEADER_V2_LENGTH..].copy_from_slice(&self.payload.encode());
        bytes
    }

    /// Requires a receipt retained independently of both source and target
    /// directories. This check happens before restore mutates the target.
    pub fn verify_external_anchor(
        self,
        external_anchor: ExternalRollbackAnchorV1,
    ) -> Result<(), RecoveryBundleError> {
        external_anchor
            .verify(
                self.header.id(),
                self.payload.generation(),
                self.payload.ciphertext_id(),
            )
            .map_err(|source| RecoveryBundleError::ExternalAnchorMismatch { source })
    }

    /// Restores this synthetic bundle into a separate already-locked target
    /// directory after preflighting its external rollback receipt. The payload
    /// store then rechecks header, generation, nonce and ciphertext identity.
    /// This is not a secret restore path.
    pub fn restore(
        self,
        destination: &CandidateKeystoreHeaderStore,
        external_anchor: ExternalRollbackAnchorV1,
    ) -> Result<RecoveryRestoreOutcome, RecoveryBundleError> {
        self.verify_external_anchor(external_anchor)?;
        let header = destination
            .initialize(self.header)
            .map_err(|source| RecoveryBundleError::HeaderStore { source })?;
        let payload = destination
            .open_payloads()
            .map_err(|source| RecoveryBundleError::PayloadStore { source })?
            .publish(self.payload, external_anchor)
            .map_err(|source| RecoveryBundleError::PayloadStore { source })?;
        Ok(RecoveryRestoreOutcome { header, payload })
    }

    pub const fn header(self) -> KeystoreHeaderV2 {
        self.header
    }

    pub const fn payload(self) -> CandidateKeystorePayloadV1 {
        self.payload
    }

    fn new(
        header: KeystoreHeaderV2,
        payload: CandidateKeystorePayloadV1,
    ) -> Result<Self, RecoveryBundleError> {
        payload
            .verify_header(header)
            .map_err(|source| RecoveryBundleError::PayloadHeaderBinding { source })?;
        Ok(Self { header, payload })
    }
}

/// Per-file restore outcomes, kept explicit so callers cannot mistake an
/// idempotent header for a newly published payload generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryRestoreOutcome {
    pub header: HeaderStoreInitializeOutcome,
    pub payload: PayloadStorePublishOutcome,
}

/// Parser, source, anchor or target error for the synthetic recovery bundle.
#[derive(Debug)]
pub enum RecoveryBundleError {
    InvalidLength {
        actual: usize,
    },
    InvalidMagic,
    UnsupportedVersion,
    Header {
        source: KeystoreHeaderError,
    },
    Payload {
        source: KeystorePayloadError,
    },
    PayloadHeaderBinding {
        source: KeystorePayloadBindingError,
    },
    ExternalAnchorMismatch {
        source: ExternalRollbackAnchorMismatch,
    },
    HeaderStore {
        source: HeaderStoreError,
    },
    PayloadStore {
        source: PayloadStoreError,
    },
}

impl fmt::Display for RecoveryBundleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { .. } => {
                formatter.write_str("synthetic recovery bundle has invalid length")
            }
            Self::InvalidMagic => {
                formatter.write_str("synthetic recovery bundle has invalid magic")
            }
            Self::UnsupportedVersion => {
                formatter.write_str("synthetic recovery bundle has unsupported version")
            }
            Self::Header { source } => write!(formatter, "synthetic recovery header: {source}"),
            Self::Payload { source } => write!(formatter, "synthetic recovery payload: {source}"),
            Self::PayloadHeaderBinding { source } => {
                write!(
                    formatter,
                    "synthetic recovery header/payload binding: {source}"
                )
            }
            Self::ExternalAnchorMismatch { source } => {
                write!(formatter, "synthetic recovery external anchor: {source}")
            }
            Self::HeaderStore { source } => {
                write!(formatter, "synthetic recovery header store: {source}")
            }
            Self::PayloadStore { source } => {
                write!(formatter, "synthetic recovery payload store: {source}")
            }
        }
    }
}

impl std::error::Error for RecoveryBundleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Header { source } => Some(source),
            Self::Payload { source } => Some(source),
            Self::PayloadHeaderBinding { source } => Some(source),
            Self::ExternalAnchorMismatch { source } => Some(source),
            Self::HeaderStore { source } => Some(source),
            Self::PayloadStore { source } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::{
        CandidateKeystoreHeaderStore, CandidateKeystorePayloadV1, CandidatePayloadCiphertextIdV1,
        ExternalRollbackAnchorV1, HeaderStoreError, HeaderStoreInitializeOutcome, KeystoreHeaderV2,
        PayloadStorePublishOutcome,
    };

    use super::{
        CandidateSyntheticRecoveryBundleV1, RecoveryBundleError, RecoveryRestoreOutcome,
        SYNTHETIC_RECOVERY_BUNDLE_V1_LENGTH,
    };

    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn test_directory(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "noxis-wallet-keystore-recovery-{label}-{}-{}",
            std::process::id(),
            TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn header() -> KeystoreHeaderV2 {
        KeystoreHeaderV2::with_test_entropy([7; 32], 42, [8; 16])
    }

    fn synthetic_payload(
        header: KeystoreHeaderV2,
        generation: u64,
        nonce: u8,
    ) -> CandidateKeystorePayloadV1 {
        CandidateKeystorePayloadV1::seal_synthetic_fixture(
            header,
            generation,
            [nonce; 24],
            b"correct horse battery staple",
            &[0xA5; 64],
        )
        .unwrap()
    }

    fn anchor_for(
        header: KeystoreHeaderV2,
        payload: CandidateKeystorePayloadV1,
    ) -> ExternalRollbackAnchorV1 {
        ExternalRollbackAnchorV1::new(header.id(), payload.generation(), payload.ciphertext_id())
            .unwrap()
    }

    #[test]
    fn bundle_round_trips_between_distinct_directories_with_external_anchor() {
        let source_root = test_directory("source");
        let destination_root = test_directory("destination");
        let header = header();
        let payload = synthetic_payload(header, 7, 9);
        let external_anchor = anchor_for(header, payload);
        let serialized_anchor =
            ExternalRollbackAnchorV1::decode(&external_anchor.encode()).unwrap();
        let bundle = {
            let source = CandidateKeystoreHeaderStore::open(&source_root).unwrap();
            source.initialize(header).unwrap();
            source
                .open_payloads()
                .unwrap()
                .publish(payload, external_anchor)
                .unwrap();
            CandidateSyntheticRecoveryBundleV1::capture(&source, serialized_anchor).unwrap()
        };
        let bundle = CandidateSyntheticRecoveryBundleV1::decode(&bundle.encode()).unwrap();
        let destination = CandidateKeystoreHeaderStore::open(&destination_root).unwrap();
        assert_eq!(
            bundle.restore(&destination, serialized_anchor).unwrap(),
            RecoveryRestoreOutcome {
                header: HeaderStoreInitializeOutcome::Initialized,
                payload: PayloadStorePublishOutcome::Published,
            }
        );
        assert_eq!(
            destination
                .open_payloads()
                .unwrap()
                .load_anchored(serialized_anchor)
                .unwrap(),
            payload
        );
        drop(destination);
        std::fs::remove_dir_all(source_root).unwrap();
        std::fs::remove_dir_all(destination_root).unwrap();
    }

    #[test]
    fn wrong_external_anchor_fails_before_target_initialization() {
        let source_root = test_directory("wrong-anchor-source");
        let destination_root = test_directory("wrong-anchor-destination");
        let header = header();
        let payload = synthetic_payload(header, 7, 9);
        let valid_anchor = anchor_for(header, payload);
        let bundle = {
            let source = CandidateKeystoreHeaderStore::open(&source_root).unwrap();
            source.initialize(header).unwrap();
            source
                .open_payloads()
                .unwrap()
                .publish(payload, valid_anchor)
                .unwrap();
            CandidateSyntheticRecoveryBundleV1::capture(&source, valid_anchor).unwrap()
        };
        let wrong_anchor = ExternalRollbackAnchorV1::new(
            header.id(),
            payload.generation(),
            CandidatePayloadCiphertextIdV1::new([9; 32]).unwrap(),
        )
        .unwrap();
        let destination = CandidateKeystoreHeaderStore::open(&destination_root).unwrap();
        assert!(matches!(
            bundle.restore(&destination, wrong_anchor),
            Err(RecoveryBundleError::ExternalAnchorMismatch { .. })
        ));
        assert!(matches!(
            destination.load(),
            Err(HeaderStoreError::Io { .. })
        ));
        drop(destination);
        std::fs::remove_dir_all(source_root).unwrap();
        std::fs::remove_dir_all(destination_root).unwrap();
    }

    #[test]
    fn parser_rejects_truncated_or_header_substituted_bundle() {
        let header = header();
        let payload = synthetic_payload(header, 7, 9);
        let bundle = CandidateSyntheticRecoveryBundleV1::new(header, payload).unwrap();
        let encoded = bundle.encode();
        assert!(matches!(
            CandidateSyntheticRecoveryBundleV1::decode(
                &encoded[..SYNTHETIC_RECOVERY_BUNDLE_V1_LENGTH - 1]
            ),
            Err(RecoveryBundleError::InvalidLength { actual })
                if actual == SYNTHETIC_RECOVERY_BUNDLE_V1_LENGTH - 1
        ));
        let mut substituted_header = encoded;
        substituted_header[6 + 36] ^= 1;
        assert!(matches!(
            CandidateSyntheticRecoveryBundleV1::decode(&substituted_header),
            Err(RecoveryBundleError::PayloadHeaderBinding { .. })
        ));
    }
}
