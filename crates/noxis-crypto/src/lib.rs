//! Cryptographic contracts, not cryptographic implementations.
//!
//! Implementations plugged into these traits must be audited independently.

use std::fmt;

use noxis_types::{
    AssetId, Commitment, GenesisId, MintPolicyId, Nullifier, ProofVerifierId, StateId,
    TransactionIntentId, ValidationContextId,
};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlgorithmId {
    Sha256,
    Sha3_256,
    X25519,
    MlKem768,
    Ed25519,
    MlDsa65,
    PluggableProofSystem,
}

impl AlgorithmId {
    const fn protocol_tag(self) -> u8 {
        match self {
            Self::Sha256 => 1,
            Self::Sha3_256 => 2,
            Self::X25519 => 3,
            Self::MlKem768 => 4,
            Self::Ed25519 => 5,
            Self::MlDsa65 => 6,
            Self::PluggableProofSystem => 7,
        }
    }

    fn from_protocol_tag(tag: u8) -> Result<Self, ValidationContextError> {
        match tag {
            1 => Ok(Self::Sha256),
            2 => Ok(Self::Sha3_256),
            3 => Ok(Self::X25519),
            4 => Ok(Self::MlKem768),
            5 => Ok(Self::Ed25519),
            6 => Ok(Self::MlDsa65),
            7 => Ok(Self::PluggableProofSystem),
            _ => Err(ValidationContextError::UnknownAlgorithm(tag)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CryptoSuite {
    pub version: u16,
    pub hash: AlgorithmId,
    pub transport_kem: AlgorithmId,
    pub identity_signature: AlgorithmId,
    pub proof_system: AlgorithmId,
}

impl CryptoSuite {
    pub const RESEARCH_V1: Self = Self {
        version: 1,
        // Current state/record identifiers and the provisional tree use
        // SHA-256. This remains explicitly non-ZK-compatible research wiring.
        hash: AlgorithmId::Sha256,
        transport_kem: AlgorithmId::MlKem768,
        identity_signature: AlgorithmId::MlDsa65,
        proof_system: AlgorithmId::PluggableProofSystem,
    };

    /// Checks that each algorithm label is legal for its named protocol role.
    ///
    /// This does not claim that the primitive is implemented or audited. It
    /// prevents a canonical message from mislabeling a hash as a signature or
    /// a proof-system placeholder as a transport mechanism.
    pub const fn validate(self) -> Result<(), CryptoSuiteError> {
        if self.version == 0 {
            return Err(CryptoSuiteError::ZeroVersion);
        }
        if !matches!(self.hash, AlgorithmId::Sha256 | AlgorithmId::Sha3_256) {
            return Err(CryptoSuiteError::AlgorithmRoleMismatch {
                field: CryptoSuiteField::Hash,
                algorithm: self.hash,
            });
        }
        if !matches!(
            self.transport_kem,
            AlgorithmId::X25519 | AlgorithmId::MlKem768
        ) {
            return Err(CryptoSuiteError::AlgorithmRoleMismatch {
                field: CryptoSuiteField::TransportKem,
                algorithm: self.transport_kem,
            });
        }
        if !matches!(
            self.identity_signature,
            AlgorithmId::Ed25519 | AlgorithmId::MlDsa65
        ) {
            return Err(CryptoSuiteError::AlgorithmRoleMismatch {
                field: CryptoSuiteField::IdentitySignature,
                algorithm: self.identity_signature,
            });
        }
        if !matches!(self.proof_system, AlgorithmId::PluggableProofSystem) {
            return Err(CryptoSuiteError::AlgorithmRoleMismatch {
                field: CryptoSuiteField::ProofSystem,
                algorithm: self.proof_system,
            });
        }
        Ok(())
    }
}

/// A named slot in a [`CryptoSuite`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoSuiteField {
    Hash,
    TransportKem,
    IdentitySignature,
    ProofSystem,
}

impl fmt::Display for CryptoSuiteField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Hash => "hash",
            Self::TransportKem => "transport KEM",
            Self::IdentitySignature => "identity signature",
            Self::ProofSystem => "proof system",
        })
    }
}

/// A suite uses a valid algorithm name in an invalid protocol role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoSuiteError {
    ZeroVersion,
    AlgorithmRoleMismatch {
        field: CryptoSuiteField,
        algorithm: AlgorithmId,
    },
}

impl fmt::Display for CryptoSuiteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroVersion => {
                formatter.write_str("cryptographic suite version must be non-zero")
            }
            Self::AlgorithmRoleMismatch { field, algorithm } => write!(
                formatter,
                "algorithm {algorithm:?} is not valid for the {field} suite field"
            ),
        }
    }
}

impl std::error::Error for CryptoSuiteError {}

/// Versioned public description of all components that decide transaction validity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidationContext {
    crypto_suite: CryptoSuite,
    proof_verifier_id: ProofVerifierId,
    mint_policy_id: MintPolicyId,
}

/// An unforgeable, context-bound permission to construct a settlement service.
///
/// No production authorization is issued in this release. The type exists so a
/// future audited suite can be approved centrally without allowing callers to
/// claim approval merely by selecting algorithm labels in a configuration.
#[derive(Debug)]
pub struct SettlementServiceAuthorization {
    validation_context_id: ValidationContextId,
}

impl ValidationContext {
    /// Byte length of the canonical public encoding.
    pub const ENCODED_LENGTH: usize = 2 + 4 + 64;

    /// Constructs a context from public, stable component identities.
    pub const fn new(
        crypto_suite: CryptoSuite,
        proof_verifier_id: ProofVerifierId,
        mint_policy_id: MintPolicyId,
    ) -> Self {
        Self {
            crypto_suite,
            proof_verifier_id,
            mint_policy_id,
        }
    }

    pub const fn crypto_suite(self) -> CryptoSuite {
        self.crypto_suite
    }

    pub const fn proof_verifier_id(self) -> ProofVerifierId {
        self.proof_verifier_id
    }

    pub const fn mint_policy_id(self) -> MintPolicyId {
        self.mint_policy_id
    }

    /// Validates the declared suite before it enters a genesis or recovery path.
    pub const fn validate(self) -> Result<(), ValidationContextError> {
        match self.crypto_suite.validate() {
            Ok(()) => Ok(()),
            Err(error) => Err(ValidationContextError::InvalidCryptoSuite(error)),
        }
    }

    /// Requests authorization to construct a settlement service.
    ///
    /// This release deliberately has no approved production proof system,
    /// commitment tree, key-management design or independent audit. Therefore
    /// every context fails closed, including contexts whose labels are valid.
    pub const fn authorize_settlement_service(
        self,
    ) -> Result<SettlementServiceAuthorization, ServiceCryptoEligibilityError> {
        let _ = self;
        Err(ServiceCryptoEligibilityError::UnapprovedValidationContext)
    }

    /// Authorizes a research-only fixture for the built-in `RESEARCH_V1` suite.
    ///
    /// This API is excluded unless the consuming crate explicitly enables the
    /// `research-testing` feature. It exists solely to exercise deterministic
    /// persistence and ABCI lifecycle tests; it does not authorize custody,
    /// public networking, a testnet carrying value, or any privacy claim.
    #[cfg(feature = "research-testing")]
    pub fn authorize_research_testing(
        self,
    ) -> Result<SettlementServiceAuthorization, ServiceCryptoEligibilityError> {
        if self.crypto_suite != CryptoSuite::RESEARCH_V1 {
            return Err(ServiceCryptoEligibilityError::UnapprovedValidationContext);
        }
        Ok(SettlementServiceAuthorization {
            validation_context_id: self.id(),
        })
    }

    /// Hash-addressed identity of this canonical public context.
    pub fn id(self) -> ValidationContextId {
        let mut hash = Sha256::new();
        hash.update(b"NOXIS/VALIDATION-CONTEXT/V1\0");
        hash.update(self.encode());
        ValidationContextId::new(hash.finalize().into())
    }

    /// Canonical, fixed-width public encoding for manifests and genesis IDs.
    pub fn encode(self) -> [u8; Self::ENCODED_LENGTH] {
        let mut bytes = [0_u8; Self::ENCODED_LENGTH];
        bytes[..2].copy_from_slice(&self.crypto_suite.version.to_be_bytes());
        bytes[2] = self.crypto_suite.hash.protocol_tag();
        bytes[3] = self.crypto_suite.transport_kem.protocol_tag();
        bytes[4] = self.crypto_suite.identity_signature.protocol_tag();
        bytes[5] = self.crypto_suite.proof_system.protocol_tag();
        bytes[6..38].copy_from_slice(&self.proof_verifier_id.0);
        bytes[38..70].copy_from_slice(&self.mint_policy_id.0);
        bytes
    }

    /// Decodes exactly one canonical context encoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, ValidationContextError> {
        if bytes.len() != Self::ENCODED_LENGTH {
            return Err(ValidationContextError::InvalidLength {
                actual: bytes.len(),
                expected: Self::ENCODED_LENGTH,
            });
        }
        let context = Self::new(
            CryptoSuite {
                version: u16::from_be_bytes([bytes[0], bytes[1]]),
                hash: AlgorithmId::from_protocol_tag(bytes[2])?,
                transport_kem: AlgorithmId::from_protocol_tag(bytes[3])?,
                identity_signature: AlgorithmId::from_protocol_tag(bytes[4])?,
                proof_system: AlgorithmId::from_protocol_tag(bytes[5])?,
            },
            ProofVerifierId::new(bytes[6..38].try_into().expect("fixed context field length")),
            MintPolicyId::new(
                bytes[38..70]
                    .try_into()
                    .expect("fixed context field length"),
            ),
        );
        context.validate()?;
        Ok(context)
    }
}

impl SettlementServiceAuthorization {
    /// Rejects use of an authorization emitted for another validation context.
    pub fn ensure_matches(
        &self,
        context: ValidationContext,
    ) -> Result<(), ServiceCryptoEligibilityError> {
        if self.validation_context_id != context.id() {
            return Err(ServiceCryptoEligibilityError::AuthorizationContextMismatch);
        }
        Ok(())
    }
}

/// A public validation-context encoding cannot be interpreted safely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationContextError {
    InvalidLength { actual: usize, expected: usize },
    UnknownAlgorithm(u8),
    InvalidCryptoSuite(CryptoSuiteError),
}

impl fmt::Display for ValidationContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { actual, expected } => {
                write!(
                    formatter,
                    "validation context has {actual} bytes; expected {expected}"
                )
            }
            Self::UnknownAlgorithm(tag) => {
                write!(
                    formatter,
                    "validation context has unknown algorithm tag {tag}"
                )
            }
            Self::InvalidCryptoSuite(error) => {
                write!(
                    formatter,
                    "validation context has invalid cryptographic suite: {error}"
                )
            }
        }
    }
}

impl std::error::Error for ValidationContextError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidCryptoSuite(error) => Some(error),
            _ => None,
        }
    }
}

/// A request to start settlement processing without an approved crypto stack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceCryptoEligibilityError {
    /// No concrete production suite has been approved in this release.
    UnapprovedValidationContext,
    /// A capability issued for one context was presented with another one.
    AuthorizationContextMismatch,
}

impl fmt::Display for ServiceCryptoEligibilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnapprovedValidationContext => formatter.write_str(
                "the validation context has no approved production cryptographic implementation",
            ),
            Self::AuthorizationContextMismatch => formatter.write_str(
                "settlement-service authorization belongs to a different validation context",
            ),
        }
    }
}

impl std::error::Error for ServiceCryptoEligibilityError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof {
    pub suite_version: u16,
    pub bytes: Vec<u8>,
}

/// The exact public state commitment against which a transfer proof is checked.
///
/// This value is produced by the ledger's commitment tree. The tree depth is
/// included so roots from different state domains cannot be interchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateAnchor {
    pub root: [u8; 32],
    pub tree_depth: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferStatement {
    /// Deployment identity that prevents proof reuse across unrelated ledgers.
    pub genesis_id: GenesisId,
    /// Public identity of the verification rules used for this transfer.
    pub validation_context_id: ValidationContextId,
    /// Non-self-referential identity of the transfer semantics being proved.
    pub transaction_intent_id: TransactionIntentId,
    /// Complete local state identity, in addition to the Merkle root used for membership.
    pub state_id: StateId,
    pub asset_id: AssetId,
    pub input_nullifiers: Vec<Nullifier>,
    pub output_commitments: Vec<Commitment>,
    pub state_anchor: StateAnchor,
}

pub trait ProofVerifier: Send + Sync {
    /// Stable public identity of this verifier's circuit, parameters and rules.
    ///
    /// It is committed by the genesis validation context and compared before
    /// historical state records or checkpoints are replayed.
    fn proof_verifier_id(&self) -> ProofVerifierId;

    /// Verifies membership, authorization, conservation and privacy properties of a transfer.
    fn verify_transfer(
        &self,
        statement: &TransferStatement,
        proof: &Proof,
    ) -> Result<(), VerificationError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationError {
    UnsupportedSuite,
    InvalidProof,
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSuite => {
                formatter.write_str("proof uses an unsupported cryptographic suite")
            }
            Self::InvalidProof => formatter.write_str("proof verification failed"),
        }
    }
}

impl std::error::Error for VerificationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_context_round_trips_and_changes_when_a_component_changes() {
        let context = ValidationContext::new(
            CryptoSuite::RESEARCH_V1,
            ProofVerifierId::new([1; 32]),
            MintPolicyId::new([2; 32]),
        );
        assert_eq!(
            ValidationContext::decode(&context.encode()).unwrap(),
            context
        );
        assert_ne!(
            context.id(),
            ValidationContext::new(
                CryptoSuite::RESEARCH_V1,
                ProofVerifierId::new([3; 32]),
                MintPolicyId::new([2; 32]),
            )
            .id()
        );
        assert_ne!(
            context.id(),
            ValidationContext::new(
                CryptoSuite::RESEARCH_V1,
                ProofVerifierId::new([1; 32]),
                MintPolicyId::new([4; 32]),
            )
            .id()
        );
    }

    #[test]
    fn validation_context_rejects_unknown_algorithm_tags() {
        let context = ValidationContext::new(
            CryptoSuite::RESEARCH_V1,
            ProofVerifierId::new([1; 32]),
            MintPolicyId::new([2; 32]),
        );
        let mut encoded = context.encode();
        encoded[2] = 255;
        assert_eq!(
            ValidationContext::decode(&encoded),
            Err(ValidationContextError::UnknownAlgorithm(255))
        );
    }

    #[test]
    fn validation_context_rejects_a_known_algorithm_in_the_wrong_role() {
        let invalid_suite = CryptoSuite {
            hash: AlgorithmId::Ed25519,
            ..CryptoSuite::RESEARCH_V1
        };
        assert_eq!(
            invalid_suite.validate(),
            Err(CryptoSuiteError::AlgorithmRoleMismatch {
                field: CryptoSuiteField::Hash,
                algorithm: AlgorithmId::Ed25519,
            })
        );

        let context = ValidationContext::new(
            invalid_suite,
            ProofVerifierId::new([1; 32]),
            MintPolicyId::new([2; 32]),
        );
        assert_eq!(
            ValidationContext::decode(&context.encode()),
            Err(ValidationContextError::InvalidCryptoSuite(
                CryptoSuiteError::AlgorithmRoleMismatch {
                    field: CryptoSuiteField::Hash,
                    algorithm: AlgorithmId::Ed25519,
                }
            ))
        );
    }

    #[test]
    fn no_context_can_claim_production_settlement_approval() {
        let context = ValidationContext::new(
            CryptoSuite::RESEARCH_V1,
            ProofVerifierId::new([1; 32]),
            MintPolicyId::new([2; 32]),
        );
        assert!(matches!(
            context.authorize_settlement_service(),
            Err(ServiceCryptoEligibilityError::UnapprovedValidationContext)
        ));
    }

    #[cfg(feature = "research-testing")]
    #[test]
    fn research_authorization_is_bound_to_its_exact_context() {
        let context = ValidationContext::new(
            CryptoSuite::RESEARCH_V1,
            ProofVerifierId::new([1; 32]),
            MintPolicyId::new([2; 32]),
        );
        let authorization = context.authorize_research_testing().unwrap();
        assert!(authorization.ensure_matches(context).is_ok());
        assert_eq!(
            authorization.ensure_matches(ValidationContext::new(
                CryptoSuite::RESEARCH_V1,
                ProofVerifierId::new([3; 32]),
                MintPolicyId::new([2; 32]),
            )),
            Err(ServiceCryptoEligibilityError::AuthorizationContextMismatch)
        );
    }
}
