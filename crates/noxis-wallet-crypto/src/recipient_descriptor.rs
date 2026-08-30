//! Authenticated local pairing of an incoming address and a note recipient commitment.
//!
//! The descriptor prevents an address/commitment mix-up at the wallet boundary.
//! It is deliberately in-memory only: its signing transcript is canonical, but
//! no public descriptor wire format, trusted directory, key derivation proof or
//! spending API is selected here.

use std::fmt;

use hkdf::Hkdf;
use noxis_poseidon2_privacy_reference::{
    Poseidon2P24PrivacyReference, Poseidon2P24PrivacyReferenceError,
};
use noxis_privacy_types::{PrivacyTypesError, RecipientCommitmentV2};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::{
    CandidateWalletRootV1, HybridIdentityKeypair, HybridIdentityPublicKey, HybridIdentitySignature,
    HybridPaymentAddress, HybridPaymentAddressEntry, HybridRecipientEnvelope,
    HybridRecipientKeypair, PaymentAddressError, PaymentDiversifier, RecipientEnvelopeContext,
    encode_payment_address,
};

/// Stable label inside the signed public recipient-descriptor transcript.
pub const CANDIDATE_RECIPIENT_DESCRIPTOR_DOMAIN: &[u8] =
    b"NOXIS/CANDIDATE-RECIPIENT-DESCRIPTOR/V1\0";

/// Public domain separator for the local-only root derivation. It is not a
/// wire-format identifier and must not be interpreted as a stable keystore
/// standard yet.
pub const CANDIDATE_RECIPIENT_ROOT_DERIVATION_DOMAIN: &[u8] =
    b"NOXIS/CANDIDATE-RECIPIENT-ROOT/V1\0";

const ROOT_DERIVATION_SALT: &[u8] = b"NOXIS/CANDIDATE-RECIPIENT-ROOT/V1/SALT\0";
const DIVERSIFIER_LABEL: &[u8] = b"DIVERSIFIER\0";
const NULLIFIER_LABEL: &[u8] = b"NULLIFIER\0";
const X25519_LABEL: &[u8] = b"X25519\0";
const ML_KEM_768_LABEL: &[u8] = b"ML-KEM-768\0";

/// Local key material pairing one incoming `NXPA` address with one private
/// nullifier key and its `H_ADDR` recipient commitment.
///
/// At creation, the receiving and nullifier secrets are derived from one fresh
/// 64-byte local root using independently labelled HKDF-SHA-256 outputs. The
/// root is erased immediately after construction; recovery/backup is not
/// implemented and the public descriptor cannot prove this relationship.
pub struct CandidatePrivateRecipientKeysetV1 {
    incoming_view_key: Option<CandidateIncomingViewKeyV1>,
    nullifier_key: [u8; 32],
    recipient_commitment: RecipientCommitmentV2,
    descriptor_identity: HybridIdentityKeypair,
}

/// Local, non-exportable authority to scan candidate incoming notes for one
/// recipient address. It intentionally holds no nullifier or spend material.
pub struct CandidateIncomingViewKeyV1 {
    payment_address: HybridPaymentAddressEntry,
    recipient_commitment: RecipientCommitmentV2,
}

/// Public, signed view of a candidate recipient keyset.
///
/// The signature authenticates this exact address/commitment pair to a caller
/// that already trusts the descriptor identity. It does not publicly prove the
/// local root derivation or make that relation visible to a STARK verifier.
#[derive(Clone)]
pub struct CandidatePrivateRecipientDescriptorV1 {
    payment_address: HybridPaymentAddress,
    recipient_commitment: RecipientCommitmentV2,
    descriptor_identity: HybridIdentityPublicKey,
    signature: HybridIdentitySignature,
}

impl CandidatePrivateRecipientKeysetV1 {
    /// Generates a fresh local root, derives recipient index zero, erases the
    /// root, then derives the public `H_ADDR` recipient commitment. Descriptor
    /// identity remains separate: it authenticates the public pair but is not
    /// spend authority.
    pub fn generate(key_epoch: u64) -> Result<Self, CandidatePrivateRecipientError> {
        CandidateWalletRootV1::generate().derive_recipient_keyset(key_epoch, 0)
    }

    pub(crate) fn from_wallet_root(
        root: &CandidateWalletRootV1,
        key_epoch: u64,
        address_index: u32,
    ) -> Result<Self, CandidatePrivateRecipientError> {
        let diversifier = PaymentDiversifier::from_bytes(derive_root_child::<16>(
            root.bytes(),
            key_epoch,
            address_index,
            DIVERSIFIER_LABEL,
            None,
        ));
        let mut nullifier_key = derive_root_child::<32>(
            root.bytes(),
            key_epoch,
            address_index,
            NULLIFIER_LABEL,
            Some(diversifier),
        );
        let mut x25519_seed = derive_root_child::<32>(
            root.bytes(),
            key_epoch,
            address_index,
            X25519_LABEL,
            Some(diversifier),
        );
        let mut ml_kem_768_seed = derive_root_child::<64>(
            root.bytes(),
            key_epoch,
            address_index,
            ML_KEM_768_LABEL,
            Some(diversifier),
        );
        let recipient = HybridRecipientKeypair::from_derived_seeds(x25519_seed, ml_kem_768_seed);
        x25519_seed.zeroize();
        ml_kem_768_seed.zeroize();
        let payment_address =
            HybridPaymentAddressEntry::with_derived_recipient(diversifier, key_epoch, recipient);
        let reference = match Poseidon2P24PrivacyReference::load_candidate() {
            Ok(reference) => reference,
            Err(error) => {
                nullifier_key.zeroize();
                return Err(error.into());
            }
        };
        let recipient_commitment = match reference.hash_addr(&nullifier_key) {
            Ok(elements) => match RecipientCommitmentV2::from_elements(elements) {
                Ok(commitment) => commitment,
                Err(error) => {
                    nullifier_key.zeroize();
                    return Err(error.into());
                }
            },
            Err(error) => {
                nullifier_key.zeroize();
                return Err(error.into());
            }
        };
        Ok(Self {
            incoming_view_key: Some(CandidateIncomingViewKeyV1 {
                payment_address,
                recipient_commitment,
            }),
            nullifier_key,
            recipient_commitment,
            descriptor_identity: HybridIdentityKeypair::generate(),
        })
    }

    #[cfg(test)]
    fn from_root_for_test(
        root: [u8; 64],
        key_epoch: u64,
        address_index: u32,
    ) -> Result<Self, CandidatePrivateRecipientError> {
        CandidateWalletRootV1::from_bytes_for_test(root)
            .derive_recipient_keyset(key_epoch, address_index)
    }

    /// The public receiving material that a sender may verify and use.
    pub fn public_descriptor(&self) -> CandidatePrivateRecipientDescriptorV1 {
        let payment_address = self.incoming_view_key().payment_address().clone();
        let recipient_commitment = self.recipient_commitment;
        let payload = descriptor_payload(&payment_address, recipient_commitment);
        CandidatePrivateRecipientDescriptorV1 {
            payment_address,
            recipient_commitment,
            descriptor_identity: self.descriptor_identity.public_key(),
            signature: self.descriptor_identity.sign(&payload),
        }
    }

    /// Public commitment that a received candidate note must carry.
    pub const fn recipient_commitment(&self) -> RecipientCommitmentV2 {
        self.recipient_commitment
    }

    /// Consumes the full local recipient keyset and retains only incoming
    /// scanning authority. The returned view key cannot access the nullifier
    /// material that was erased before this conversion.
    pub fn into_incoming_view_key(mut self) -> CandidateIncomingViewKeyV1 {
        self.nullifier_key.zeroize();
        self.incoming_view_key
            .take()
            .expect("candidate keyset always owns one incoming view key")
    }

    pub(crate) fn incoming_view_key(&self) -> &CandidateIncomingViewKeyV1 {
        self.incoming_view_key
            .as_ref()
            .expect("candidate keyset always owns one incoming view key")
    }
}

impl Drop for CandidatePrivateRecipientKeysetV1 {
    fn drop(&mut self) {
        self.nullifier_key.zeroize();
    }
}

impl CandidateIncomingViewKeyV1 {
    /// Public incoming address associated with this local scanner. Sharing this
    /// value grants no ability to decrypt or spend.
    pub const fn payment_address(&self) -> &HybridPaymentAddress {
        self.payment_address.address()
    }

    /// Public `H_ADDR` value that an incoming candidate note must carry.
    pub const fn recipient_commitment(&self) -> RecipientCommitmentV2 {
        self.recipient_commitment
    }

    /// Opens only envelopes addressed to this local view key. This is crate
    /// private because candidate-note validation owns the public commitment
    /// check and must not be bypassed by a scanner caller.
    pub(crate) fn decrypt_incoming(
        &self,
        context: &RecipientEnvelopeContext,
        envelope: &HybridRecipientEnvelope,
    ) -> Result<Vec<u8>, PaymentAddressError> {
        self.payment_address.decrypt_incoming(context, envelope)
    }
}

impl CandidatePrivateRecipientDescriptorV1 {
    /// The exact public address to which a sender encrypts the candidate note.
    pub const fn payment_address(&self) -> &HybridPaymentAddress {
        &self.payment_address
    }

    /// The `H_ADDR` value a sender must place inside the candidate note.
    pub const fn recipient_commitment(&self) -> RecipientCommitmentV2 {
        self.recipient_commitment
    }

    /// Verifies both Ed25519 and ML-DSA-65 signature components over the exact
    /// descriptor transcript.
    pub fn verify(&self) -> bool {
        self.descriptor_identity.verify(
            &descriptor_payload(self.payment_address(), self.recipient_commitment),
            &self.signature,
        )
    }
}

fn descriptor_payload(
    payment_address: &HybridPaymentAddress,
    recipient_commitment: RecipientCommitmentV2,
) -> Vec<u8> {
    let address = encode_payment_address(payment_address);
    let mut payload = Vec::with_capacity(
        CANDIDATE_RECIPIENT_DESCRIPTOR_DOMAIN.len()
            + 2
            + address.len()
            + RecipientCommitmentV2::LENGTH,
    );
    payload.extend_from_slice(CANDIDATE_RECIPIENT_DESCRIPTOR_DOMAIN);
    payload.extend_from_slice(&(address.len() as u16).to_be_bytes());
    payload.extend_from_slice(&address);
    payload.extend_from_slice(&recipient_commitment.as_bytes());
    payload
}

fn derive_root_child<const OUTPUT_LENGTH: usize>(
    root: &[u8; 64],
    key_epoch: u64,
    address_index: u32,
    label: &[u8],
    diversifier: Option<PaymentDiversifier>,
) -> [u8; OUTPUT_LENGTH] {
    let hkdf = Hkdf::<Sha256>::new(Some(ROOT_DERIVATION_SALT), root);
    let mut info = Vec::with_capacity(
        CANDIDATE_RECIPIENT_ROOT_DERIVATION_DOMAIN.len()
            + label.len()
            + 8
            + 4
            + diversifier.map_or(0, |_| 16),
    );
    info.extend_from_slice(CANDIDATE_RECIPIENT_ROOT_DERIVATION_DOMAIN);
    info.extend_from_slice(label);
    info.extend_from_slice(&key_epoch.to_be_bytes());
    info.extend_from_slice(&address_index.to_be_bytes());
    if let Some(diversifier) = diversifier {
        info.extend_from_slice(&diversifier.as_bytes());
    }
    let mut output = [0_u8; OUTPUT_LENGTH];
    hkdf.expand(&info, &mut output)
        .expect("fixed root-derivation output is valid for SHA-256 HKDF");
    output
}

/// Fail-closed errors while creating a local candidate recipient keyset.
#[derive(Debug)]
pub enum CandidatePrivateRecipientError {
    PrivacyReference(Poseidon2P24PrivacyReferenceError),
    PrivacyTypes(PrivacyTypesError),
}

impl From<Poseidon2P24PrivacyReferenceError> for CandidatePrivateRecipientError {
    fn from(value: Poseidon2P24PrivacyReferenceError) -> Self {
        Self::PrivacyReference(value)
    }
}

impl From<PrivacyTypesError> for CandidatePrivateRecipientError {
    fn from(value: PrivacyTypesError) -> Self {
        Self::PrivacyTypes(value)
    }
}

impl fmt::Display for CandidatePrivateRecipientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "candidate private recipient error: {self:?}")
    }
}

impl std::error::Error for CandidatePrivateRecipientError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_descriptor_authenticates_its_public_address_and_commitment() {
        let keyset = CandidatePrivateRecipientKeysetV1::generate(4).unwrap();
        let descriptor = keyset.public_descriptor();
        assert!(descriptor.verify());
        assert_eq!(
            descriptor.recipient_commitment(),
            keyset.recipient_commitment()
        );
        assert_eq!(descriptor.payment_address().key_epoch(), 4);
    }

    #[test]
    fn independently_generated_keysets_have_distinct_public_recipient_commitments() {
        let first = CandidatePrivateRecipientKeysetV1::generate(4).unwrap();
        let second = CandidatePrivateRecipientKeysetV1::generate(4).unwrap();
        assert_ne!(first.recipient_commitment(), second.recipient_commitment());
        assert_ne!(
            first.public_descriptor().payment_address().address_id(),
            second.public_descriptor().payment_address().address_id()
        );
    }

    #[test]
    fn fixed_root_reproduces_the_complete_public_recipient_pair() {
        let root = [0xA5; 64];
        let first = CandidatePrivateRecipientKeysetV1::from_root_for_test(root, 4, 0).unwrap();
        let second = CandidatePrivateRecipientKeysetV1::from_root_for_test(root, 4, 0).unwrap();

        assert_eq!(first.recipient_commitment(), second.recipient_commitment());
        assert_eq!(
            first.public_descriptor().payment_address().address_id(),
            second.public_descriptor().payment_address().address_id()
        );
    }

    #[test]
    fn key_epoch_domain_separates_one_root() {
        let root = [0x5A; 64];
        let first = CandidatePrivateRecipientKeysetV1::from_root_for_test(root, 4, 0).unwrap();
        let second = CandidatePrivateRecipientKeysetV1::from_root_for_test(root, 5, 0).unwrap();

        assert_ne!(first.recipient_commitment(), second.recipient_commitment());
        assert_ne!(
            first.public_descriptor().payment_address().address_id(),
            second.public_descriptor().payment_address().address_id()
        );
    }
}
