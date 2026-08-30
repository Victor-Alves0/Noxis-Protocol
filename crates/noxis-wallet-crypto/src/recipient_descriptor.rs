//! Authenticated local pairing of an incoming address and a note recipient commitment.
//!
//! The descriptor prevents an address/commitment mix-up at the wallet boundary.
//! It is deliberately in-memory only: its signing transcript is canonical, but
//! no public descriptor wire format, trusted directory, key derivation proof or
//! spending API is selected here.

use std::fmt;

use noxis_poseidon2_privacy_reference::{
    Poseidon2P24PrivacyReference, Poseidon2P24PrivacyReferenceError,
};
use noxis_privacy_types::{PrivacyTypesError, RecipientCommitmentV2};
use rand_core::{OsRng, RngCore as _};
use zeroize::Zeroize;

use crate::{
    HybridIdentityKeypair, HybridIdentityPublicKey, HybridIdentitySignature, HybridPaymentAddress,
    HybridPaymentAddressEntry, HybridRecipientEnvelope, PaymentAddressError,
    RecipientEnvelopeContext, encode_payment_address,
};

/// Stable label inside the signed public recipient-descriptor transcript.
pub const CANDIDATE_RECIPIENT_DESCRIPTOR_DOMAIN: &[u8] =
    b"NOXIS/CANDIDATE-RECIPIENT-DESCRIPTOR/V1\0";

/// Local key material pairing one incoming `NXPA` address with one private
/// nullifier key and its `H_ADDR` recipient commitment.
pub struct CandidatePrivateRecipientKeysetV1 {
    payment_address: HybridPaymentAddressEntry,
    nullifier_key: [u8; 32],
    recipient_commitment: RecipientCommitmentV2,
    descriptor_identity: HybridIdentityKeypair,
}

/// Public, signed view of a candidate recipient keyset.
///
/// The signature authenticates this exact address/commitment pair to a caller
/// that already trusts the descriptor identity. It does not prove a
/// deterministic relationship between X25519/ML-KEM secret material and the
/// nullifier key.
#[derive(Clone)]
pub struct CandidatePrivateRecipientDescriptorV1 {
    payment_address: HybridPaymentAddress,
    recipient_commitment: RecipientCommitmentV2,
    descriptor_identity: HybridIdentityPublicKey,
    signature: HybridIdentitySignature,
}

impl CandidatePrivateRecipientKeysetV1 {
    /// Generates independent incoming, nullifier and descriptor-identity
    /// secrets, then derives the public `H_ADDR` recipient commitment.
    pub fn generate(key_epoch: u64) -> Result<Self, CandidatePrivateRecipientError> {
        let payment_address = HybridPaymentAddressEntry::generate(key_epoch);
        let mut nullifier_key = [0_u8; 32];
        OsRng.fill_bytes(&mut nullifier_key);
        let reference = Poseidon2P24PrivacyReference::load_candidate()?;
        let recipient_commitment =
            RecipientCommitmentV2::from_elements(reference.hash_addr(&nullifier_key)?)?;
        Ok(Self {
            payment_address,
            nullifier_key,
            recipient_commitment,
            descriptor_identity: HybridIdentityKeypair::generate(),
        })
    }

    /// The public receiving material that a sender may verify and use.
    pub fn public_descriptor(&self) -> CandidatePrivateRecipientDescriptorV1 {
        let payment_address = self.payment_address.address().clone();
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

    /// Decrypts only envelopes sent to this local incoming address.
    pub(crate) fn decrypt_incoming(
        &self,
        context: &RecipientEnvelopeContext,
        envelope: &HybridRecipientEnvelope,
    ) -> Result<Vec<u8>, PaymentAddressError> {
        self.payment_address.decrypt_incoming(context, envelope)
    }
}

impl Drop for CandidatePrivateRecipientKeysetV1 {
    fn drop(&mut self) {
        self.nullifier_key.zeroize();
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
}
