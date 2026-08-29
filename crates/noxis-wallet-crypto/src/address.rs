//! Diversified hybrid payment-address candidate.
//!
//! An address owns a fresh X25519 + ML-KEM-768 receiving key set instead of
//! reusing another address's recipient keys. This gives a wallet a concrete
//! unit to rotate and scan, but it is not yet a complete stealth-address
//! protocol: canonical address encoding, on-chain output binding, viewing-key
//! export, and STARK constraints are deliberately separate future work.

use std::fmt;

use rand_core::{OsRng, RngCore as _};
use sha2::{Digest as _, Sha256};

use crate::{
    HYBRID_WALLET_PROFILE_ID, HybridRecipientEnvelope, HybridRecipientKeypair,
    HybridRecipientPublicKey, RecipientEnvelopeContext, RecipientEnvelopeError,
};

const PAYMENT_ADDRESS_DOMAIN: &[u8] = b"NOXIS/PAYMENT-ADDRESS/V1\0";
const DIVERSIFIER_LENGTH: usize = 16;

/// Public random value distinguishing independent payment addresses belonging
/// to the same wallet. It is not a secret and is not derived from a spend key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PaymentDiversifier([u8; DIVERSIFIER_LENGTH]);

impl PaymentDiversifier {
    /// Generates a new public diversifier from the operating-system CSPRNG.
    pub fn random() -> Self {
        let mut bytes = [0; DIVERSIFIER_LENGTH];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub const fn from_bytes(bytes: [u8; DIVERSIFIER_LENGTH]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(self) -> [u8; DIVERSIFIER_LENGTH] {
        self.0
    }
}

/// Public address material safe to hand to a sender. It has no spend secret;
/// it only permits creation of encrypted incoming envelopes.
#[derive(Clone)]
pub struct HybridPaymentAddress {
    diversifier: PaymentDiversifier,
    key_epoch: u64,
    recipient: HybridRecipientPublicKey,
    address_id: [u8; 32],
}

/// Local wallet entry that owns one diversified recipient key pair. At this
/// stage it functions as incoming viewing material only: spending remains the
/// responsibility of the future note/STARK wallet component.
pub struct HybridPaymentAddressEntry {
    address: HybridPaymentAddress,
    recipient_secret: HybridRecipientKeypair,
}

/// A payment-address operation was attempted with incompatible public context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PaymentAddressError {
    WrongKeyEpoch { address: u64, context: u64 },
    RecipientEnvelope(RecipientEnvelopeError),
}

impl fmt::Display for PaymentAddressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongKeyEpoch { address, context } => write!(
                formatter,
                "payment address key epoch {address} does not match envelope context epoch {context}"
            ),
            Self::RecipientEnvelope(error) => {
                write!(formatter, "recipient envelope failed: {error}")
            }
        }
    }
}

impl std::error::Error for PaymentAddressError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RecipientEnvelope(error) => Some(error),
            _ => None,
        }
    }
}

impl From<RecipientEnvelopeError> for PaymentAddressError {
    fn from(error: RecipientEnvelopeError) -> Self {
        Self::RecipientEnvelope(error)
    }
}

impl HybridPaymentAddressEntry {
    /// Generates a fresh diversified payment address and independent receiving
    /// keys. It deliberately does not derive child keys from a wallet seed;
    /// seed derivation needs a reviewed keystore specification first.
    pub fn generate(key_epoch: u64) -> Self {
        Self::with_diversifier(PaymentDiversifier::random(), key_epoch)
    }

    /// Same as [`Self::generate`] with caller-selected public diversifier,
    /// useful for deterministic test vectors and imported address records.
    pub fn with_diversifier(diversifier: PaymentDiversifier, key_epoch: u64) -> Self {
        let recipient_secret = HybridRecipientKeypair::generate();
        let recipient = recipient_secret.public_key();
        let address = HybridPaymentAddress::new(diversifier, key_epoch, recipient);
        Self {
            address,
            recipient_secret,
        }
    }

    pub const fn address(&self) -> &HybridPaymentAddress {
        &self.address
    }

    /// Decrypts an incoming envelope only for this address and exact key epoch.
    /// A future wallet scanner will call this after its canonical decoder has
    /// applied size limits and selected the correct candidate address.
    pub fn decrypt_incoming(
        &self,
        context: &RecipientEnvelopeContext,
        envelope: &HybridRecipientEnvelope,
    ) -> Result<Vec<u8>, PaymentAddressError> {
        self.ensure_epoch(context)?;
        self.recipient_secret
            .decrypt_envelope(context, envelope)
            .map_err(Into::into)
    }

    fn ensure_epoch(&self, context: &RecipientEnvelopeContext) -> Result<(), PaymentAddressError> {
        if self.address.key_epoch != context.key_epoch() {
            return Err(PaymentAddressError::WrongKeyEpoch {
                address: self.address.key_epoch,
                context: context.key_epoch(),
            });
        }
        Ok(())
    }
}

impl HybridPaymentAddress {
    fn new(
        diversifier: PaymentDiversifier,
        key_epoch: u64,
        recipient: HybridRecipientPublicKey,
    ) -> Self {
        let address_id = payment_address_id(diversifier, key_epoch, &recipient);
        Self {
            diversifier,
            key_epoch,
            recipient,
            address_id,
        }
    }

    pub const fn diversifier(&self) -> PaymentDiversifier {
        self.diversifier
    }

    pub const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    /// Stable public identifier of this complete diversified address.
    pub const fn address_id(&self) -> [u8; 32] {
        self.address_id
    }

    /// Encrypts an incoming note payload using only the public address. The
    /// output is rejected if the address and chain context disagree on epoch.
    pub fn encrypt_incoming(
        &self,
        context: &RecipientEnvelopeContext,
        payload: &[u8],
    ) -> Result<HybridRecipientEnvelope, PaymentAddressError> {
        if self.key_epoch != context.key_epoch() {
            return Err(PaymentAddressError::WrongKeyEpoch {
                address: self.key_epoch,
                context: context.key_epoch(),
            });
        }
        self.recipient
            .encrypt_envelope(context, payload)
            .map_err(Into::into)
    }
}

fn payment_address_id(
    diversifier: PaymentDiversifier,
    key_epoch: u64,
    recipient: &HybridRecipientPublicKey,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(PAYMENT_ADDRESS_DOMAIN);
    hash.update(HYBRID_WALLET_PROFILE_ID);
    hash.update(diversifier.as_bytes());
    hash.update(key_epoch.to_be_bytes());
    hash.update(recipient.keyset_id(key_epoch));
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diversified_addresses_use_independent_public_receiving_keys() {
        let first = HybridPaymentAddressEntry::with_diversifier(
            PaymentDiversifier::from_bytes([1; DIVERSIFIER_LENGTH]),
            3,
        );
        let second = HybridPaymentAddressEntry::with_diversifier(
            PaymentDiversifier::from_bytes([2; DIVERSIFIER_LENGTH]),
            3,
        );

        assert_ne!(first.address().address_id(), second.address().address_id());
        assert_ne!(
            first.address().recipient.x25519_public_key(),
            second.address().recipient.x25519_public_key()
        );
    }

    #[test]
    fn sender_uses_only_public_address_and_only_owner_can_scan_note() {
        let owner = HybridPaymentAddressEntry::generate(5);
        let other = HybridPaymentAddressEntry::generate(5);
        let context = RecipientEnvelopeContext::new(b"noxis-local-research", 5).unwrap();
        let envelope = owner
            .address()
            .encrypt_incoming(&context, b"candidate private note")
            .unwrap();

        assert_eq!(
            owner.decrypt_incoming(&context, &envelope).unwrap(),
            b"candidate private note"
        );
        assert_eq!(
            other.decrypt_incoming(&context, &envelope),
            Err(PaymentAddressError::RecipientEnvelope(
                RecipientEnvelopeError::WrongRecipientKeySet
            ))
        );
    }

    #[test]
    fn address_rejects_another_key_epoch_before_encryption() {
        let address = HybridPaymentAddressEntry::generate(5);
        let wrong_context = RecipientEnvelopeContext::new(b"noxis-local-research", 6).unwrap();

        assert!(matches!(
            address
                .address()
                .encrypt_incoming(&wrong_context, b"candidate private note"),
            Err(PaymentAddressError::WrongKeyEpoch {
                address: 5,
                context: 6,
            })
        ));
    }
}
