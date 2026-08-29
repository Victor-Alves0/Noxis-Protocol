//! Experimental, local-only implementation pieces for the Noxis hybrid wallet
//! profile.
//!
//! This crate deliberately does **not** authorize a production wallet. It has
//! no keystore, seed format, wire encoding, transaction authorization, note
//! encryption, network transport, or proof generation. It exists to keep the
//! concrete post-quantum primitive integration separate from the protocol's
//! cryptographic contracts and to make its failures testable.
//!
//! The selected primitives are Ed25519 + ML-DSA-65 for identity, and X25519 +
//! ML-KEM-768 for recipient key material. The hybrid recipient-envelope
//! combiner remains unimplemented until its message format, KDF and AEAD are
//! specified and reviewed; the TLS combiner is not reused outside TLS.

use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as _, SigningKey as Ed25519SigningKey,
    VerifyingKey as Ed25519VerifyingKey,
};
use ml_dsa::{
    Generate as _, Keypair as _, MlDsa65, Signature as MlDsaSignature, Signer as _,
    SigningKey as MlDsaSigningKey, Verifier as _, VerifyingKey as MlDsaVerifyingKey,
};
use ml_kem::{
    DecapsulationKey768, EncapsulationKey768, MlKem768,
    kem::{Decapsulate as _, Encapsulate as _, Kem as _},
};
use rand_core::OsRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

/// Stable label prepended to every identity message signed by this crate.
pub const IDENTITY_SIGNING_DOMAIN: &[u8] = b"NOXIS/IDENTITY-SIGN/V1\0";

/// The public half of a hybrid identity. Verification accepts only a complete
/// Ed25519 and ML-DSA-65 signature pair over the same domain-bound message.
#[derive(Clone)]
pub struct HybridIdentityPublicKey {
    ed25519: Ed25519VerifyingKey,
    ml_dsa_65: MlDsaVerifyingKey<MlDsa65>,
}

/// A pair of signatures. Neither component is a valid Noxis identity
/// signature by itself.
#[derive(Clone)]
pub struct HybridIdentitySignature {
    ed25519: Ed25519Signature,
    ml_dsa_65: MlDsaSignature<MlDsa65>,
}

/// Local-only hybrid identity key material. It intentionally provides neither
/// serialization nor byte extraction; a future keystore owns that boundary.
pub struct HybridIdentityKeypair {
    ed25519: Ed25519SigningKey,
    ml_dsa_65: MlDsaSigningKey<MlDsa65>,
}

impl HybridIdentityKeypair {
    /// Generates independent classical and post-quantum signing keys.
    pub fn generate() -> Self {
        Self {
            ed25519: Ed25519SigningKey::generate(&mut OsRng),
            ml_dsa_65: MlDsaSigningKey::<MlDsa65>::generate(),
        }
    }

    pub fn public_key(&self) -> HybridIdentityPublicKey {
        HybridIdentityPublicKey {
            ed25519: self.ed25519.verifying_key(),
            ml_dsa_65: self.ml_dsa_65.verifying_key(),
        }
    }

    /// Signs one explicit application payload with both algorithms.
    pub fn sign(&self, payload: &[u8]) -> HybridIdentitySignature {
        let message = identity_message(payload);
        HybridIdentitySignature {
            ed25519: self.ed25519.sign(&message),
            ml_dsa_65: self.ml_dsa_65.sign(&message),
        }
    }
}

impl HybridIdentityPublicKey {
    /// Verifies both components. A malformed, missing, or invalid component
    /// fails the entire hybrid signature.
    pub fn verify(&self, payload: &[u8], signature: &HybridIdentitySignature) -> bool {
        let message = identity_message(payload);
        self.ed25519
            .verify_strict(&message, &signature.ed25519)
            .is_ok()
            && self
                .ml_dsa_65
                .verify(&message, &signature.ml_dsa_65)
                .is_ok()
    }
}

/// Independent recipient key material for the future X25519 + ML-KEM-768
/// envelope. The two secrets are intentionally distinct from identity keys.
///
/// No shared-secret combiner is exposed here: designing one without its
/// canonical envelope and associated data would create an unsafe protocol.
pub struct HybridRecipientKeypair {
    x25519_secret: X25519StaticSecret,
    x25519_public: X25519PublicKey,
    ml_kem_768_secret: DecapsulationKey768,
    ml_kem_768_public: EncapsulationKey768,
}

/// ML-KEM-768 ciphertext held until a future Noxis recipient envelope gives it
/// a canonical wire encoding and authenticated context.
pub struct MlKem768Ciphertext(ml_kem::Ciphertext<MlKem768>);

/// A local ML-KEM-768 shared secret. It has no byte-extraction API so callers
/// cannot accidentally persist or log it before the envelope KDF is defined.
#[allow(
    dead_code,
    reason = "the future reviewed envelope KDF will consume this secret; extraction is deliberately unavailable"
)]
pub struct MlKem768SharedSecret(ml_kem::SharedKey);

impl HybridRecipientKeypair {
    /// Generates independent X25519 and ML-KEM-768 recipient keys.
    pub fn generate() -> Self {
        let x25519_secret = X25519StaticSecret::random_from_rng(OsRng);
        let x25519_public = X25519PublicKey::from(&x25519_secret);
        let (ml_kem_768_secret, ml_kem_768_public) = MlKem768::generate_keypair();
        Self {
            x25519_secret,
            x25519_public,
            ml_kem_768_secret,
            ml_kem_768_public,
        }
    }

    /// The classical recipient public key. The future envelope will publish it
    /// alongside the ML-KEM public key under one profile and key epoch.
    pub fn x25519_public_key(&self) -> [u8; 32] {
        self.x25519_public.to_bytes()
    }

    /// Performs the ML-KEM-768 half of the future hybrid envelope. This is
    /// intentionally not a complete Noxis envelope: no X25519 combination,
    /// KDF, authenticated data, or payload encryption exists yet.
    pub fn encapsulate_ml_kem_768(&self) -> (MlKem768Ciphertext, MlKem768SharedSecret) {
        let (ciphertext, shared_secret) = self.ml_kem_768_public.encapsulate();
        (
            MlKem768Ciphertext(ciphertext),
            MlKem768SharedSecret(shared_secret),
        )
    }

    /// Recovers the ML-KEM-768 half-secret generated by
    /// [`Self::encapsulate_ml_kem_768`].
    pub fn decapsulate_ml_kem_768(&self, ciphertext: &MlKem768Ciphertext) -> MlKem768SharedSecret {
        MlKem768SharedSecret(self.ml_kem_768_secret.decapsulate(&ciphertext.0))
    }
}

fn identity_message(payload: &[u8]) -> Vec<u8> {
    let payload_length = u32::try_from(payload.len()).expect("identity payload length exceeds u32");
    let mut message = Vec::with_capacity(IDENTITY_SIGNING_DOMAIN.len() + 4 + payload.len());
    message.extend_from_slice(IDENTITY_SIGNING_DOMAIN);
    message.extend_from_slice(&payload_length.to_be_bytes());
    message.extend_from_slice(payload);
    message
}

impl Drop for HybridRecipientKeypair {
    fn drop(&mut self) {
        // The external primitive key types own their own secret cleanup where
        // available. The X25519 static secret is local and is erased here.
        self.x25519_secret.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_hybrid_identity_requires_both_signatures() {
        let identity = HybridIdentityKeypair::generate();
        let public_key = identity.public_key();
        let payload = b"canonical application payload";
        let signature = identity.sign(payload);

        assert!(public_key.verify(payload, &signature));
        assert!(!public_key.verify(b"different application payload", &signature));
    }

    #[test]
    fn recipient_key_material_performs_real_ml_kem_768_key_establishment() {
        let recipient = HybridRecipientKeypair::generate();
        let (ciphertext, sender_secret) = recipient.encapsulate_ml_kem_768();
        let receiver_secret = recipient.decapsulate_ml_kem_768(&ciphertext);

        assert_eq!(sender_secret.0, receiver_secret.0);
        assert_ne!(recipient.x25519_public_key(), [0; 32]);
    }
}
