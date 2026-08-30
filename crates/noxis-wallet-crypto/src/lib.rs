//! Experimental, local-only implementation pieces for the Noxis hybrid wallet
//! profile.
//!
//! This crate deliberately does **not** authorize a production wallet. It has
//! no keystore, seed format, wire encoding, transaction authorization, network
//! transport, or proof generation. It exists to keep the
//! concrete post-quantum primitive integration separate from the protocol's
//! cryptographic contracts and to make its failures testable.
//!
//! The selected primitives are Ed25519 + ML-DSA-65 for identity, and X25519 +
//! ML-KEM-768 for recipient key material. The experimental recipient envelope
//! has its own canonical transcript and is never a reuse of a TLS combiner.

use aead::{Aead as _, KeyInit as _, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as _, SigningKey as Ed25519SigningKey,
    VerifyingKey as Ed25519VerifyingKey,
};
use hkdf::Hkdf;
use ml_dsa::{
    Generate as _, Keypair as _, MlDsa65, Signature as MlDsaSignature, Signer as _,
    SigningKey as MlDsaSigningKey, Verifier as _, VerifyingKey as MlDsaVerifyingKey,
};
use ml_kem::{
    DecapsulationKey768, EncapsulationKey768, KeyExport as _, MlKem768, Seed as MlKemSeed,
    kem::{Decapsulate as _, Encapsulate as _, Kem as _},
};
use rand_core::{OsRng, RngCore as _};
use sha2::{Digest as _, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

mod address;
mod address_book;
mod ciphertext_digest;
mod private_note;
mod recipient_descriptor;
mod wire;

pub use address::{
    HybridPaymentAddress, HybridPaymentAddressEntry, PaymentAddressError, PaymentDiversifier,
};
pub use address_book::{
    AddressBookStoreOutcome, PUBLIC_ADDRESS_BOOK_LOCK_FILE_NAME, PublicAddressBook,
    PublicAddressBookError,
};
pub use ciphertext_digest::{
    CANDIDATE_CIPHERTEXT_DIGEST_FRAME_VERSION, CandidateCiphertextDigestError,
    CandidatePrivateOutputSlotV1, candidate_ciphertext_digest_v1,
};
pub use private_note::{
    CANDIDATE_PRIVATE_NOTE_PREIMAGE_LENGTH, CandidatePrivateNoteEnvelopeV1,
    CandidatePrivateNoteError, ReceivedCandidatePrivateNoteV1, decrypt_candidate_private_note,
    decrypt_candidate_private_note_for_incoming_view_key,
    decrypt_candidate_private_note_for_recipient, encrypt_candidate_private_note,
    encrypt_candidate_private_note_to_descriptor,
};
pub use recipient_descriptor::{
    CANDIDATE_RECIPIENT_DESCRIPTOR_DOMAIN, CandidateIncomingViewKeyV1,
    CandidatePrivateRecipientDescriptorV1, CandidatePrivateRecipientError,
    CandidatePrivateRecipientKeysetV1,
};
pub use wire::{
    HYBRID_RECIPIENT_ENVELOPE_MAGIC, PAYMENT_ADDRESS_MAGIC, PaymentAddressCodecError,
    decode_hybrid_recipient_envelope, decode_payment_address, encode_hybrid_recipient_envelope,
    encode_payment_address,
};

/// Stable label prepended to every identity message signed by this crate.
pub const IDENTITY_SIGNING_DOMAIN: &[u8] = b"NOXIS/IDENTITY-SIGN/V1\0";

/// Fixed identifier of the only hybrid wallet profile implemented here.
pub const HYBRID_WALLET_PROFILE_ID: &[u8] = b"noxis-hybrid-v1";

const RECIPIENT_ENVELOPE_DOMAIN: &[u8] = b"NOXIS/RECIPIENT-ENVELOPE/V1\0";
const RECIPIENT_ENVELOPE_KDF_INFO: &[u8] = b"NOXIS/RECIPIENT-ENVELOPE/KEY/V1\0";
pub(crate) const ML_KEM_768_PUBLIC_KEY_LENGTH: usize = 1184;
pub(crate) const ML_KEM_768_CIPHERTEXT_LENGTH: usize = 1088;
pub(crate) const XCHACHA20_NONCE_LENGTH: usize = 24;

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

/// Public half of a recipient key pair. A sender needs only this value to
/// create an envelope; private recipient material never leaves the wallet.
#[derive(Clone)]
pub struct HybridRecipientPublicKey {
    x25519_public: X25519PublicKey,
    ml_kem_768_public: EncapsulationKey768,
}

/// Public metadata that must be known by both sides of a recipient envelope.
/// The chain is never negotiated from an envelope: the caller chooses it from
/// its configured network before encryption or decryption.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipientEnvelopeContext {
    chain_id: Vec<u8>,
    key_epoch: u64,
}

/// A single experimental recipient envelope. It is an in-memory object only;
/// canonical network serialization belongs to a later codec module.
pub struct HybridRecipientEnvelope {
    pub(crate) key_epoch: u64,
    pub(crate) keyset_id: [u8; 32],
    pub(crate) ephemeral_x25519_public_key: [u8; 32],
    pub(crate) ml_kem_768_ciphertext: [u8; ML_KEM_768_CIPHERTEXT_LENGTH],
    pub(crate) nonce: [u8; XCHACHA20_NONCE_LENGTH],
    pub(crate) encrypted_payload: Vec<u8>,
}

/// An envelope was malformed, addressed to another recipient context, or
/// failed authenticated decryption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecipientEnvelopeError {
    EmptyChainId,
    ChainIdTooLong,
    AllZeroX25519SharedSecret,
    WrongKeyEpoch,
    WrongRecipientKeySet,
    AuthenticationFailed,
}

impl std::fmt::Display for RecipientEnvelopeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::EmptyChainId => "recipient envelope chain ID must not be empty",
            Self::ChainIdTooLong => "recipient envelope chain ID exceeds the canonical limit",
            Self::AllZeroX25519SharedSecret => {
                "X25519 recipient exchange produced the prohibited all-zero secret"
            }
            Self::WrongKeyEpoch => "recipient envelope belongs to a different key epoch",
            Self::WrongRecipientKeySet => {
                "recipient envelope belongs to a different recipient key set"
            }
            Self::AuthenticationFailed => "recipient envelope authentication failed",
        })
    }
}

impl std::error::Error for RecipientEnvelopeError {}

impl RecipientEnvelopeContext {
    /// Creates a network-bound envelope context. A u16 length field is used in
    /// the exact authenticated transcript, so overly long values are rejected.
    pub fn new(chain_id: &[u8], key_epoch: u64) -> Result<Self, RecipientEnvelopeError> {
        if chain_id.is_empty() {
            return Err(RecipientEnvelopeError::EmptyChainId);
        }
        if chain_id.len() > usize::from(u16::MAX) {
            return Err(RecipientEnvelopeError::ChainIdTooLong);
        }
        Ok(Self {
            chain_id: chain_id.to_vec(),
            key_epoch,
        })
    }

    pub const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }
}

/// ML-KEM-768 ciphertext held until a later codec gives the envelope a
/// canonical wire encoding.
pub struct MlKem768Ciphertext(ml_kem::Ciphertext<MlKem768>);

/// A local ML-KEM-768 shared secret. It has no byte-extraction API so callers
/// cannot accidentally persist or log it outside the envelope implementation.
#[allow(
    dead_code,
    reason = "the envelope consumes this secret internally; extraction is deliberately unavailable"
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

    /// Constructs receiving material from independently domain-separated
    /// secret inputs owned by the wallet derivation layer. This stays crate
    /// private: callers must never select or reuse these inputs directly.
    pub(crate) fn from_derived_seeds(
        mut x25519_seed: [u8; 32],
        mut ml_kem_768_seed: [u8; 64],
    ) -> Self {
        let x25519_secret = X25519StaticSecret::from(x25519_seed);
        let x25519_public = X25519PublicKey::from(&x25519_secret);
        let ml_kem_768_secret = DecapsulationKey768::from_seed(MlKemSeed::from(ml_kem_768_seed));
        let ml_kem_768_public = ml_kem_768_secret.encapsulation_key().clone();
        x25519_seed.zeroize();
        ml_kem_768_seed.zeroize();
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

    /// Returns the public receiving key set that may safely be shared with a
    /// sender. It remains distinct from this wallet's identity signing keys.
    pub fn public_key(&self) -> HybridRecipientPublicKey {
        HybridRecipientPublicKey {
            x25519_public: self.x25519_public,
            ml_kem_768_public: self.ml_kem_768_public.clone(),
        }
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

    /// Encrypts a payload to this recipient using both halves of the hybrid
    /// profile. The resulting key is derived from *both* X25519 and ML-KEM
    /// shared secrets, bound to the canonical envelope header, then used only
    /// for this XChaCha20-Poly1305 operation.
    pub fn encrypt_envelope(
        &self,
        context: &RecipientEnvelopeContext,
        payload: &[u8],
    ) -> Result<HybridRecipientEnvelope, RecipientEnvelopeError> {
        self.public_key().encrypt_envelope(context, payload)
    }

    /// Authenticates and decrypts a hybrid recipient envelope only when its
    /// key epoch and complete recipient key set match the local wallet.
    pub fn decrypt_envelope(
        &self,
        context: &RecipientEnvelopeContext,
        envelope: &HybridRecipientEnvelope,
    ) -> Result<Vec<u8>, RecipientEnvelopeError> {
        if envelope.key_epoch != context.key_epoch {
            return Err(RecipientEnvelopeError::WrongKeyEpoch);
        }
        let expected_keyset_id = self.keyset_id(context.key_epoch);
        if envelope.keyset_id != expected_keyset_id {
            return Err(RecipientEnvelopeError::WrongRecipientKeySet);
        }

        let ephemeral_public = X25519PublicKey::from(envelope.ephemeral_x25519_public_key);
        let x25519_shared_secret = self
            .x25519_secret
            .diffie_hellman(&ephemeral_public)
            .to_bytes();
        if is_all_zero(&x25519_shared_secret) {
            return Err(RecipientEnvelopeError::AllZeroX25519SharedSecret);
        }
        let ciphertext =
            ml_kem::Ciphertext::<MlKem768>::try_from(envelope.ml_kem_768_ciphertext.as_slice())
                .map_err(|_| RecipientEnvelopeError::AuthenticationFailed)?;
        let ml_kem_768_shared_secret = self.ml_kem_768_secret.decapsulate(&ciphertext);
        let header = self.envelope_header(
            context,
            expected_keyset_id,
            envelope.ephemeral_x25519_public_key,
            envelope.ml_kem_768_ciphertext,
            envelope.nonce,
        );
        decrypt_payload(
            &x25519_shared_secret,
            ml_kem_768_shared_secret.as_slice(),
            &header,
            &envelope.nonce,
            &envelope.encrypted_payload,
        )
    }

    fn keyset_id(&self, key_epoch: u64) -> [u8; 32] {
        recipient_keyset_id(&self.x25519_public, &self.ml_kem_768_public, key_epoch)
    }

    fn envelope_header(
        &self,
        context: &RecipientEnvelopeContext,
        keyset_id: [u8; 32],
        ephemeral_x25519_public_key: [u8; 32],
        ml_kem_768_ciphertext: [u8; ML_KEM_768_CIPHERTEXT_LENGTH],
        nonce: [u8; XCHACHA20_NONCE_LENGTH],
    ) -> Vec<u8> {
        recipient_envelope_header(
            context,
            keyset_id,
            &self.x25519_public,
            &self.ml_kem_768_public,
            ephemeral_x25519_public_key,
            ml_kem_768_ciphertext,
            nonce,
        )
    }
}

impl HybridRecipientPublicKey {
    /// The classical recipient public key. It is exposed only as part of the
    /// complete hybrid public key set.
    pub fn x25519_public_key(&self) -> [u8; 32] {
        self.x25519_public.to_bytes()
    }

    /// Identifies this complete public recipient key set at one wallet key
    /// epoch. It is safe to publish, unlike a private receiving key.
    pub fn keyset_id(&self, key_epoch: u64) -> [u8; 32] {
        recipient_keyset_id(&self.x25519_public, &self.ml_kem_768_public, key_epoch)
    }

    pub(crate) fn from_wire_components(
        x25519_public: [u8; 32],
        ml_kem_768_public: [u8; ML_KEM_768_PUBLIC_KEY_LENGTH],
    ) -> Result<Self, ()> {
        let encoded_key =
            ml_kem::Key::<EncapsulationKey768>::try_from(ml_kem_768_public.as_slice())
                .map_err(|_| ())?;
        let ml_kem_768_public = EncapsulationKey768::new(&encoded_key).map_err(|_| ())?;
        Ok(Self {
            x25519_public: X25519PublicKey::from(x25519_public),
            ml_kem_768_public,
        })
    }

    /// Encrypts a payload using only the recipient's public X25519 and
    /// ML-KEM-768 key material. The sender never needs recipient secrets.
    pub fn encrypt_envelope(
        &self,
        context: &RecipientEnvelopeContext,
        payload: &[u8],
    ) -> Result<HybridRecipientEnvelope, RecipientEnvelopeError> {
        let ephemeral_secret = X25519StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
        let x25519_shared_secret = ephemeral_secret
            .diffie_hellman(&self.x25519_public)
            .to_bytes();
        if is_all_zero(&x25519_shared_secret) {
            return Err(RecipientEnvelopeError::AllZeroX25519SharedSecret);
        }

        let (ml_kem_768_ciphertext, ml_kem_768_shared_secret) =
            self.ml_kem_768_public.encapsulate();
        let mut ciphertext_bytes = [0; ML_KEM_768_CIPHERTEXT_LENGTH];
        ciphertext_bytes.copy_from_slice(ml_kem_768_ciphertext.as_slice());

        let mut nonce = [0; XCHACHA20_NONCE_LENGTH];
        OsRng.fill_bytes(&mut nonce);
        let keyset_id = recipient_keyset_id(
            &self.x25519_public,
            &self.ml_kem_768_public,
            context.key_epoch,
        );
        let header = recipient_envelope_header(
            context,
            keyset_id,
            &self.x25519_public,
            &self.ml_kem_768_public,
            ephemeral_public.to_bytes(),
            ciphertext_bytes,
            nonce,
        );
        let encrypted_payload = encrypt_payload(
            &x25519_shared_secret,
            ml_kem_768_shared_secret.as_slice(),
            &header,
            &nonce,
            payload,
        )?;

        Ok(HybridRecipientEnvelope {
            key_epoch: context.key_epoch,
            keyset_id,
            ephemeral_x25519_public_key: ephemeral_public.to_bytes(),
            ml_kem_768_ciphertext: ciphertext_bytes,
            nonce,
            encrypted_payload,
        })
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

fn recipient_keyset_id(
    x25519_public: &X25519PublicKey,
    ml_kem_768_public: &EncapsulationKey768,
    key_epoch: u64,
) -> [u8; 32] {
    let mut public_key_bytes = [0; ML_KEM_768_PUBLIC_KEY_LENGTH];
    public_key_bytes.copy_from_slice(ml_kem_768_public.to_bytes().as_slice());
    let mut hash = Sha256::new();
    hash.update(b"NOXIS/RECIPIENT-KEYSET/V1\0");
    hash.update(HYBRID_WALLET_PROFILE_ID);
    hash.update(key_epoch.to_be_bytes());
    hash.update(x25519_public.to_bytes());
    hash.update(public_key_bytes);
    hash.finalize().into()
}

fn recipient_envelope_header(
    context: &RecipientEnvelopeContext,
    keyset_id: [u8; 32],
    recipient_x25519_public: &X25519PublicKey,
    recipient_ml_kem_768_public: &EncapsulationKey768,
    ephemeral_x25519_public_key: [u8; 32],
    ml_kem_768_ciphertext: [u8; ML_KEM_768_CIPHERTEXT_LENGTH],
    nonce: [u8; XCHACHA20_NONCE_LENGTH],
) -> Vec<u8> {
    let mut recipient_ml_kem_public_key = [0; ML_KEM_768_PUBLIC_KEY_LENGTH];
    recipient_ml_kem_public_key.copy_from_slice(recipient_ml_kem_768_public.to_bytes().as_slice());
    let mut header = Vec::with_capacity(
        RECIPIENT_ENVELOPE_DOMAIN.len()
            + 1
            + HYBRID_WALLET_PROFILE_ID.len()
            + 2
            + context.chain_id.len()
            + 8
            + 32
            + 32
            + ML_KEM_768_PUBLIC_KEY_LENGTH
            + 32
            + ML_KEM_768_CIPHERTEXT_LENGTH
            + XCHACHA20_NONCE_LENGTH,
    );
    header.extend_from_slice(RECIPIENT_ENVELOPE_DOMAIN);
    header.push(HYBRID_WALLET_PROFILE_ID.len() as u8);
    header.extend_from_slice(HYBRID_WALLET_PROFILE_ID);
    header.extend_from_slice(&(context.chain_id.len() as u16).to_be_bytes());
    header.extend_from_slice(&context.chain_id);
    header.extend_from_slice(&context.key_epoch.to_be_bytes());
    header.extend_from_slice(&keyset_id);
    header.extend_from_slice(&recipient_x25519_public.to_bytes());
    header.extend_from_slice(&recipient_ml_kem_public_key);
    header.extend_from_slice(&ephemeral_x25519_public_key);
    header.extend_from_slice(&ml_kem_768_ciphertext);
    header.extend_from_slice(&nonce);
    header
}

fn encrypt_payload(
    x25519_shared_secret: &[u8; 32],
    ml_kem_768_shared_secret: &[u8],
    header: &[u8],
    nonce: &[u8; XCHACHA20_NONCE_LENGTH],
    payload: &[u8],
) -> Result<Vec<u8>, RecipientEnvelopeError> {
    let mut key = derive_envelope_key(x25519_shared_secret, ml_kem_768_shared_secret, header);
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| RecipientEnvelopeError::AuthenticationFailed)?;
    let result = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: payload,
                aad: header,
            },
        )
        .map_err(|_| RecipientEnvelopeError::AuthenticationFailed);
    key.zeroize();
    result
}

fn decrypt_payload(
    x25519_shared_secret: &[u8; 32],
    ml_kem_768_shared_secret: &[u8],
    header: &[u8],
    nonce: &[u8; XCHACHA20_NONCE_LENGTH],
    encrypted_payload: &[u8],
) -> Result<Vec<u8>, RecipientEnvelopeError> {
    let mut key = derive_envelope_key(x25519_shared_secret, ml_kem_768_shared_secret, header);
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| RecipientEnvelopeError::AuthenticationFailed)?;
    let result = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: encrypted_payload,
                aad: header,
            },
        )
        .map_err(|_| RecipientEnvelopeError::AuthenticationFailed);
    key.zeroize();
    result
}

fn derive_envelope_key(
    x25519_shared_secret: &[u8; 32],
    ml_kem_768_shared_secret: &[u8],
    header: &[u8],
) -> [u8; 32] {
    let mut input_key_material = [0; 64];
    input_key_material[..32].copy_from_slice(x25519_shared_secret);
    input_key_material[32..].copy_from_slice(ml_kem_768_shared_secret);
    let salt: [u8; 32] = Sha256::digest(header).into();
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &input_key_material);
    let mut key = [0; 32];
    hkdf.expand(RECIPIENT_ENVELOPE_KDF_INFO, &mut key)
        .expect("fixed 32-byte output is valid for SHA-256 HKDF");
    input_key_material.zeroize();
    key
}

const fn is_all_zero(bytes: &[u8; 32]) -> bool {
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

    #[test]
    fn hybrid_envelope_requires_both_secrets_and_authenticated_context() {
        let recipient = HybridRecipientKeypair::generate();
        let context = RecipientEnvelopeContext::new(b"noxis-local-research", 7).unwrap();
        let sender_view = recipient.public_key();
        let envelope = sender_view
            .encrypt_envelope(&context, b"private note payload")
            .unwrap();

        assert_eq!(
            recipient.decrypt_envelope(&context, &envelope).unwrap(),
            b"private note payload"
        );
        let wrong_context = RecipientEnvelopeContext::new(b"noxis-local-research", 8).unwrap();
        assert_eq!(
            recipient.decrypt_envelope(&wrong_context, &envelope),
            Err(RecipientEnvelopeError::WrongKeyEpoch)
        );
        let wrong_chain = RecipientEnvelopeContext::new(b"another-noxis-network", 7).unwrap();
        assert_eq!(
            recipient.decrypt_envelope(&wrong_chain, &envelope),
            Err(RecipientEnvelopeError::AuthenticationFailed)
        );

        let another_recipient = HybridRecipientKeypair::generate();
        assert_eq!(
            another_recipient.decrypt_envelope(&context, &envelope),
            Err(RecipientEnvelopeError::WrongRecipientKeySet)
        );
    }

    #[test]
    fn hybrid_envelope_rejects_ciphertext_tampering() {
        let recipient = HybridRecipientKeypair::generate();
        let context = RecipientEnvelopeContext::new(b"noxis-local-research", 7).unwrap();
        let mut envelope = recipient
            .public_key()
            .encrypt_envelope(&context, b"private note payload")
            .unwrap();
        let last = envelope.encrypted_payload.len() - 1;
        envelope.encrypted_payload[last] ^= 1;

        assert_eq!(
            recipient.decrypt_envelope(&context, &envelope),
            Err(RecipientEnvelopeError::AuthenticationFailed)
        );
    }
}
