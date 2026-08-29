//! Canonical binary representations for diversified payment addresses and
//! hybrid recipient envelopes.
//!
//! This module deliberately owns no networking or transaction framing. It
//! makes the public address and encrypted envelope portable between processes,
//! while the outer private-transfer codec remains responsible for its own
//! arity and resource limits.

use std::fmt;

use ml_kem::KeyExport as _;

use crate::{
    HYBRID_WALLET_PROFILE_ID, HybridPaymentAddress, HybridRecipientEnvelope,
    HybridRecipientPublicKey, ML_KEM_768_CIPHERTEXT_LENGTH, ML_KEM_768_PUBLIC_KEY_LENGTH,
    PaymentDiversifier, XCHACHA20_NONCE_LENGTH,
};

/// Fixed prefix for a public diversified Noxis payment address.
pub const PAYMENT_ADDRESS_MAGIC: [u8; 4] = *b"NXPA";
/// Fixed prefix for a hybrid recipient envelope.
pub const HYBRID_RECIPIENT_ENVELOPE_MAGIC: [u8; 4] = *b"NXRE";

const PAYMENT_ADDRESS_FORMAT_VERSION: u16 = 1;
const HYBRID_RECIPIENT_ENVELOPE_FORMAT_VERSION: u16 = 1;
const DIVERSIFIER_LENGTH: usize = 16;
const ADDRESS_ID_LENGTH: usize = 32;
const KEYSET_ID_LENGTH: usize = 32;
const X25519_PUBLIC_KEY_LENGTH: usize = 32;
const MIN_ENCRYPTED_PAYLOAD_BYTES: usize = 16;
/// Keeps one envelope below the existing 4 KiB private-transfer packet bound.
pub const MAX_ENCRYPTED_PAYLOAD_BYTES: usize = 2 * 1024;

/// A payment-address or recipient-envelope byte sequence was not canonical.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PaymentAddressCodecError {
    Truncated,
    TrailingBytes,
    InvalidPaymentAddressMagic,
    UnsupportedPaymentAddressVersion(u16),
    InvalidRecipientEnvelopeMagic,
    UnsupportedRecipientEnvelopeVersion(u16),
    UnsupportedCryptoProfile,
    InvalidMlKemPublicKey,
    AddressIdMismatch,
    InvalidEncryptedPayloadLength { actual: usize },
}

impl fmt::Display for PaymentAddressCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => formatter.write_str("payment-address encoding is truncated"),
            Self::TrailingBytes => {
                formatter.write_str("payment-address encoding has trailing bytes")
            }
            Self::InvalidPaymentAddressMagic => {
                formatter.write_str("payment-address encoding has an invalid magic")
            }
            Self::UnsupportedPaymentAddressVersion(version) => {
                write!(
                    formatter,
                    "unsupported payment-address format version {version}"
                )
            }
            Self::InvalidRecipientEnvelopeMagic => {
                formatter.write_str("recipient-envelope encoding has an invalid magic")
            }
            Self::UnsupportedRecipientEnvelopeVersion(version) => {
                write!(
                    formatter,
                    "unsupported recipient-envelope format version {version}"
                )
            }
            Self::UnsupportedCryptoProfile => {
                formatter.write_str("payment address uses an unsupported cryptographic profile")
            }
            Self::InvalidMlKemPublicKey => {
                formatter.write_str("payment address contains an invalid ML-KEM-768 public key")
            }
            Self::AddressIdMismatch => formatter
                .write_str("payment address identifier does not match its public components"),
            Self::InvalidEncryptedPayloadLength { actual } => write!(
                formatter,
                "encrypted recipient payload has invalid length {actual}; expected 16..={MAX_ENCRYPTED_PAYLOAD_BYTES} bytes"
            ),
        }
    }
}

impl std::error::Error for PaymentAddressCodecError {}

/// Encodes exactly one public diversified payment address.
pub fn encode_payment_address(address: &HybridPaymentAddress) -> Vec<u8> {
    let mut output = Vec::with_capacity(
        PAYMENT_ADDRESS_MAGIC.len()
            + 2
            + 1
            + HYBRID_WALLET_PROFILE_ID.len()
            + DIVERSIFIER_LENGTH
            + 8
            + X25519_PUBLIC_KEY_LENGTH
            + ML_KEM_768_PUBLIC_KEY_LENGTH
            + ADDRESS_ID_LENGTH,
    );
    output.extend_from_slice(&PAYMENT_ADDRESS_MAGIC);
    write_u16(&mut output, PAYMENT_ADDRESS_FORMAT_VERSION);
    write_profile(&mut output);
    output.extend_from_slice(&address.diversifier().as_bytes());
    write_u64(&mut output, address.key_epoch());
    output.extend_from_slice(&address.recipient().x25519_public_key());
    output.extend_from_slice(&address.recipient().ml_kem_768_public.to_bytes());
    output.extend_from_slice(&address.address_id());
    output
}

/// Decodes one exact public diversified payment address, revalidating ML-KEM
/// key material and recomputing the address identifier before returning it.
pub fn decode_payment_address(
    bytes: &[u8],
) -> Result<HybridPaymentAddress, PaymentAddressCodecError> {
    let mut reader = Reader::new(bytes);
    if reader.read_array::<4>()? != PAYMENT_ADDRESS_MAGIC {
        return Err(PaymentAddressCodecError::InvalidPaymentAddressMagic);
    }
    let version = reader.read_u16()?;
    if version != PAYMENT_ADDRESS_FORMAT_VERSION {
        return Err(PaymentAddressCodecError::UnsupportedPaymentAddressVersion(
            version,
        ));
    }
    reader.read_profile()?;
    let diversifier = PaymentDiversifier::from_bytes(reader.read_array::<DIVERSIFIER_LENGTH>()?);
    let key_epoch = reader.read_u64()?;
    let x25519_public = reader.read_array::<X25519_PUBLIC_KEY_LENGTH>()?;
    let ml_kem_768_public = reader.read_array::<ML_KEM_768_PUBLIC_KEY_LENGTH>()?;
    let claimed_address_id = reader.read_array::<ADDRESS_ID_LENGTH>()?;
    reader.finish()?;

    let recipient =
        HybridRecipientPublicKey::from_wire_components(x25519_public, ml_kem_768_public)
            .map_err(|_| PaymentAddressCodecError::InvalidMlKemPublicKey)?;
    let address = HybridPaymentAddress::new(diversifier, key_epoch, recipient);
    if address.address_id() != claimed_address_id {
        return Err(PaymentAddressCodecError::AddressIdMismatch);
    }
    Ok(address)
}

/// Encodes exactly one hybrid recipient envelope. The bytes are authenticated
/// by the envelope's inner AEAD when a wallet later decrypts them.
pub fn encode_hybrid_recipient_envelope(
    envelope: &HybridRecipientEnvelope,
) -> Result<Vec<u8>, PaymentAddressCodecError> {
    ensure_encrypted_payload_length(envelope.encrypted_payload.len())?;
    let mut output = Vec::with_capacity(
        HYBRID_RECIPIENT_ENVELOPE_MAGIC.len()
            + 2
            + 8
            + KEYSET_ID_LENGTH
            + X25519_PUBLIC_KEY_LENGTH
            + ML_KEM_768_CIPHERTEXT_LENGTH
            + XCHACHA20_NONCE_LENGTH
            + 4
            + envelope.encrypted_payload.len(),
    );
    output.extend_from_slice(&HYBRID_RECIPIENT_ENVELOPE_MAGIC);
    write_u16(&mut output, HYBRID_RECIPIENT_ENVELOPE_FORMAT_VERSION);
    write_u64(&mut output, envelope.key_epoch);
    output.extend_from_slice(&envelope.keyset_id);
    output.extend_from_slice(&envelope.ephemeral_x25519_public_key);
    output.extend_from_slice(&envelope.ml_kem_768_ciphertext);
    output.extend_from_slice(&envelope.nonce);
    write_u32(&mut output, envelope.encrypted_payload.len() as u32);
    output.extend_from_slice(&envelope.encrypted_payload);
    Ok(output)
}

/// Decodes one exact bounded hybrid recipient envelope. It cannot claim that
/// the envelope is authentic; that requires the recipient's private key.
pub fn decode_hybrid_recipient_envelope(
    bytes: &[u8],
) -> Result<HybridRecipientEnvelope, PaymentAddressCodecError> {
    let mut reader = Reader::new(bytes);
    if reader.read_array::<4>()? != HYBRID_RECIPIENT_ENVELOPE_MAGIC {
        return Err(PaymentAddressCodecError::InvalidRecipientEnvelopeMagic);
    }
    let version = reader.read_u16()?;
    if version != HYBRID_RECIPIENT_ENVELOPE_FORMAT_VERSION {
        return Err(PaymentAddressCodecError::UnsupportedRecipientEnvelopeVersion(version));
    }
    let key_epoch = reader.read_u64()?;
    let keyset_id = reader.read_array::<KEYSET_ID_LENGTH>()?;
    let ephemeral_x25519_public_key = reader.read_array::<X25519_PUBLIC_KEY_LENGTH>()?;
    let ml_kem_768_ciphertext = reader.read_array::<ML_KEM_768_CIPHERTEXT_LENGTH>()?;
    let nonce = reader.read_array::<XCHACHA20_NONCE_LENGTH>()?;
    let encrypted_payload_length = reader.read_u32()? as usize;
    ensure_encrypted_payload_length(encrypted_payload_length)?;
    let encrypted_payload = reader.read_exact(encrypted_payload_length)?.to_vec();
    reader.finish()?;
    Ok(HybridRecipientEnvelope {
        key_epoch,
        keyset_id,
        ephemeral_x25519_public_key,
        ml_kem_768_ciphertext,
        nonce,
        encrypted_payload,
    })
}

fn ensure_encrypted_payload_length(length: usize) -> Result<(), PaymentAddressCodecError> {
    if !(MIN_ENCRYPTED_PAYLOAD_BYTES..=MAX_ENCRYPTED_PAYLOAD_BYTES).contains(&length) {
        return Err(PaymentAddressCodecError::InvalidEncryptedPayloadLength { actual: length });
    }
    Ok(())
}

fn write_profile(output: &mut Vec<u8>) {
    output.push(HYBRID_WALLET_PROFILE_ID.len() as u8);
    output.extend_from_slice(HYBRID_WALLET_PROFILE_ID);
}

fn write_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn write_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn write_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], PaymentAddressCodecError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(PaymentAddressCodecError::Truncated)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(PaymentAddressCodecError::Truncated)?;
        self.offset = end;
        Ok(bytes)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], PaymentAddressCodecError> {
        self.read_exact(N)?
            .try_into()
            .map_err(|_| PaymentAddressCodecError::Truncated)
    }

    fn read_u16(&mut self) -> Result<u16, PaymentAddressCodecError> {
        Ok(u16::from_be_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> Result<u32, PaymentAddressCodecError> {
        Ok(u32::from_be_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> Result<u64, PaymentAddressCodecError> {
        Ok(u64::from_be_bytes(self.read_array()?))
    }

    fn read_profile(&mut self) -> Result<(), PaymentAddressCodecError> {
        let length = usize::from(self.read_array::<1>()?[0]);
        if self.read_exact(length)? != HYBRID_WALLET_PROFILE_ID {
            return Err(PaymentAddressCodecError::UnsupportedCryptoProfile);
        }
        Ok(())
    }

    fn finish(self) -> Result<(), PaymentAddressCodecError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(PaymentAddressCodecError::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HybridPaymentAddressEntry, RecipientEnvelopeContext};

    #[test]
    fn payment_address_round_trips_and_rejects_tampering_or_trailing_bytes() {
        let entry = HybridPaymentAddressEntry::generate(11);
        let encoded = encode_payment_address(entry.address());
        let decoded = decode_payment_address(&encoded).unwrap();
        assert_eq!(decoded.address_id(), entry.address().address_id());
        assert_eq!(decoded.diversifier(), entry.address().diversifier());

        let mut tampered = encoded.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(matches!(
            decode_payment_address(&tampered),
            Err(PaymentAddressCodecError::AddressIdMismatch)
        ));
        let mut trailing = encoded;
        trailing.push(0);
        assert!(matches!(
            decode_payment_address(&trailing),
            Err(PaymentAddressCodecError::TrailingBytes)
        ));
    }

    #[test]
    fn portable_address_encrypts_and_owner_decrypts_portable_envelope() {
        let entry = HybridPaymentAddressEntry::generate(12);
        let address = decode_payment_address(&encode_payment_address(entry.address())).unwrap();
        let context = RecipientEnvelopeContext::new(b"noxis-local-research", 12).unwrap();
        let envelope = address
            .encrypt_incoming(&context, b"portable private note")
            .unwrap();
        let encoded_envelope = encode_hybrid_recipient_envelope(&envelope).unwrap();
        let decoded_envelope = decode_hybrid_recipient_envelope(&encoded_envelope).unwrap();

        assert_eq!(
            entry.decrypt_incoming(&context, &decoded_envelope).unwrap(),
            b"portable private note"
        );
    }

    #[test]
    fn envelope_decoder_rejects_truncation_oversize_and_trailing_bytes() {
        let entry = HybridPaymentAddressEntry::generate(13);
        let context = RecipientEnvelopeContext::new(b"noxis-local-research", 13).unwrap();
        let envelope = entry
            .address()
            .encrypt_incoming(&context, b"private note")
            .unwrap();
        let encoded = encode_hybrid_recipient_envelope(&envelope).unwrap();

        assert!(matches!(
            decode_hybrid_recipient_envelope(&encoded[..encoded.len() - 1]),
            Err(PaymentAddressCodecError::Truncated)
        ));
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            decode_hybrid_recipient_envelope(&trailing),
            Err(PaymentAddressCodecError::TrailingBytes)
        ));

        let payload_length_offset = HYBRID_RECIPIENT_ENVELOPE_MAGIC.len()
            + 2
            + 8
            + KEYSET_ID_LENGTH
            + X25519_PUBLIC_KEY_LENGTH
            + ML_KEM_768_CIPHERTEXT_LENGTH
            + XCHACHA20_NONCE_LENGTH;
        let mut oversized = encoded;
        oversized[payload_length_offset..payload_length_offset + 4]
            .copy_from_slice(&((MAX_ENCRYPTED_PAYLOAD_BYTES + 1) as u32).to_be_bytes());
        assert!(matches!(
            decode_hybrid_recipient_envelope(&oversized),
            Err(PaymentAddressCodecError::InvalidEncryptedPayloadLength {
                actual
            }) if actual == MAX_ENCRYPTED_PAYLOAD_BYTES + 1
        ));
    }
}
