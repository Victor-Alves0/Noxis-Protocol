//! Canonical, versioned binary codec for Noxis ledger transactions.
//!
//! This format has one representation for each supported transaction value:
//! integers use big-endian byte order, collection lengths are explicit `u32`s,
//! and decoders reject trailing bytes, unknown tags, invalid lengths, and data
//! above resource limits. It is deliberately dependency-free.

use std::fmt;

use noxis_crypto::{AlgorithmId, CryptoSuite, CryptoSuiteError, Proof};
use noxis_ledger::{Mint, Operation, Transaction, Transfer};
use noxis_privacy_types::{PrivacyTypesError, PrivateTransferIntentV2};
use noxis_types::{Amount, AssetId, Commitment, Nullifier, TransactionId, TransactionIntentId};
use sha2::{Digest, Sha256};

/// The fixed prefix identifying a Noxis transaction wire message.
pub const TRANSACTION_MAGIC: [u8; 4] = *b"NOXT";
/// The only transaction-wire format version currently supported.
pub const TRANSACTION_FORMAT_VERSION: u16 = 1;

/// Fixed prefix for the private-transfer v2 packet. It is never `NOXT` v1.
pub const PRIVATE_TRANSFER_MAGIC: [u8; 4] = *b"NXPT";
/// The only private-transfer packet format currently supported.
pub const PRIVATE_TRANSFER_FORMAT_VERSION: u16 = 1;
/// Maximum bytes of one encrypted-recipient envelope before KEM is implemented.
pub const MAX_PRIVATE_ENVELOPE_BYTES: u16 = 4 * 1024;
/// Provisional upper bound for an opaque v2 proof, pending adversarial benchmarks.
pub const MAX_PRIVATE_PROOF_BYTES: u32 = 2 * 1024 * 1024;

/// Upper bound on each transfer input/output collection.
pub const MAX_COLLECTION_ITEMS: u32 = 65_536;
/// Upper bound on an opaque proof or authorization payload.
pub const MAX_OPAQUE_BYTES: u32 = 16 * 1024 * 1024;

const OPERATION_TRANSFER: u8 = 1;
const OPERATION_MINT: u8 = 2;
#[cfg(test)]
const SUITE_BYTES: usize = 6;

/// A framed v2 private transfer whose cryptographic contents remain opaque.
///
/// This packet only fixes resource limits and field order. It does not verify
/// proof soundness, derive envelope digests, perform KEM/AEAD, or authorize a
/// ledger transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateTransferPacketV2 {
    intent: PrivateTransferIntentV2,
    recipient_envelopes: [Vec<u8>; 2],
    proof: Vec<u8>,
}

impl PrivateTransferPacketV2 {
    pub fn new(
        intent: PrivateTransferIntentV2,
        recipient_envelopes: [Vec<u8>; 2],
        proof: Vec<u8>,
    ) -> Result<Self, CodecError> {
        for envelope in &recipient_envelopes {
            ensure_private_envelope_limit(envelope.len())?;
        }
        ensure_private_proof_limit(proof.len())?;
        Ok(Self {
            intent,
            recipient_envelopes,
            proof,
        })
    }

    pub const fn intent(&self) -> &PrivateTransferIntentV2 {
        &self.intent
    }

    pub const fn recipient_envelopes(&self) -> &[Vec<u8>; 2] {
        &self.recipient_envelopes
    }

    pub fn proof(&self) -> &[u8] {
        &self.proof
    }
}

/// Produces the sole canonical external representation of a v2 private packet.
pub fn encode_private_transfer(packet: &PrivateTransferPacketV2) -> Result<Vec<u8>, CodecError> {
    let packet = PrivateTransferPacketV2::new(
        packet.intent.clone(),
        packet.recipient_envelopes.clone(),
        packet.proof.clone(),
    )?;
    let mut output = Vec::with_capacity(
        PRIVATE_TRANSFER_MAGIC.len()
            + 2
            + PrivateTransferIntentV2::ENCODED_LENGTH
            + 2 * (2 + MAX_PRIVATE_ENVELOPE_BYTES as usize)
            + 4
            + packet.proof.len(),
    );
    output.extend_from_slice(&PRIVATE_TRANSFER_MAGIC);
    write_u16(&mut output, PRIVATE_TRANSFER_FORMAT_VERSION);
    output.extend_from_slice(&packet.intent.encode());
    for envelope in &packet.recipient_envelopes {
        write_private_envelope(&mut output, envelope)?;
    }
    write_private_proof(&mut output, &packet.proof)?;
    Ok(output)
}

/// Decodes exactly one bounded v2 private packet.
pub fn decode_private_transfer(bytes: &[u8]) -> Result<PrivateTransferPacketV2, CodecError> {
    let mut reader = Reader::new(bytes);
    if reader.read_array::<4>()? != PRIVATE_TRANSFER_MAGIC {
        return Err(CodecError::InvalidPrivateTransferMagic);
    }
    let version = reader.read_u16()?;
    if version != PRIVATE_TRANSFER_FORMAT_VERSION {
        return Err(CodecError::UnsupportedPrivateTransferFormatVersion(version));
    }
    let intent_bytes = reader.read_exact(PrivateTransferIntentV2::ENCODED_LENGTH)?;
    let intent = PrivateTransferIntentV2::decode(intent_bytes)
        .map_err(CodecError::InvalidPrivateTransferIntent)?;
    let recipient_envelopes = [
        reader.read_private_envelope()?,
        reader.read_private_envelope()?,
    ];
    let proof = reader.read_private_proof()?;
    reader.finish()?;
    PrivateTransferPacketV2::new(intent, recipient_envelopes, proof)
}

/// Produces the sole canonical wire representation of `transaction`.
///
/// Values whose fields exceed wire limits are rejected rather than silently
/// truncated or encoded in a non-portable form.
pub fn encode_transaction(transaction: &Transaction) -> Result<Vec<u8>, CodecError> {
    validate_transaction_shape(transaction)?;

    let mut output = Vec::new();
    output.extend_from_slice(&TRANSACTION_MAGIC);
    write_u16(&mut output, TRANSACTION_FORMAT_VERSION);
    output.extend_from_slice(&transaction.id.0);
    write_suite(&mut output, transaction.suite);

    match &transaction.operation {
        Operation::Transfer(transfer) => {
            output.push(OPERATION_TRANSFER);
            output.extend_from_slice(&transfer.asset_id.0);
            write_identifiers(&mut output, &transfer.input_nullifiers, |value| value.0)?;
            write_identifiers(&mut output, &transfer.output_commitments, |value| value.0)?;
            write_u16(&mut output, transfer.proof.suite_version);
            write_bytes(&mut output, &transfer.proof.bytes)?;
        }
        Operation::Mint(mint) => {
            output.push(OPERATION_MINT);
            output.extend_from_slice(&mint.asset_id.0);
            output.extend_from_slice(&mint.amount.units().to_be_bytes());
            write_identifiers(&mut output, &mint.output_commitments, |value| value.0)?;
            write_bytes(&mut output, &mint.authorization)?;
        }
    }

    Ok(output)
}

/// Decodes exactly one canonical transaction message.
pub fn decode_transaction(bytes: &[u8]) -> Result<Transaction, CodecError> {
    let mut reader = Reader::new(bytes);
    let magic = reader.read_array::<4>()?;
    if magic != TRANSACTION_MAGIC {
        return Err(CodecError::InvalidMagic);
    }
    let version = reader.read_u16()?;
    if version != TRANSACTION_FORMAT_VERSION {
        return Err(CodecError::UnsupportedFormatVersion(version));
    }

    let id = TransactionId::new(reader.read_array()?);
    let suite = read_suite(&mut reader)?;
    let operation = match reader.read_u8()? {
        OPERATION_TRANSFER => Operation::Transfer(read_transfer(&mut reader)?),
        OPERATION_MINT => Operation::Mint(read_mint(&mut reader)?),
        tag => return Err(CodecError::UnknownOperation(tag)),
    };
    reader.finish()?;

    let transaction = Transaction {
        id,
        suite,
        operation,
    };
    validate_transaction_shape(&transaction)?;
    Ok(transaction)
}

/// Returns canonical semantic bytes used to identify a transaction intent.
///
/// The legacy `Transaction::id` and opaque proof/authorization envelopes are
/// deliberately excluded. Including `id` would create a self-reference; a ZK
/// proof or mint signature may itself bind this intent ID, so including either
/// envelope would create another cycle. The next protocol version will carry
/// the state anchor and genesis binding explicitly in this intent.
pub fn encode_transaction_intent(transaction: &Transaction) -> Result<Vec<u8>, CodecError> {
    validate_transaction_shape(transaction)?;
    let mut output = Vec::new();
    output.extend_from_slice(b"NXTI");
    write_u16(&mut output, 1);
    write_suite(&mut output, transaction.suite);
    match &transaction.operation {
        Operation::Transfer(transfer) => {
            output.push(OPERATION_TRANSFER);
            output.extend_from_slice(&transfer.asset_id.0);
            write_identifiers(&mut output, &transfer.input_nullifiers, |value| value.0)?;
            write_identifiers(&mut output, &transfer.output_commitments, |value| value.0)?;
        }
        Operation::Mint(mint) => {
            output.push(OPERATION_MINT);
            output.extend_from_slice(&mint.asset_id.0);
            output.extend_from_slice(&mint.amount.units().to_be_bytes());
            write_identifiers(&mut output, &mint.output_commitments, |value| value.0)?;
        }
    }
    Ok(output)
}

/// Derives a non-self-referential semantic identity for idempotency and future
/// proof/signature binding. It is not yet a network transaction ID because the
/// current wire format lacks genesis and explicit anchor fields.
pub fn transaction_intent_id(transaction: &Transaction) -> Result<TransactionIntentId, CodecError> {
    let intent = encode_transaction_intent(transaction)?;
    let mut hash = Sha256::new();
    hash.update(b"NOXIS/TX-INTENT-ID/V1\0");
    hash.update(
        u32::try_from(intent.len())
            .map_err(|_| CodecError::LengthOverflow)?
            .to_be_bytes(),
    );
    hash.update(intent);
    Ok(TransactionIntentId::new(hash.finalize().into()))
}

fn read_transfer(reader: &mut Reader<'_>) -> Result<Transfer, CodecError> {
    let asset_id = AssetId::new(reader.read_array()?);
    let input_nullifiers = read_identifiers(reader, Nullifier::new)?;
    let output_commitments = read_identifiers(reader, Commitment::new)?;
    let proof = Proof {
        suite_version: reader.read_u16()?,
        bytes: reader.read_bytes()?,
    };
    Ok(Transfer {
        asset_id,
        input_nullifiers,
        output_commitments,
        proof,
    })
}

fn read_mint(reader: &mut Reader<'_>) -> Result<Mint, CodecError> {
    let asset_id = AssetId::new(reader.read_array()?);
    let amount = u128::from_be_bytes(reader.read_array()?);
    let amount = Amount::new(amount).ok_or(CodecError::ZeroMintAmount)?;
    let output_commitments = read_identifiers(reader, Commitment::new)?;
    let authorization = reader.read_bytes()?;
    Ok(Mint {
        asset_id,
        amount,
        output_commitments,
        authorization,
    })
}

fn validate_transaction_shape(transaction: &Transaction) -> Result<(), CodecError> {
    transaction
        .suite
        .validate()
        .map_err(CodecError::InvalidCryptoSuite)?;
    match &transaction.operation {
        Operation::Transfer(transfer) => {
            ensure_non_empty(transfer.input_nullifiers.len(), "transfer input nullifiers")?;
            ensure_non_empty(
                transfer.output_commitments.len(),
                "transfer output commitments",
            )?;
            ensure_collection_limit(transfer.input_nullifiers.len())?;
            ensure_collection_limit(transfer.output_commitments.len())?;
            ensure_opaque_limit(transfer.proof.bytes.len())?;
            if transaction.suite.version != transfer.proof.suite_version {
                return Err(CodecError::ProofSuiteVersionMismatch {
                    transaction: transaction.suite.version,
                    proof: transfer.proof.suite_version,
                });
            }
        }
        Operation::Mint(mint) => {
            ensure_non_empty(mint.output_commitments.len(), "mint output commitments")?;
            ensure_collection_limit(mint.output_commitments.len())?;
            ensure_opaque_limit(mint.authorization.len())?;
        }
    }
    Ok(())
}

fn ensure_non_empty(length: usize, field: &'static str) -> Result<(), CodecError> {
    if length == 0 {
        Err(CodecError::EmptyRequiredField(field))
    } else {
        Ok(())
    }
}

fn ensure_collection_limit(length: usize) -> Result<(), CodecError> {
    if length > MAX_COLLECTION_ITEMS as usize {
        Err(CodecError::CollectionTooLarge {
            actual: length,
            maximum: MAX_COLLECTION_ITEMS,
        })
    } else {
        Ok(())
    }
}

fn ensure_opaque_limit(length: usize) -> Result<(), CodecError> {
    if length > MAX_OPAQUE_BYTES as usize {
        Err(CodecError::OpaqueDataTooLarge {
            actual: length,
            maximum: MAX_OPAQUE_BYTES,
        })
    } else {
        Ok(())
    }
}

fn ensure_private_envelope_limit(length: usize) -> Result<(), CodecError> {
    if length == 0 {
        return Err(CodecError::EmptyRequiredField("private recipient envelope"));
    }
    if length > MAX_PRIVATE_ENVELOPE_BYTES as usize {
        return Err(CodecError::PrivateEnvelopeTooLarge {
            actual: length,
            maximum: MAX_PRIVATE_ENVELOPE_BYTES,
        });
    }
    Ok(())
}

fn ensure_private_proof_limit(length: usize) -> Result<(), CodecError> {
    if length == 0 {
        return Err(CodecError::EmptyRequiredField("private transfer proof"));
    }
    if length > MAX_PRIVATE_PROOF_BYTES as usize {
        return Err(CodecError::PrivateProofTooLarge {
            actual: length,
            maximum: MAX_PRIVATE_PROOF_BYTES,
        });
    }
    Ok(())
}

fn write_suite(output: &mut Vec<u8>, suite: CryptoSuite) {
    write_u16(output, suite.version);
    output.push(encode_algorithm(suite.hash));
    output.push(encode_algorithm(suite.transport_kem));
    output.push(encode_algorithm(suite.identity_signature));
    output.push(encode_algorithm(suite.proof_system));
}

fn read_suite(reader: &mut Reader<'_>) -> Result<CryptoSuite, CodecError> {
    Ok(CryptoSuite {
        version: reader.read_u16()?,
        hash: decode_algorithm(reader.read_u8()?)?,
        transport_kem: decode_algorithm(reader.read_u8()?)?,
        identity_signature: decode_algorithm(reader.read_u8()?)?,
        proof_system: decode_algorithm(reader.read_u8()?)?,
    })
}

fn encode_algorithm(algorithm: AlgorithmId) -> u8 {
    match algorithm {
        AlgorithmId::Sha3_256 => 1,
        AlgorithmId::X25519 => 2,
        AlgorithmId::MlKem768 => 3,
        AlgorithmId::Ed25519 => 4,
        AlgorithmId::MlDsa65 => 5,
        AlgorithmId::PluggableProofSystem => 6,
        // Added without renumbering v1 values so historic codec data remains
        // unambiguous; current genesis/manifest versions reject old contexts.
        AlgorithmId::Sha256 => 7,
    }
}

fn decode_algorithm(code: u8) -> Result<AlgorithmId, CodecError> {
    match code {
        1 => Ok(AlgorithmId::Sha3_256),
        2 => Ok(AlgorithmId::X25519),
        3 => Ok(AlgorithmId::MlKem768),
        4 => Ok(AlgorithmId::Ed25519),
        5 => Ok(AlgorithmId::MlDsa65),
        6 => Ok(AlgorithmId::PluggableProofSystem),
        7 => Ok(AlgorithmId::Sha256),
        value => Err(CodecError::UnknownAlgorithm(value)),
    }
}

fn write_identifiers<T>(
    output: &mut Vec<u8>,
    values: &[T],
    bytes: impl Fn(&T) -> [u8; 32],
) -> Result<(), CodecError> {
    ensure_collection_limit(values.len())?;
    let length = u32::try_from(values.len()).map_err(|_| CodecError::CollectionTooLarge {
        actual: values.len(),
        maximum: MAX_COLLECTION_ITEMS,
    })?;
    write_u32(output, length);
    for value in values {
        output.extend_from_slice(&bytes(value));
    }
    Ok(())
}

fn read_identifiers<T>(
    reader: &mut Reader<'_>,
    construct: impl Fn([u8; 32]) -> T,
) -> Result<Vec<T>, CodecError> {
    let length = reader.read_collection_length()?;
    let mut values = Vec::with_capacity(length);
    for _ in 0..length {
        values.push(construct(reader.read_array()?));
    }
    Ok(values)
}

fn write_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CodecError> {
    ensure_opaque_limit(bytes.len())?;
    let length = u32::try_from(bytes.len()).map_err(|_| CodecError::OpaqueDataTooLarge {
        actual: bytes.len(),
        maximum: MAX_OPAQUE_BYTES,
    })?;
    write_u32(output, length);
    output.extend_from_slice(bytes);
    Ok(())
}

fn write_private_envelope(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CodecError> {
    ensure_private_envelope_limit(bytes.len())?;
    let length = u16::try_from(bytes.len()).map_err(|_| CodecError::PrivateEnvelopeTooLarge {
        actual: bytes.len(),
        maximum: MAX_PRIVATE_ENVELOPE_BYTES,
    })?;
    write_u16(output, length);
    output.extend_from_slice(bytes);
    Ok(())
}

fn write_private_proof(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CodecError> {
    ensure_private_proof_limit(bytes.len())?;
    let length = u32::try_from(bytes.len()).map_err(|_| CodecError::PrivateProofTooLarge {
        actual: bytes.len(),
        maximum: MAX_PRIVATE_PROOF_BYTES,
    })?;
    write_u32(output, length);
    output.extend_from_slice(bytes);
    Ok(())
}

fn write_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}
fn write_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.read_exact(1)?[0])
    }
    fn read_u16(&mut self) -> Result<u16, CodecError> {
        Ok(u16::from_be_bytes(self.read_array()?))
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        self.read_exact(N)?
            .try_into()
            .map_err(|_| CodecError::UnexpectedEnd {
                offset: self.offset,
            })
    }

    fn read_bytes(&mut self) -> Result<Vec<u8>, CodecError> {
        let length = self.read_u32()?;
        if length > MAX_OPAQUE_BYTES {
            return Err(CodecError::OpaqueDataTooLarge {
                actual: length as usize,
                maximum: MAX_OPAQUE_BYTES,
            });
        }
        Ok(self.read_exact(length as usize)?.to_vec())
    }

    fn read_private_envelope(&mut self) -> Result<Vec<u8>, CodecError> {
        let length = self.read_u16()? as usize;
        ensure_private_envelope_limit(length)?;
        Ok(self.read_exact(length)?.to_vec())
    }

    fn read_private_proof(&mut self) -> Result<Vec<u8>, CodecError> {
        let length = self.read_u32()? as usize;
        ensure_private_proof_limit(length)?;
        Ok(self.read_exact(length)?.to_vec())
    }

    fn read_collection_length(&mut self) -> Result<usize, CodecError> {
        let length = self.read_u32()?;
        if length > MAX_COLLECTION_ITEMS {
            return Err(CodecError::CollectionTooLarge {
                actual: length as usize,
                maximum: MAX_COLLECTION_ITEMS,
            });
        }
        let byte_count = (length as usize)
            .checked_mul(32)
            .ok_or(CodecError::LengthOverflow)?;
        if self.remaining() < byte_count {
            return Err(CodecError::UnexpectedEnd {
                offset: self.offset,
            });
        }
        Ok(length as usize)
    }

    fn read_u32(&mut self) -> Result<u32, CodecError> {
        Ok(u32::from_be_bytes(self.read_array()?))
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], CodecError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(CodecError::LengthOverflow)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(CodecError::UnexpectedEnd {
                offset: self.offset,
            })?;
        self.offset = end;
        Ok(slice)
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }
    fn finish(self) -> Result<(), CodecError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(CodecError::TrailingBytes {
                count: self.remaining(),
            })
        }
    }
}

/// A precise reason a message cannot be encoded or decoded safely.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CodecError {
    InvalidMagic,
    UnsupportedFormatVersion(u16),
    InvalidPrivateTransferMagic,
    UnsupportedPrivateTransferFormatVersion(u16),
    InvalidPrivateTransferIntent(PrivacyTypesError),
    UnknownOperation(u8),
    UnknownAlgorithm(u8),
    InvalidCryptoSuite(CryptoSuiteError),
    UnexpectedEnd { offset: usize },
    TrailingBytes { count: usize },
    LengthOverflow,
    CollectionTooLarge { actual: usize, maximum: u32 },
    OpaqueDataTooLarge { actual: usize, maximum: u32 },
    PrivateEnvelopeTooLarge { actual: usize, maximum: u16 },
    PrivateProofTooLarge { actual: usize, maximum: u32 },
    EmptyRequiredField(&'static str),
    ZeroMintAmount,
    ProofSuiteVersionMismatch { transaction: u16, proof: u16 },
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => formatter.write_str("invalid transaction magic bytes"),
            Self::UnsupportedFormatVersion(version) => write!(
                formatter,
                "unsupported transaction format version {version}"
            ),
            Self::InvalidPrivateTransferMagic => {
                formatter.write_str("invalid private-transfer magic bytes")
            }
            Self::UnsupportedPrivateTransferFormatVersion(version) => {
                write!(
                    formatter,
                    "unsupported private-transfer format version {version}"
                )
            }
            Self::InvalidPrivateTransferIntent(error) => {
                write!(formatter, "invalid private-transfer intent: {error}")
            }
            Self::UnknownOperation(tag) => {
                write!(formatter, "unknown transaction operation tag {tag}")
            }
            Self::UnknownAlgorithm(tag) => {
                write!(formatter, "unknown cryptographic algorithm tag {tag}")
            }
            Self::InvalidCryptoSuite(error) => {
                write!(
                    formatter,
                    "transaction has invalid cryptographic suite: {error}"
                )
            }
            Self::UnexpectedEnd { offset } => {
                write!(formatter, "unexpected end of message at byte {offset}")
            }
            Self::TrailingBytes { count } => {
                write!(formatter, "message contains {count} trailing byte(s)")
            }
            Self::LengthOverflow => formatter.write_str("encoded length overflows platform bounds"),
            Self::CollectionTooLarge { actual, maximum } => write!(
                formatter,
                "collection length {actual} exceeds maximum {maximum}"
            ),
            Self::OpaqueDataTooLarge { actual, maximum } => write!(
                formatter,
                "opaque data length {actual} exceeds maximum {maximum}"
            ),
            Self::PrivateEnvelopeTooLarge { actual, maximum } => write!(
                formatter,
                "private recipient envelope length {actual} exceeds maximum {maximum}"
            ),
            Self::PrivateProofTooLarge { actual, maximum } => write!(
                formatter,
                "private transfer proof length {actual} exceeds maximum {maximum}"
            ),
            Self::EmptyRequiredField(field) => write!(formatter, "{field} cannot be empty"),
            Self::ZeroMintAmount => formatter.write_str("mint amount must be non-zero"),
            Self::ProofSuiteVersionMismatch { transaction, proof } => write!(
                formatter,
                "transaction suite version {transaction} does not match proof suite version {proof}"
            ),
        }
    }
}

impl std::error::Error for CodecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidCryptoSuite(error) => Some(error),
            Self::InvalidPrivateTransferIntent(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noxis_privacy_types::{
        CiphertextDigestV2, CircuitId, MerkleRootV2, NoteCommitmentV2, NullifierV2,
        PrivateTransferOutputV2, TreeParametersId, TreeParametersV2,
    };

    fn transfer() -> Transaction {
        Transaction {
            id: TransactionId::new([1; 32]),
            suite: CryptoSuite::RESEARCH_V1,
            operation: Operation::Transfer(Transfer {
                asset_id: AssetId::new([2; 32]),
                input_nullifiers: vec![Nullifier::new([3; 32]), Nullifier::new([4; 32])],
                output_commitments: vec![Commitment::new([5; 32])],
                proof: Proof {
                    suite_version: 1,
                    bytes: vec![6, 7, 8],
                },
            }),
        }
    }

    fn mint() -> Transaction {
        Transaction {
            id: TransactionId::new([9; 32]),
            suite: CryptoSuite::RESEARCH_V1,
            operation: Operation::Mint(Mint {
                asset_id: AssetId::new([10; 32]),
                amount: Amount::new(42).unwrap(),
                output_commitments: vec![Commitment::new([11; 32])],
                authorization: vec![12, 13],
            }),
        }
    }

    fn private_packet() -> PrivateTransferPacketV2 {
        let intent = PrivateTransferIntentV2::new(
            CircuitId::new([20; 32]),
            noxis_types::GenesisId::new([21; 32]),
            noxis_types::ValidationContextId::new([22; 32]),
            noxis_types::StateId::new([23; 32]),
            TreeParametersV2::new(TreeParametersId::new([24; 32])),
            MerkleRootV2::new([25; 64]).unwrap(),
            AssetId::new([26; 32]),
            [
                NullifierV2::new([27; 64]).unwrap(),
                NullifierV2::new([28; 64]).unwrap(),
            ],
            [
                PrivateTransferOutputV2::new(
                    NoteCommitmentV2::new([29; 64]).unwrap(),
                    CiphertextDigestV2::new([31; 64]).unwrap(),
                ),
                PrivateTransferOutputV2::new(
                    NoteCommitmentV2::new([30; 64]).unwrap(),
                    CiphertextDigestV2::new([32; 64]).unwrap(),
                ),
            ],
        )
        .unwrap();
        PrivateTransferPacketV2::new(intent, [vec![33, 34], vec![35]], vec![36, 37]).unwrap()
    }

    #[test]
    fn transfer_round_trip_is_exact_and_canonical() {
        let transaction = transfer();
        let encoded = encode_transaction(&transaction).unwrap();
        assert_eq!(decode_transaction(&encoded).unwrap(), transaction);
        assert_eq!(
            encode_transaction(&decode_transaction(&encoded).unwrap()).unwrap(),
            encoded
        );
    }

    #[test]
    fn mint_round_trip_is_exact_and_canonical() {
        let transaction = mint();
        let encoded = encode_transaction(&transaction).unwrap();
        assert_eq!(decode_transaction(&encoded).unwrap(), transaction);
        assert_eq!(
            encode_transaction(&decode_transaction(&encoded).unwrap()).unwrap(),
            encoded
        );
    }

    #[test]
    fn private_transfer_round_trip_is_exact_and_does_not_use_noxt() {
        let packet = private_packet();
        let encoded = encode_private_transfer(&packet).unwrap();
        assert_eq!(&encoded[..4], &PRIVATE_TRANSFER_MAGIC);
        assert_eq!(decode_private_transfer(&encoded).unwrap(), packet);
        assert_eq!(
            encode_private_transfer(&decode_private_transfer(&encoded).unwrap()).unwrap(),
            encoded
        );
    }

    #[test]
    fn private_transfer_rejects_unknown_values_truncation_and_trailing_bytes() {
        let encoded = encode_private_transfer(&private_packet()).unwrap();
        assert_eq!(
            decode_private_transfer(&encoded[..5]),
            Err(CodecError::UnexpectedEnd { offset: 4 })
        );

        let mut magic = encoded.clone();
        magic[0] ^= 1;
        assert_eq!(
            decode_private_transfer(&magic),
            Err(CodecError::InvalidPrivateTransferMagic)
        );

        let mut version = encoded.clone();
        version[5] = 2;
        assert_eq!(
            decode_private_transfer(&version),
            Err(CodecError::UnsupportedPrivateTransferFormatVersion(2))
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            decode_private_transfer(&trailing),
            Err(CodecError::TrailingBytes { count: 1 })
        );
    }

    #[test]
    fn private_transfer_bounds_opaque_parts_before_allocating() {
        let mut encoded = encode_private_transfer(&private_packet()).unwrap();
        let first_envelope_length_offset = 4 + 2 + PrivateTransferIntentV2::ENCODED_LENGTH;
        encoded[first_envelope_length_offset..first_envelope_length_offset + 2]
            .copy_from_slice(&(MAX_PRIVATE_ENVELOPE_BYTES + 1).to_be_bytes());
        assert_eq!(
            decode_private_transfer(&encoded),
            Err(CodecError::PrivateEnvelopeTooLarge {
                actual: (MAX_PRIVATE_ENVELOPE_BYTES + 1) as usize,
                maximum: MAX_PRIVATE_ENVELOPE_BYTES,
            })
        );

        let mut encoded = encode_private_transfer(&private_packet()).unwrap();
        let proof_length_offset = 4 + 2 + PrivateTransferIntentV2::ENCODED_LENGTH + 2 + 2 + 2 + 1;
        encoded[proof_length_offset..proof_length_offset + 4]
            .copy_from_slice(&(MAX_PRIVATE_PROOF_BYTES + 1).to_be_bytes());
        assert_eq!(
            decode_private_transfer(&encoded),
            Err(CodecError::PrivateProofTooLarge {
                actual: (MAX_PRIVATE_PROOF_BYTES + 1) as usize,
                maximum: MAX_PRIVATE_PROOF_BYTES,
            })
        );

        let overlong_proof = PrivateTransferPacketV2::new(
            private_packet().intent().clone(),
            [vec![1], vec![2]],
            vec![0; MAX_PRIVATE_PROOF_BYTES as usize + 1],
        );
        assert_eq!(
            overlong_proof,
            Err(CodecError::PrivateProofTooLarge {
                actual: MAX_PRIVATE_PROOF_BYTES as usize + 1,
                maximum: MAX_PRIVATE_PROOF_BYTES,
            })
        );
    }

    #[test]
    fn private_transfer_rejects_empty_and_accepts_exact_opaque_limits() {
        let packet = private_packet();
        assert_eq!(
            PrivateTransferPacketV2::new(packet.intent().clone(), [Vec::new(), vec![1]], vec![2]),
            Err(CodecError::EmptyRequiredField("private recipient envelope"))
        );
        assert_eq!(
            PrivateTransferPacketV2::new(packet.intent().clone(), [vec![1], vec![2]], Vec::new()),
            Err(CodecError::EmptyRequiredField("private transfer proof"))
        );
        let largest = PrivateTransferPacketV2::new(
            packet.intent().clone(),
            [
                vec![1; MAX_PRIVATE_ENVELOPE_BYTES as usize],
                vec![2; MAX_PRIVATE_ENVELOPE_BYTES as usize],
            ],
            vec![3; MAX_PRIVATE_PROOF_BYTES as usize],
        )
        .unwrap();
        assert_eq!(
            decode_private_transfer(&encode_private_transfer(&largest).unwrap()).unwrap(),
            largest
        );
    }

    #[test]
    fn rejects_unknown_protocol_values_and_trailing_bytes() {
        let mut encoded = encode_transaction(&transfer()).unwrap();
        encoded[4] = 0;
        encoded[5] = 2;
        assert_eq!(
            decode_transaction(&encoded),
            Err(CodecError::UnsupportedFormatVersion(2))
        );

        let mut encoded = encode_transaction(&transfer()).unwrap();
        encoded.push(0);
        assert_eq!(
            decode_transaction(&encoded),
            Err(CodecError::TrailingBytes { count: 1 })
        );

        let mut encoded = encode_transaction(&transfer()).unwrap();
        let operation_offset = 4 + 2 + 32 + SUITE_BYTES;
        encoded[operation_offset] = 99;
        assert_eq!(
            decode_transaction(&encoded),
            Err(CodecError::UnknownOperation(99))
        );
    }

    #[test]
    fn rejects_truncated_and_oversized_payloads_before_allocating() {
        let encoded = encode_transaction(&transfer()).unwrap();
        assert_eq!(
            decode_transaction(&encoded[..10]),
            Err(CodecError::UnexpectedEnd { offset: 6 })
        );

        let mut encoded = encode_transaction(&transfer()).unwrap();
        let input_count_offset = 4 + 2 + 32 + SUITE_BYTES + 1 + 32;
        encoded[input_count_offset..input_count_offset + 4]
            .copy_from_slice(&(MAX_COLLECTION_ITEMS + 1).to_be_bytes());
        assert_eq!(
            decode_transaction(&encoded),
            Err(CodecError::CollectionTooLarge {
                actual: (MAX_COLLECTION_ITEMS + 1) as usize,
                maximum: MAX_COLLECTION_ITEMS
            })
        );
    }

    #[test]
    fn rejects_structurally_invalid_values_for_both_paths() {
        let mut invalid = transfer();
        if let Operation::Transfer(transfer) = &mut invalid.operation {
            transfer.input_nullifiers.clear();
        }
        assert_eq!(
            encode_transaction(&invalid),
            Err(CodecError::EmptyRequiredField("transfer input nullifiers"))
        );

        let mut encoded = encode_transaction(&mint()).unwrap();
        let amount_offset = 4 + 2 + 32 + SUITE_BYTES + 1 + 32;
        encoded[amount_offset..amount_offset + 16].fill(0);
        assert_eq!(
            decode_transaction(&encoded),
            Err(CodecError::ZeroMintAmount)
        );
    }

    #[test]
    fn rejects_proof_with_different_suite_version() {
        let mut invalid = transfer();
        if let Operation::Transfer(transfer) = &mut invalid.operation {
            transfer.proof.suite_version = 2;
        }
        assert_eq!(
            encode_transaction(&invalid),
            Err(CodecError::ProofSuiteVersionMismatch {
                transaction: 1,
                proof: 2
            })
        );
    }

    #[test]
    fn rejects_a_suite_with_a_known_algorithm_in_the_wrong_role() {
        let mut invalid = transfer();
        invalid.suite.hash = AlgorithmId::Ed25519;
        assert_eq!(
            encode_transaction(&invalid),
            Err(CodecError::InvalidCryptoSuite(
                CryptoSuiteError::AlgorithmRoleMismatch {
                    field: noxis_crypto::CryptoSuiteField::Hash,
                    algorithm: AlgorithmId::Ed25519,
                }
            ))
        );
    }

    #[test]
    fn intent_id_ignores_legacy_id_and_opaque_proof_envelope() {
        let first = transfer();
        let mut second = first.clone();
        second.id = TransactionId::new([99; 32]);
        if let Operation::Transfer(transfer) = &mut second.operation {
            transfer.proof.bytes = vec![99, 98, 97];
        }
        assert_eq!(
            transaction_intent_id(&first).unwrap(),
            transaction_intent_id(&second).unwrap()
        );
        assert_ne!(
            encode_transaction(&first).unwrap(),
            encode_transaction(&second).unwrap()
        );
    }
}
