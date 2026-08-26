use std::fmt;

use noxis_types::ValidatorId;
use sha2::{Digest, Sha256};

use crate::ValidatorSet;

/// Version of the canonical CometBFT network-identity encoding.
///
/// This version governs only the encoding below. It is intentionally separate
/// from both the Noxis protocol rule set and the CometBFT compatibility
/// version committed by [`CometBftNetworkIdentity`].
pub const COMET_BFT_NETWORK_IDENTITY_FORMAT_VERSION: u16 = 1;
/// Largest accepted CometBFT chain ID in its canonical Noxis representation.
pub const MAX_COMET_BFT_CHAIN_ID_BYTES: usize = 128;
/// Largest accepted CometBFT compatibility-version label.
pub const MAX_COMET_BFT_COMPATIBILITY_VERSION_BYTES: usize = 64;
/// Width of the SHA-256 commitment to the engine's canonical parameters.
pub const COMET_BFT_PARAMETERS_SHA256_LENGTH: usize = 32;

/// Exact CometBFT compatibility label supported by the first Noxis adapter.
///
/// The generic network-identity format can represent other pinned engine
/// versions, but the canonical validator conversion below intentionally
/// supports only this version until every changed wire rule is reviewed.
pub const COMET_BFT_V0_38_COMPATIBILITY_VERSION: &str = "cometbft-0.38";
/// Noxis validator-key scheme code for a raw CometBFT v0.38 Ed25519 key.
///
/// This is a protocol-local identifier, not an IANA, NIST, or Comet registry
/// number. It is deliberately explicit so an arbitrary generic validator key
/// cannot be passed to a CometBFT process as if it were Ed25519.
pub const COMET_BFT_ED25519_SIGNATURE_SCHEME: u16 = 1;
/// Raw Ed25519 public-key width required by CometBFT v0.38.
pub const COMET_BFT_ED25519_PUBLIC_KEY_LENGTH: usize = 32;
/// Width of the CometBFT address derived from a validator public key.
pub const COMET_BFT_VALIDATOR_ADDRESS_LENGTH: usize = 20;
/// CometBFT v0.38 prevents arithmetic clipping by limiting total validator
/// power to `MaxInt64 / 8`.
pub const COMET_BFT_MAX_TOTAL_VOTING_POWER: u64 = (i64::MAX as u64) / 8;

/// Width in bytes of an opaque CometBFT block or validator-set hash.
pub const COMET_BFT_HASH_LENGTH: usize = 32;

const COMET_BFT_NETWORK_ID_DOMAIN: &[u8] = b"NOXIS/COMET-BFT/NETWORK-ID/V1\0";
const COMET_BFT_GENESIS_ID_DOMAIN: &[u8] = b"NOXIS/COMET-BFT/GENESIS-ID/V1\0";

const MIN_ENCODED_LENGTH: usize = 2 + 1 + 1 + 8 + 1 + 1 + COMET_BFT_PARAMETERS_SHA256_LENGTH;
/// Largest canonical byte representation of [`CometBftNetworkIdentity`].
pub const MAX_COMET_BFT_NETWORK_IDENTITY_ENCODED_LENGTH: usize = 2
    + 1
    + MAX_COMET_BFT_CHAIN_ID_BYTES
    + 8
    + 1
    + MAX_COMET_BFT_COMPATIBILITY_VERSION_BYTES
    + COMET_BFT_PARAMETERS_SHA256_LENGTH;

/// Immutable network identity required to bind Noxis to one CometBFT genesis.
///
/// `parameters_sha256` is the SHA-256 digest of the separately specified,
/// canonical CometBFT genesis/consensus-parameter document. Noxis does not
/// manufacture or interpret that document here; pinning its digest prevents a
/// node from silently using different engine parameters under the same Noxis
/// genesis. The future Comet adapter must obtain the document, recompute this
/// digest and refuse a mismatch before opening network transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CometBftNetworkIdentity {
    chain_id: String,
    initial_height: i64,
    compatibility_version: String,
    parameters_sha256: [u8; COMET_BFT_PARAMETERS_SHA256_LENGTH],
}

impl CometBftNetworkIdentity {
    /// Validates an immutable CometBFT identity before it enters genesis.
    pub fn new(
        chain_id: impl Into<String>,
        initial_height: i64,
        compatibility_version: impl Into<String>,
        parameters_sha256: [u8; COMET_BFT_PARAMETERS_SHA256_LENGTH],
    ) -> Result<Self, EngineIdentityError> {
        let chain_id = chain_id.into();
        validate_label(
            &chain_id,
            MAX_COMET_BFT_CHAIN_ID_BYTES,
            EngineIdentityError::InvalidChainId,
        )?;
        if initial_height <= 0 {
            return Err(EngineIdentityError::InvalidInitialHeight(initial_height));
        }
        let compatibility_version = compatibility_version.into();
        validate_label(
            &compatibility_version,
            MAX_COMET_BFT_COMPATIBILITY_VERSION_BYTES,
            EngineIdentityError::InvalidCompatibilityVersion,
        )?;
        Ok(Self {
            chain_id,
            initial_height,
            compatibility_version,
            parameters_sha256,
        })
    }

    /// CometBFT chain ID, exactly as committed by the genesis configuration.
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    /// First CometBFT block height represented by this genesis.
    pub const fn initial_height(&self) -> i64 {
        self.initial_height
    }

    /// Explicit engine compatibility label pinned by this Noxis network.
    ///
    /// It is an opaque, printable version label. The transport adapter is
    /// responsible for recognizing and enforcing a supported value.
    pub fn compatibility_version(&self) -> &str {
        &self.compatibility_version
    }

    /// SHA-256 commitment to canonical CometBFT genesis parameters.
    pub const fn parameters_sha256(&self) -> [u8; COMET_BFT_PARAMETERS_SHA256_LENGTH] {
        self.parameters_sha256
    }

    /// Domain-separated stable identifier for this complete engine identity.
    ///
    /// It includes chain ID, initial height, pinned compatibility version and
    /// parameter commitment. A decision stores this value rather than trusting
    /// a caller-supplied chain name.
    pub fn id(&self) -> [u8; COMET_BFT_HASH_LENGTH] {
        let mut hash = Sha256::new();
        hash.update(COMET_BFT_NETWORK_ID_DOMAIN);
        hash.update(self.encode());
        hash.finalize().into()
    }

    /// Maps a positive Noxis execution height to its configured CometBFT
    /// height. Noxis genesis is height zero; the first durable block is at the
    /// configured Comet initial height.
    pub fn engine_height_for(&self, noxis_height: u64) -> Result<i64, EngineIdentityError> {
        if noxis_height == 0 {
            return Err(EngineIdentityError::InvalidNoxisHeight);
        }
        let offset =
            i64::try_from(noxis_height - 1).map_err(|_| EngineIdentityError::HeightOverflow)?;
        self.initial_height
            .checked_add(offset)
            .ok_or(EngineIdentityError::HeightOverflow)
    }

    /// Deterministic binary representation used by Noxis genesis and NXMF.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            MIN_ENCODED_LENGTH + self.chain_id.len() + self.compatibility_version.len(),
        );
        bytes.extend_from_slice(&COMET_BFT_NETWORK_IDENTITY_FORMAT_VERSION.to_be_bytes());
        bytes.push(self.chain_id.len() as u8);
        bytes.extend_from_slice(self.chain_id.as_bytes());
        bytes.extend_from_slice(&self.initial_height.to_be_bytes());
        bytes.push(self.compatibility_version.len() as u8);
        bytes.extend_from_slice(self.compatibility_version.as_bytes());
        bytes.extend_from_slice(&self.parameters_sha256);
        bytes
    }
}

/// One initial validator after its exact CometBFT v0.38 representation has
/// been derived from the generic Noxis consensus configuration.
///
/// Noxis keeps its own stable [`ValidatorId`], while Comet derives the engine
/// address from the public key. Both are retained so an adapter cannot quietly
/// substitute one identity for the other.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CometBftValidator {
    noxis_validator_id: ValidatorId,
    address: [u8; COMET_BFT_VALIDATOR_ADDRESS_LENGTH],
    public_key: [u8; COMET_BFT_ED25519_PUBLIC_KEY_LENGTH],
    voting_power: i64,
}

impl CometBftValidator {
    /// Reconstructs one validator observed in a CometBFT v0.38 `InitChain`
    /// request after the transport adapter has associated it with its expected
    /// Noxis validator ID.
    pub fn from_comet_ed25519(
        noxis_validator_id: ValidatorId,
        public_key: [u8; COMET_BFT_ED25519_PUBLIC_KEY_LENGTH],
        voting_power: i64,
    ) -> Result<Self, EngineIdentityError> {
        if voting_power <= 0 || voting_power as u64 > COMET_BFT_MAX_TOTAL_VOTING_POWER {
            return Err(EngineIdentityError::InvalidCometValidatorVotingPower(
                voting_power,
            ));
        }
        let mut address = [0; COMET_BFT_VALIDATOR_ADDRESS_LENGTH];
        let digest: [u8; COMET_BFT_HASH_LENGTH] = Sha256::digest(public_key).into();
        address.copy_from_slice(&digest[..COMET_BFT_VALIDATOR_ADDRESS_LENGTH]);
        Ok(Self {
            noxis_validator_id,
            address,
            public_key,
            voting_power,
        })
    }

    pub const fn noxis_validator_id(self) -> ValidatorId {
        self.noxis_validator_id
    }

    /// `SHA256(raw_ed25519_public_key)[..20]`, as specified by CometBFT.
    pub const fn address(self) -> [u8; COMET_BFT_VALIDATOR_ADDRESS_LENGTH] {
        self.address
    }

    /// Raw 32-byte Ed25519 public key, not a serialized Noxis wrapper.
    pub const fn public_key(self) -> [u8; COMET_BFT_ED25519_PUBLIC_KEY_LENGTH] {
        self.public_key
    }

    pub const fn voting_power(self) -> i64 {
        self.voting_power
    }

    fn from_noxis(validator: &crate::Validator) -> Result<Self, EngineIdentityError> {
        if validator.verification_key().signature_scheme() != COMET_BFT_ED25519_SIGNATURE_SCHEME {
            return Err(
                EngineIdentityError::UnsupportedCometValidatorSignatureScheme {
                    actual: validator.verification_key().signature_scheme(),
                    expected: COMET_BFT_ED25519_SIGNATURE_SCHEME,
                },
            );
        }
        let public_key: [u8; COMET_BFT_ED25519_PUBLIC_KEY_LENGTH] = validator
            .verification_key()
            .bytes()
            .try_into()
            .map_err(
                |_| EngineIdentityError::InvalidCometEd25519PublicKeyLength {
                    actual: validator.verification_key().bytes().len(),
                    expected: COMET_BFT_ED25519_PUBLIC_KEY_LENGTH,
                },
            )?;
        let voting_power = i64::try_from(validator.voting_power()).map_err(|_| {
            EngineIdentityError::CometValidatorVotingPowerTooLarge {
                actual: validator.voting_power(),
                maximum: COMET_BFT_MAX_TOTAL_VOTING_POWER,
            }
        })?;
        Self::from_comet_ed25519(validator.id(), public_key, voting_power)
    }

    /// Exact protobuf bytes of CometBFT v0.38 `types.SimpleValidator`.
    ///
    /// `ValidatorSet.Hash()` commits to these bytes; it does not include the
    /// Noxis validator ID, Comet address or proposer priority.
    fn comet_hash_bytes(self) -> Vec<u8> {
        // `crypto.PublicKey { ed25519: bytes }`.
        let mut public_key = Vec::with_capacity(2 + COMET_BFT_ED25519_PUBLIC_KEY_LENGTH);
        public_key.push(0x0a); // field 1, wire type bytes
        public_key.push(COMET_BFT_ED25519_PUBLIC_KEY_LENGTH as u8);
        public_key.extend_from_slice(&self.public_key);

        // `types.SimpleValidator { pub_key: PublicKey, voting_power: int64 }`.
        let mut bytes = Vec::with_capacity(2 + public_key.len() + 11);
        bytes.push(0x0a); // field 1, wire type bytes
        encode_uvarint(public_key.len() as u64, &mut bytes);
        bytes.extend_from_slice(&public_key);
        bytes.push(0x10); // field 2, wire type varint
        encode_uvarint(self.voting_power as u64, &mut bytes);
        bytes
    }
}

/// Canonical initial validator set as CometBFT v0.38 will interpret it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CometBftValidatorSet {
    validators: Vec<CometBftValidator>,
    hash: [u8; COMET_BFT_HASH_LENGTH],
}

impl CometBftValidatorSet {
    /// Converts the generic Noxis validator set to its one supported Comet
    /// representation and calculates the engine's exact validator-set hash.
    pub fn from_noxis_validator_set(
        validators: &ValidatorSet,
    ) -> Result<Self, EngineIdentityError> {
        let mut mapped = validators
            .validators()
            .iter()
            .map(CometBftValidator::from_noxis)
            .collect::<Result<Vec<_>, _>>()?;
        let total = mapped.iter().try_fold(0_u64, |total, validator| {
            total.checked_add(validator.voting_power as u64).ok_or(
                EngineIdentityError::CometTotalVotingPowerTooLarge {
                    actual: u64::MAX,
                    maximum: COMET_BFT_MAX_TOTAL_VOTING_POWER,
                },
            )
        })?;
        if total > COMET_BFT_MAX_TOTAL_VOTING_POWER {
            return Err(EngineIdentityError::CometTotalVotingPowerTooLarge {
                actual: total,
                maximum: COMET_BFT_MAX_TOTAL_VOTING_POWER,
            });
        }
        // CometBFT sorts the live set by voting power, descending, then address
        // ascending. That order feeds ValidatorSet.Hash().
        mapped.sort_unstable_by(|left, right| {
            right
                .voting_power
                .cmp(&left.voting_power)
                .then_with(|| left.address.cmp(&right.address))
        });
        if mapped
            .windows(2)
            .any(|pair| pair[0].address == pair[1].address)
        {
            return Err(EngineIdentityError::DuplicateCometValidatorAddress);
        }
        let hashes = mapped
            .iter()
            .copied()
            .map(CometBftValidator::comet_hash_bytes)
            .collect::<Vec<_>>();
        let hash = comet_merkle_root(&hashes);
        Ok(Self {
            validators: mapped,
            hash,
        })
    }

    pub fn validators(&self) -> &[CometBftValidator] {
        &self.validators
    }

    /// Exact `ValidatorSet.Hash()` for the mapped CometBFT v0.38 set.
    pub const fn hash(&self) -> [u8; COMET_BFT_HASH_LENGTH] {
        self.hash
    }
}

/// Complete genesis anchor consumed by the Noxis CometBFT adapter.
///
/// It binds the network identity to the *derived* CometBFT validator set. The
/// derivation is intentionally strict and version-specific; later Comet
/// versions or key types require a new reviewed mapping rather than a best
/// effort fallback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CometBftGenesis {
    identity: CometBftNetworkIdentity,
    validators: CometBftValidatorSet,
    id: [u8; COMET_BFT_HASH_LENGTH],
}

impl CometBftGenesis {
    pub fn from_consensus_config(
        identity: CometBftNetworkIdentity,
        validators: &ValidatorSet,
    ) -> Result<Self, EngineIdentityError> {
        if identity.compatibility_version() != COMET_BFT_V0_38_COMPATIBILITY_VERSION {
            return Err(EngineIdentityError::UnsupportedCometCompatibilityVersion);
        }
        let validators = CometBftValidatorSet::from_noxis_validator_set(validators)?;
        let mut hash = Sha256::new();
        hash.update(COMET_BFT_GENESIS_ID_DOMAIN);
        hash.update(identity.encode());
        hash.update(validators.hash());
        Ok(Self {
            identity,
            validators,
            id: hash.finalize().into(),
        })
    }

    pub fn identity(&self) -> &CometBftNetworkIdentity {
        &self.identity
    }

    pub fn validators(&self) -> &CometBftValidatorSet {
        &self.validators
    }

    /// Stable commitment to both the engine identity and its initial validator
    /// mapping; used by consensus anchors and durable decisions.
    pub const fn id(&self) -> [u8; COMET_BFT_HASH_LENGTH] {
        self.id
    }
}

/// Context from a CometBFT decision that Noxis persists and commits.
///
/// The future TCP adapter must construct this from the exact engine request;
/// neither the executor nor storage fabricates it. `next_validators_hash` is
/// retained even while validator-set updates are unsupported, so a different
/// engine schedule cannot be silently attached to the same Noxis block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CometBftDecision {
    network_id: [u8; COMET_BFT_HASH_LENGTH],
    height: i64,
    block_hash: [u8; COMET_BFT_HASH_LENGTH],
    next_validators_hash: [u8; COMET_BFT_HASH_LENGTH],
}

impl CometBftDecision {
    pub fn new(
        genesis: &CometBftGenesis,
        height: i64,
        block_hash: [u8; COMET_BFT_HASH_LENGTH],
        next_validators_hash: [u8; COMET_BFT_HASH_LENGTH],
    ) -> Result<Self, EngineIdentityError> {
        if height <= 0 {
            return Err(EngineIdentityError::InvalidDecisionHeight(height));
        }
        if block_hash == [0; COMET_BFT_HASH_LENGTH] {
            return Err(EngineIdentityError::ZeroDecisionBlockHash);
        }
        if next_validators_hash == [0; COMET_BFT_HASH_LENGTH] {
            return Err(EngineIdentityError::ZeroNextValidatorsHash);
        }
        Ok(Self {
            network_id: genesis.id(),
            height,
            block_hash,
            next_validators_hash,
        })
    }

    /// Reconstructs a decision already stored in a canonical durable frame.
    ///
    /// Network/height correspondence is checked separately by
    /// [`Self::validate_for`] during replay, once the configured identity and
    /// Noxis height are available.
    pub fn from_persisted(
        network_id: [u8; COMET_BFT_HASH_LENGTH],
        height: i64,
        block_hash: [u8; COMET_BFT_HASH_LENGTH],
        next_validators_hash: [u8; COMET_BFT_HASH_LENGTH],
    ) -> Result<Self, EngineIdentityError> {
        if network_id == [0; COMET_BFT_HASH_LENGTH] {
            return Err(EngineIdentityError::ZeroDecisionNetworkId);
        }
        if height <= 0 {
            return Err(EngineIdentityError::InvalidDecisionHeight(height));
        }
        if block_hash == [0; COMET_BFT_HASH_LENGTH] {
            return Err(EngineIdentityError::ZeroDecisionBlockHash);
        }
        if next_validators_hash == [0; COMET_BFT_HASH_LENGTH] {
            return Err(EngineIdentityError::ZeroNextValidatorsHash);
        }
        Ok(Self {
            network_id,
            height,
            block_hash,
            next_validators_hash,
        })
    }

    pub const fn network_id(self) -> [u8; COMET_BFT_HASH_LENGTH] {
        self.network_id
    }

    pub const fn height(self) -> i64 {
        self.height
    }

    pub const fn block_hash(self) -> [u8; COMET_BFT_HASH_LENGTH] {
        self.block_hash
    }

    pub const fn next_validators_hash(self) -> [u8; COMET_BFT_HASH_LENGTH] {
        self.next_validators_hash
    }

    /// Verifies that this is the unique CometBFT decision expected for one
    /// Noxis execution height and configured network.
    pub fn validate_for(
        self,
        genesis: &CometBftGenesis,
        noxis_height: u64,
    ) -> Result<(), EngineIdentityError> {
        if self.network_id != genesis.id() {
            return Err(EngineIdentityError::DecisionNetworkMismatch);
        }
        let expected = genesis.identity().engine_height_for(noxis_height)?;
        if self.height != expected {
            return Err(EngineIdentityError::DecisionHeightMismatch {
                expected,
                actual: self.height,
            });
        }
        if self.next_validators_hash != genesis.validators().hash() {
            return Err(EngineIdentityError::UnexpectedNextValidatorsHash);
        }
        Ok(())
    }
}

fn encode_uvarint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value as u8) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn comet_merkle_root(values: &[Vec<u8>]) -> [u8; COMET_BFT_HASH_LENGTH] {
    debug_assert!(!values.is_empty());
    let leaves = values
        .iter()
        .map(|value| {
            let mut hash = Sha256::new();
            hash.update([0]);
            hash.update(value);
            hash.finalize().into()
        })
        .collect::<Vec<[u8; COMET_BFT_HASH_LENGTH]>>();
    comet_merkle_hashes(&leaves)
}

fn comet_merkle_hashes(values: &[[u8; COMET_BFT_HASH_LENGTH]]) -> [u8; COMET_BFT_HASH_LENGTH] {
    if values.len() == 1 {
        return values[0];
    }
    let split = largest_power_of_two_below(values.len());
    let left = comet_merkle_hashes(&values[..split]);
    let right = comet_merkle_hashes(&values[split..]);
    let mut hash = Sha256::new();
    hash.update([1]);
    hash.update(left);
    hash.update(right);
    hash.finalize().into()
}

fn largest_power_of_two_below(value: usize) -> usize {
    debug_assert!(value > 1);
    1_usize << (usize::BITS - (value - 1).leading_zeros() - 1)
}

/// Decodes one exact canonical CometBFT network identity.
pub fn decode_comet_bft_network_identity(
    bytes: &[u8],
) -> Result<CometBftNetworkIdentity, EngineIdentityError> {
    if !(MIN_ENCODED_LENGTH..=MAX_COMET_BFT_NETWORK_IDENTITY_ENCODED_LENGTH).contains(&bytes.len())
    {
        return Err(EngineIdentityError::InvalidEncodedLength(bytes.len()));
    }
    let mut reader = IdentityReader::new(bytes);
    let format_version = reader.read_u16()?;
    if format_version != COMET_BFT_NETWORK_IDENTITY_FORMAT_VERSION {
        return Err(EngineIdentityError::UnsupportedFormatVersion(
            format_version,
        ));
    }
    let chain_id_length = reader.read_u8()? as usize;
    let chain_id = reader.read_label(chain_id_length)?;
    let initial_height = reader.read_i64()?;
    let compatibility_version_length = reader.read_u8()? as usize;
    let compatibility_version = reader.read_label(compatibility_version_length)?;
    let parameters_sha256 = reader.read_array()?;
    reader.finish()?;
    let identity = CometBftNetworkIdentity::new(
        chain_id,
        initial_height,
        compatibility_version,
        parameters_sha256,
    )?;
    if identity.encode() != bytes {
        return Err(EngineIdentityError::NonCanonicalEncoding);
    }
    Ok(identity)
}

fn validate_label(
    value: &str,
    maximum: usize,
    invalid_error: EngineIdentityError,
) -> Result<(), EngineIdentityError> {
    if value.is_empty()
        || value.len() > maximum
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(invalid_error);
    }
    Ok(())
}

struct IdentityReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> IdentityReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, EngineIdentityError> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, EngineIdentityError> {
        Ok(u16::from_be_bytes(self.read_array()?))
    }

    fn read_i64(&mut self) -> Result<i64, EngineIdentityError> {
        Ok(i64::from_be_bytes(self.read_array()?))
    }

    fn read_label(&mut self, length: usize) -> Result<String, EngineIdentityError> {
        let bytes = self.read_exact(length)?;
        let value = std::str::from_utf8(bytes).map_err(|_| EngineIdentityError::NonUtf8Label)?;
        Ok(value.to_owned())
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], EngineIdentityError> {
        self.read_exact(N)?
            .try_into()
            .map_err(|_| EngineIdentityError::UnexpectedEnd {
                offset: self.offset,
            })
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], EngineIdentityError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(EngineIdentityError::LengthOverflow)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(EngineIdentityError::UnexpectedEnd {
                offset: self.offset,
            })?;
        self.offset = end;
        Ok(value)
    }

    fn finish(self) -> Result<(), EngineIdentityError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(EngineIdentityError::TrailingBytes {
                count: self.bytes.len() - self.offset,
            })
        }
    }
}

/// A CometBFT network identity was malformed or not canonically encoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineIdentityError {
    InvalidChainId,
    InvalidInitialHeight(i64),
    InvalidCompatibilityVersion,
    InvalidNoxisHeight,
    InvalidDecisionHeight(i64),
    ZeroDecisionBlockHash,
    ZeroDecisionNetworkId,
    ZeroNextValidatorsHash,
    DecisionNetworkMismatch,
    DecisionHeightMismatch { expected: i64, actual: i64 },
    InvalidEncodedLength(usize),
    UnsupportedFormatVersion(u16),
    NonUtf8Label,
    NonCanonicalEncoding,
    UnexpectedEnd { offset: usize },
    TrailingBytes { count: usize },
    LengthOverflow,
    HeightOverflow,
    UnsupportedCometCompatibilityVersion,
    UnsupportedCometValidatorSignatureScheme { actual: u16, expected: u16 },
    InvalidCometEd25519PublicKeyLength { actual: usize, expected: usize },
    InvalidCometValidatorVotingPower(i64),
    CometValidatorVotingPowerTooLarge { actual: u64, maximum: u64 },
    CometTotalVotingPowerTooLarge { actual: u64, maximum: u64 },
    DuplicateCometValidatorAddress,
    UnexpectedNextValidatorsHash,
}

impl fmt::Display for EngineIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidChainId => formatter.write_str("invalid CometBFT chain ID"),
            Self::InvalidInitialHeight(height) => {
                write!(formatter, "invalid CometBFT initial height {height}")
            }
            Self::InvalidCompatibilityVersion => {
                formatter.write_str("invalid CometBFT compatibility version")
            }
            Self::InvalidNoxisHeight => {
                formatter.write_str("Noxis execution height must be positive")
            }
            Self::InvalidDecisionHeight(height) => {
                write!(formatter, "invalid CometBFT decision height {height}")
            }
            Self::ZeroDecisionBlockHash => {
                formatter.write_str("CometBFT decision block hash cannot be zero")
            }
            Self::ZeroDecisionNetworkId => {
                formatter.write_str("CometBFT decision network ID cannot be zero")
            }
            Self::ZeroNextValidatorsHash => {
                formatter.write_str("CometBFT next validators hash cannot be zero")
            }
            Self::DecisionNetworkMismatch => {
                formatter.write_str("CometBFT decision belongs to another network")
            }
            Self::DecisionHeightMismatch { expected, actual } => write!(
                formatter,
                "expected CometBFT decision height {expected}, received {actual}"
            ),
            Self::InvalidEncodedLength(length) => {
                write!(
                    formatter,
                    "invalid CometBFT identity encoding length {length}"
                )
            }
            Self::UnsupportedFormatVersion(version) => {
                write!(
                    formatter,
                    "unsupported CometBFT identity format version {version}"
                )
            }
            Self::NonUtf8Label => formatter.write_str("CometBFT identity label is not UTF-8"),
            Self::NonCanonicalEncoding => {
                formatter.write_str("CometBFT identity does not use canonical encoding")
            }
            Self::UnexpectedEnd { offset } => {
                write!(
                    formatter,
                    "unexpected end of CometBFT identity at byte {offset}"
                )
            }
            Self::TrailingBytes { count } => {
                write!(formatter, "CometBFT identity has {count} trailing byte(s)")
            }
            Self::LengthOverflow => formatter.write_str("CometBFT identity length overflows"),
            Self::HeightOverflow => {
                formatter.write_str("CometBFT/Noxis height conversion overflows")
            }
            Self::UnsupportedCometCompatibilityVersion => formatter.write_str(
                "CometBFT validator mapping requires the pinned cometbft-0.38 compatibility version",
            ),
            Self::UnsupportedCometValidatorSignatureScheme { actual, expected } => write!(
                formatter,
                "CometBFT v0.38 requires validator signature scheme {expected}, received {actual}"
            ),
            Self::InvalidCometEd25519PublicKeyLength { actual, expected } => write!(
                formatter,
                "CometBFT Ed25519 public key has {actual} bytes; expected {expected}"
            ),
            Self::InvalidCometValidatorVotingPower(value) => write!(
                formatter,
                "CometBFT validator voting power must be positive and at most {COMET_BFT_MAX_TOTAL_VOTING_POWER}, received {value}"
            ),
            Self::CometValidatorVotingPowerTooLarge { actual, maximum } => write!(
                formatter,
                "CometBFT validator voting power {actual} exceeds maximum {maximum}"
            ),
            Self::CometTotalVotingPowerTooLarge { actual, maximum } => write!(
                formatter,
                "CometBFT total validator voting power {actual} exceeds maximum {maximum}"
            ),
            Self::DuplicateCometValidatorAddress => {
                formatter.write_str("two Noxis validators map to the same CometBFT address")
            }
            Self::UnexpectedNextValidatorsHash => formatter.write_str(
                "CometBFT decision next validators hash differs from the genesis-bound validator set",
            ),
        }
    }
}

impl std::error::Error for EngineIdentityError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Validator, ValidatorSet, ValidatorVerificationKey};
    use noxis_types::ValidatorId;

    fn identity() -> CometBftNetworkIdentity {
        CometBftNetworkIdentity::new("noxis-devnet-1", 1, "cometbft-0.38", [7; 32]).unwrap()
    }

    fn validators() -> ValidatorSet {
        ValidatorSet::new(vec![
            Validator::new(
                ValidatorId::new([2; 32]),
                3,
                ValidatorVerificationKey::new(COMET_BFT_ED25519_SIGNATURE_SCHEME, vec![4; 32])
                    .unwrap(),
            )
            .unwrap(),
            Validator::new(
                ValidatorId::new([1; 32]),
                5,
                ValidatorVerificationKey::new(COMET_BFT_ED25519_SIGNATURE_SCHEME, vec![3; 32])
                    .unwrap(),
            )
            .unwrap(),
        ])
        .unwrap()
    }

    fn genesis() -> CometBftGenesis {
        CometBftGenesis::from_consensus_config(identity(), &validators()).unwrap()
    }

    #[test]
    fn round_trip_is_exact_and_canonical() {
        let identity = identity();
        let encoded = identity.encode();
        assert_eq!(
            decode_comet_bft_network_identity(&encoded).unwrap(),
            identity
        );
    }

    #[test]
    fn changes_to_every_network_field_change_encoding() {
        let baseline = identity().encode();
        assert_ne!(
            baseline,
            CometBftNetworkIdentity::new("noxis-devnet-2", 1, "cometbft-0.38", [7; 32])
                .unwrap()
                .encode()
        );
        assert_ne!(
            baseline,
            CometBftNetworkIdentity::new("noxis-devnet-1", 2, "cometbft-0.38", [7; 32])
                .unwrap()
                .encode()
        );
        assert_ne!(
            baseline,
            CometBftNetworkIdentity::new("noxis-devnet-1", 1, "cometbft-0.37", [7; 32])
                .unwrap()
                .encode()
        );
        assert_ne!(
            baseline,
            CometBftNetworkIdentity::new("noxis-devnet-1", 1, "cometbft-0.38", [8; 32])
                .unwrap()
                .encode()
        );
    }

    #[test]
    fn rejects_noncanonical_identity_values() {
        assert_eq!(
            CometBftNetworkIdentity::new("", 1, "cometbft-0.38", [0; 32]),
            Err(EngineIdentityError::InvalidChainId)
        );
        assert_eq!(
            CometBftNetworkIdentity::new("noxis", 0, "cometbft-0.38", [0; 32]),
            Err(EngineIdentityError::InvalidInitialHeight(0))
        );
        assert_eq!(
            CometBftNetworkIdentity::new("noxis", 1, "version with space", [0; 32]),
            Err(EngineIdentityError::InvalidCompatibilityVersion)
        );
    }

    #[test]
    fn decision_is_bound_to_exact_network_height_and_hashes() {
        let genesis = genesis();
        let decision =
            CometBftDecision::new(&genesis, 1, [9; 32], genesis.validators().hash()).unwrap();
        assert!(decision.validate_for(&genesis, 1).is_ok());
        assert!(matches!(
            decision.validate_for(&genesis, 2),
            Err(EngineIdentityError::DecisionHeightMismatch { .. })
        ));
        let other_identity =
            CometBftNetworkIdentity::new("other-network", 1, "cometbft-0.38", [7; 32]).unwrap();
        let other = CometBftGenesis::from_consensus_config(other_identity, &validators()).unwrap();
        assert_eq!(
            decision.validate_for(&other, 1),
            Err(EngineIdentityError::DecisionNetworkMismatch)
        );
        assert!(matches!(
            CometBftDecision::from_persisted([0; 32], 1, [9; 32], [10; 32]),
            Err(EngineIdentityError::ZeroDecisionNetworkId)
        ));
    }

    #[test]
    fn validator_mapping_uses_comet_order_address_and_hash() {
        let mapped = CometBftValidatorSet::from_noxis_validator_set(&validators()).unwrap();
        assert_eq!(mapped.validators().len(), 2);
        assert_eq!(mapped.validators()[0].voting_power(), 5);
        assert_eq!(
            mapped.validators()[0].address(),
            [
                0x64, 0x8a, 0xa5, 0xc5, 0x79, 0xfb, 0x30, 0xf3, 0x8a, 0xf7, 0x44, 0xd9, 0x7d, 0x6e,
                0xc8, 0x40, 0xc7, 0xa9, 0x12, 0x77,
            ]
        );
        assert_eq!(
            mapped.validators()[1].address(),
            [
                0x9f, 0x4f, 0xb6, 0x8f, 0x3e, 0x1d, 0xac, 0x82, 0x20, 0x2f, 0x9a, 0xa5, 0x81, 0xce,
                0x0b, 0xbf, 0x1f, 0x76, 0x5d, 0xf0,
            ]
        );
        assert_eq!(
            mapped.hash(),
            [
                0x50, 0x1f, 0xb8, 0xf9, 0x1c, 0x5f, 0xe2, 0xbe, 0x41, 0x0d, 0x94, 0xe1, 0x48, 0x20,
                0x94, 0x38, 0x67, 0xaa, 0x90, 0x22, 0xff, 0xd4, 0xee, 0x5d, 0x73, 0x46, 0xac, 0xcd,
                0x86, 0x8a, 0xf9, 0xd9,
            ]
        );
        assert_eq!(
            CometBftValidatorSet::from_noxis_validator_set(&validators()).unwrap(),
            mapped
        );
    }

    #[test]
    fn validator_mapping_rejects_non_comet_key_material() {
        let set = ValidatorSet::new(vec![
            Validator::new(
                ValidatorId::new([1; 32]),
                1,
                ValidatorVerificationKey::new(2, vec![9; 32]).unwrap(),
            )
            .unwrap(),
        ])
        .unwrap();
        assert!(matches!(
            CometBftValidatorSet::from_noxis_validator_set(&set),
            Err(EngineIdentityError::UnsupportedCometValidatorSignatureScheme { .. })
        ));
    }
}
