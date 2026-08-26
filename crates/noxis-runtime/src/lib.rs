//! Local node-runtime initialization and genesis manifest persistence.
//!
//! This crate owns only a node's local directory contract. It does not start a
//! network service, make a transaction final, or replace consensus.

use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use noxis_config::{ConfigError, GenesisConfig, MAX_GENESIS_CONSENSUS_CONFIG_BYTES};
use noxis_consensus::{
    CometBftNetworkIdentity, MAX_COMET_BFT_NETWORK_IDENTITY_ENCODED_LENGTH,
    decode_comet_bft_network_identity, decode_consensus_config, encode_consensus_config,
};
use noxis_crypto::ValidationContext;
use noxis_types::{AssetDefinition, AssetError, AssetId, AssetKind, GenesisId};

/// File name for the active genesis manifest.
pub const MANIFEST_FILE_NAME: &str = "manifest.noxis";
/// File name for the immutable genesis copy.
pub const GENESIS_COPY_FILE_NAME: &str = "genesis.noxis";
/// File name of the durable, genesis-bound state-record history.
pub const LEDGER_FILE_NAME: &str = "ledger.nxrf";
/// Directory for immutable, non-authoritative checkpoint artifacts.
pub const CHECKPOINT_DIRECTORY_NAME: &str = "checkpoints";
/// File name used to exclude concurrent node-runtime instances.
pub const LOCK_FILE_NAME: &str = ".noxis.lock";

/// Fixed bytes identifying a Noxis node manifest.
pub const MANIFEST_MAGIC: [u8; 4] = *b"NXMF";
/// The only manifest layout accepted by this release.
pub const MANIFEST_FORMAT_VERSION: u16 = 6;
/// Bound on manifest asset entries, preventing unbounded allocation on open.
pub const MAX_MANIFEST_ASSETS: u32 = 4_096;
/// Bound for canonical consensus configuration included in the local manifest.
pub const MAX_MANIFEST_CONSENSUS_CONFIG_BYTES: usize = MAX_GENESIS_CONSENSUS_CONFIG_BYTES;
/// Largest possible v6 manifest, including its bounded consensus configuration
/// and optional canonical CometBFT identity.
pub const MAX_MANIFEST_BYTES: usize = 120
    + MAX_COMET_BFT_NETWORK_IDENTITY_ENCODED_LENGTH
    + MAX_MANIFEST_CONSENSUS_CONFIG_BYTES
    + MAX_MANIFEST_ASSETS as usize * 50;

const ASSET_KIND_NATIVE_BACKED: u8 = 1;
const ASSET_KIND_SYNTHETIC: u8 = 2;

/// A path designated for Noxis node-local state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataDirectory {
    root: PathBuf,
}

impl DataDirectory {
    /// Validates a data-directory path without accessing the filesystem.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, RuntimeError> {
        let root = root.into();
        if root.as_os_str().is_empty() {
            return Err(RuntimeError::EmptyDataDirectoryPath);
        }
        Ok(Self { root })
    }

    /// Returns the configured directory path.
    pub fn path(&self) -> &Path {
        &self.root
    }

    /// Returns the manifest path within this directory.
    pub fn manifest_path(&self) -> PathBuf {
        self.root.join(MANIFEST_FILE_NAME)
    }

    /// Returns the immutable genesis-copy path within this directory.
    pub fn genesis_copy_path(&self) -> PathBuf {
        self.root.join(GENESIS_COPY_FILE_NAME)
    }

    /// Returns the durable record-log path controlled by this data directory.
    pub fn ledger_path(&self) -> PathBuf {
        self.root.join(LEDGER_FILE_NAME)
    }

    /// Returns the protected directory for checkpoint artifacts.
    pub fn checkpoints_path(&self) -> PathBuf {
        self.root.join(CHECKPOINT_DIRECTORY_NAME)
    }

    /// Returns the exclusive-runtime lock path within this directory.
    pub fn lock_path(&self) -> PathBuf {
        self.root.join(LOCK_FILE_NAME)
    }
}

/// The durable, versioned description of a node's initial state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeManifest {
    genesis: GenesisConfig,
    genesis_id: GenesisId,
}

impl NodeManifest {
    /// Creates a manifest from already validated genesis configuration.
    pub fn from_genesis(genesis: GenesisConfig) -> Result<Self, ManifestError> {
        let asset_count = genesis.assets().len();
        if asset_count > MAX_MANIFEST_ASSETS as usize {
            return Err(ManifestError::TooManyAssets {
                actual: asset_count,
                maximum: MAX_MANIFEST_ASSETS,
            });
        }
        let consensus_bytes = encode_consensus_config(genesis.consensus_config());
        if consensus_bytes.len() > MAX_MANIFEST_CONSENSUS_CONFIG_BYTES {
            return Err(ManifestError::ConsensusConfigTooLarge {
                actual: consensus_bytes.len(),
                maximum: MAX_MANIFEST_CONSENSUS_CONFIG_BYTES,
            });
        }
        let genesis_id = genesis.genesis_id();
        Ok(Self {
            genesis,
            genesis_id,
        })
    }

    /// Returns the version for this encoded manifest format.
    pub const fn format_version(&self) -> u16 {
        MANIFEST_FORMAT_VERSION
    }

    /// Returns the immutable genesis configuration represented by this manifest.
    pub fn genesis(&self) -> &GenesisConfig {
        &self.genesis
    }

    /// Returns the canonical identity of the persisted genesis configuration.
    pub const fn genesis_id(&self) -> GenesisId {
        self.genesis_id
    }

    /// Returns the deterministic binary representation of this manifest.
    pub fn encode(&self) -> Vec<u8> {
        let assets = self.genesis.assets();
        debug_assert!(assets.len() <= MAX_MANIFEST_ASSETS as usize);

        let consensus_bytes = encode_consensus_config(self.genesis.consensus_config());
        debug_assert!(consensus_bytes.len() <= MAX_MANIFEST_CONSENSUS_CONFIG_BYTES);
        let comet_identity_bytes = self
            .genesis
            .comet_bft_identity()
            .map(CometBftNetworkIdentity::encode);
        let mut bytes = Vec::with_capacity(
            120 + consensus_bytes.len()
                + comet_identity_bytes.as_ref().map_or(0, Vec::len)
                + assets.len() * 50,
        );
        bytes.extend_from_slice(&MANIFEST_MAGIC);
        bytes.extend_from_slice(&MANIFEST_FORMAT_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.genesis_id.0);
        bytes.extend_from_slice(&self.genesis.validation_context().encode());
        bytes.extend_from_slice(&(consensus_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&consensus_bytes);
        match comet_identity_bytes {
            Some(identity) => {
                bytes.push(1);
                bytes.extend_from_slice(&(identity.len() as u16).to_be_bytes());
                bytes.extend_from_slice(&identity);
            }
            None => bytes.push(0),
        }
        bytes.push(self.genesis.tree_depth());
        bytes.extend_from_slice(&(assets.len() as u32).to_be_bytes());
        for asset in assets {
            bytes.extend_from_slice(&asset.id.0);
            bytes.push(encode_asset_kind(asset.kind));
            bytes.push(asset.ticker.len() as u8);
            bytes.extend_from_slice(asset.ticker.as_bytes());
        }
        bytes
    }

    /// Decodes exactly one canonical manifest and revalidates its domain fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, ManifestError> {
        let mut reader = ManifestReader::new(bytes);
        if reader.read_array::<4>()? != MANIFEST_MAGIC {
            return Err(ManifestError::InvalidMagic);
        }
        let version = reader.read_u16()?;
        if version != MANIFEST_FORMAT_VERSION {
            return Err(ManifestError::UnsupportedFormatVersion(version));
        }
        let encoded_genesis_id = GenesisId::new(reader.read_array()?);
        let validation_context =
            ValidationContext::decode(reader.read_exact(ValidationContext::ENCODED_LENGTH)?)
                .map_err(ManifestError::InvalidValidationContext)?;
        let consensus_length = reader.read_u32()? as usize;
        if consensus_length > MAX_MANIFEST_CONSENSUS_CONFIG_BYTES {
            return Err(ManifestError::ConsensusConfigTooLarge {
                actual: consensus_length,
                maximum: MAX_MANIFEST_CONSENSUS_CONFIG_BYTES,
            });
        }
        let consensus_config = decode_consensus_config(reader.read_exact(consensus_length)?)
            .map_err(ManifestError::InvalidConsensusConfig)?;
        let comet_bft_identity = match reader.read_u8()? {
            0 => None,
            1 => {
                let length = reader.read_u16()? as usize;
                if length > MAX_COMET_BFT_NETWORK_IDENTITY_ENCODED_LENGTH {
                    return Err(ManifestError::CometBftIdentityTooLarge {
                        actual: length,
                        maximum: MAX_COMET_BFT_NETWORK_IDENTITY_ENCODED_LENGTH,
                    });
                }
                Some(
                    decode_comet_bft_network_identity(reader.read_exact(length)?)
                        .map_err(ManifestError::InvalidCometBftIdentity)?,
                )
            }
            tag => return Err(ManifestError::UnknownCometBftIdentityTag(tag)),
        };
        let tree_depth = reader.read_u8()?;
        let asset_count = reader.read_u32()?;
        if asset_count > MAX_MANIFEST_ASSETS {
            return Err(ManifestError::TooManyAssets {
                actual: asset_count as usize,
                maximum: MAX_MANIFEST_ASSETS,
            });
        }

        let mut assets = Vec::with_capacity(asset_count as usize);
        for index in 0..asset_count {
            let id = AssetId::new(reader.read_array()?);
            let kind = decode_asset_kind(reader.read_u8()?)?;
            let ticker_length = reader.read_u8()? as usize;
            let ticker_bytes = reader.read_exact(ticker_length)?;
            let ticker = std::str::from_utf8(ticker_bytes)
                .map_err(|_| ManifestError::InvalidTickerEncoding { index })?;
            let asset = AssetDefinition::new(id, ticker, kind)
                .map_err(|error| ManifestError::InvalidAsset { index, error })?;
            assets.push(asset);
        }
        reader.finish()?;
        let genesis = match comet_bft_identity {
            Some(identity) => GenesisConfig::new_with_comet_bft_identity(
                tree_depth,
                assets,
                validation_context,
                consensus_config,
                identity,
            ),
            None => GenesisConfig::new(tree_depth, assets, validation_context, consensus_config),
        }
        .map_err(ManifestError::InvalidGenesis)?;
        let computed_genesis_id = genesis.genesis_id();
        if encoded_genesis_id != computed_genesis_id {
            return Err(ManifestError::GenesisIdMismatch {
                encoded: encoded_genesis_id,
                computed: computed_genesis_id,
            });
        }
        let manifest = Self {
            genesis,
            genesis_id: encoded_genesis_id,
        };
        if manifest.encode() != bytes {
            return Err(ManifestError::NonCanonicalEncoding);
        }
        Ok(manifest)
    }
}

/// A node runtime that holds an exclusive lock for the lifetime of its process.
#[derive(Debug)]
pub struct NodeRuntime {
    data_directory: DataDirectory,
    manifest: NodeManifest,
    _lock: DirectoryLock,
}

impl NodeRuntime {
    /// Opens an existing directory or initializes a new one from `genesis`.
    ///
    /// Existing files are never overwritten. Both the active manifest and the
    /// genesis copy must be present, valid, identical, and equal to `genesis`.
    pub fn open_or_initialize(
        data_directory: DataDirectory,
        genesis: GenesisConfig,
    ) -> Result<Self, RuntimeError> {
        ensure_directory(&data_directory)?;
        let lock = DirectoryLock::acquire(data_directory.lock_path())?;
        let expected =
            NodeManifest::from_genesis(genesis).map_err(RuntimeError::InvalidGenesisForManifest)?;
        let manifest_path = data_directory.manifest_path();
        let genesis_copy_path = data_directory.genesis_copy_path();
        let manifest_exists = path_exists(&manifest_path)?;
        let genesis_copy_exists = path_exists(&genesis_copy_path)?;

        let manifest = match (manifest_exists, genesis_copy_exists) {
            (false, false) => {
                let encoded = expected.encode();
                write_new_file(&genesis_copy_path, &encoded)?;
                write_new_file(&manifest_path, &encoded)?;
                expected
            }
            (true, true) => {
                let stored_manifest = read_manifest(&manifest_path)?;
                let genesis_copy = read_manifest(&genesis_copy_path)?;
                if stored_manifest != genesis_copy {
                    return Err(RuntimeError::ManifestGenesisCopyMismatch);
                }
                if stored_manifest != expected {
                    return Err(RuntimeError::GenesisMismatch);
                }
                stored_manifest
            }
            _ => return Err(RuntimeError::IncompleteDataDirectory),
        };

        ensure_checkpoint_directory(&data_directory)?;

        Ok(Self {
            data_directory,
            manifest,
            _lock: lock,
        })
    }

    /// Returns the directory held exclusively by this runtime.
    pub fn data_directory(&self) -> &DataDirectory {
        &self.data_directory
    }

    /// Returns the durable genesis manifest for this runtime.
    pub fn manifest(&self) -> &NodeManifest {
        &self.manifest
    }

    /// Returns the genesis identity verified for this locked data directory.
    pub const fn genesis_id(&self) -> GenesisId {
        self.manifest.genesis_id()
    }

    /// Returns the protected durable record-log path for this runtime.
    pub fn ledger_path(&self) -> PathBuf {
        self.data_directory.ledger_path()
    }

    /// Returns the checkpoint directory held inside this locked runtime.
    pub fn checkpoints_path(&self) -> PathBuf {
        self.data_directory.checkpoints_path()
    }
}

#[derive(Debug)]
struct DirectoryLock {
    file: Option<File>,
    path: PathBuf,
}

impl DirectoryLock {
    fn acquire(path: PathBuf) -> Result<Self, RuntimeError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists {
                    RuntimeError::DirectoryAlreadyLocked(path.clone())
                } else {
                    RuntimeError::io("create runtime lock", path.clone(), error)
                }
            })?;
        Ok(Self {
            file: Some(file),
            path,
        })
    }
}

impl Drop for DirectoryLock {
    fn drop(&mut self) {
        // Close before deletion so Windows can release its file handle first.
        drop(self.file.take());
        let _ = fs::remove_file(&self.path);
    }
}

fn ensure_directory(data_directory: &DataDirectory) -> Result<(), RuntimeError> {
    fs::create_dir_all(data_directory.path()).map_err(|error| {
        RuntimeError::io(
            "create data directory",
            data_directory.path().to_path_buf(),
            error,
        )
    })?;
    let metadata = fs::metadata(data_directory.path()).map_err(|error| {
        RuntimeError::io(
            "inspect data directory",
            data_directory.path().to_path_buf(),
            error,
        )
    })?;
    if !metadata.is_dir() {
        return Err(RuntimeError::DataDirectoryIsNotDirectory(
            data_directory.path().to_path_buf(),
        ));
    }
    Ok(())
}

fn ensure_checkpoint_directory(data_directory: &DataDirectory) -> Result<(), RuntimeError> {
    let path = data_directory.checkpoints_path();
    fs::create_dir_all(&path)
        .map_err(|error| RuntimeError::io("create checkpoint directory", path.clone(), error))?;
    let metadata = fs::metadata(&path)
        .map_err(|error| RuntimeError::io("inspect checkpoint directory", path.clone(), error))?;
    if metadata.is_dir() {
        Ok(())
    } else {
        Err(RuntimeError::CheckpointDirectoryIsNotDirectory(path))
    }
}

fn path_exists(path: &Path) -> Result<bool, RuntimeError> {
    match fs::metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(RuntimeError::io(
            "inspect runtime file",
            path.to_path_buf(),
            error,
        )),
    }
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), RuntimeError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| RuntimeError::io("create runtime file", path.to_path_buf(), error))?;
    file.write_all(bytes)
        .map_err(|error| RuntimeError::io("write runtime file", path.to_path_buf(), error))?;
    file.sync_all()
        .map_err(|error| RuntimeError::io("sync runtime file", path.to_path_buf(), error))
}

fn read_manifest(path: &Path) -> Result<NodeManifest, RuntimeError> {
    let metadata = fs::metadata(path)
        .map_err(|error| RuntimeError::io("inspect manifest", path.to_path_buf(), error))?;
    if metadata.len() > MAX_MANIFEST_BYTES as u64 {
        return Err(RuntimeError::ManifestFileTooLarge {
            path: path.to_path_buf(),
            actual: metadata.len(),
            maximum: MAX_MANIFEST_BYTES,
        });
    }
    let bytes = fs::read(path)
        .map_err(|error| RuntimeError::io("read manifest", path.to_path_buf(), error))?;
    NodeManifest::decode(&bytes).map_err(|error| RuntimeError::InvalidManifest {
        path: path.to_path_buf(),
        error,
    })
}

fn encode_asset_kind(kind: AssetKind) -> u8 {
    match kind {
        AssetKind::NativeBacked => ASSET_KIND_NATIVE_BACKED,
        AssetKind::Synthetic => ASSET_KIND_SYNTHETIC,
    }
}

fn decode_asset_kind(tag: u8) -> Result<AssetKind, ManifestError> {
    match tag {
        ASSET_KIND_NATIVE_BACKED => Ok(AssetKind::NativeBacked),
        ASSET_KIND_SYNTHETIC => Ok(AssetKind::Synthetic),
        _ => Err(ManifestError::UnknownAssetKind(tag)),
    }
}

struct ManifestReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ManifestReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, ManifestError> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, ManifestError> {
        Ok(u16::from_be_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> Result<u32, ManifestError> {
        Ok(u32::from_be_bytes(self.read_array()?))
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], ManifestError> {
        self.read_exact(N)?
            .try_into()
            .map_err(|_| ManifestError::UnexpectedEnd {
                offset: self.offset,
            })
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], ManifestError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ManifestError::LengthOverflow)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(ManifestError::UnexpectedEnd {
                offset: self.offset,
            })?;
        self.offset = end;
        Ok(slice)
    }

    fn finish(self) -> Result<(), ManifestError> {
        let remaining = self.bytes.len().saturating_sub(self.offset);
        if remaining == 0 {
            Ok(())
        } else {
            Err(ManifestError::TrailingBytes { count: remaining })
        }
    }
}

/// A precise reason a binary node manifest is invalid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifestError {
    InvalidMagic,
    UnsupportedFormatVersion(u16),
    TooManyAssets {
        actual: usize,
        maximum: u32,
    },
    ConsensusConfigTooLarge {
        actual: usize,
        maximum: usize,
    },
    UnknownCometBftIdentityTag(u8),
    CometBftIdentityTooLarge {
        actual: usize,
        maximum: usize,
    },
    UnknownAssetKind(u8),
    InvalidTickerEncoding {
        index: u32,
    },
    InvalidAsset {
        index: u32,
        error: AssetError,
    },
    InvalidGenesis(ConfigError),
    InvalidValidationContext(noxis_crypto::ValidationContextError),
    InvalidConsensusConfig(noxis_consensus::ConsensusError),
    InvalidCometBftIdentity(noxis_consensus::EngineIdentityError),
    GenesisIdMismatch {
        encoded: GenesisId,
        computed: GenesisId,
    },
    NonCanonicalEncoding,
    UnexpectedEnd {
        offset: usize,
    },
    TrailingBytes {
        count: usize,
    },
    LengthOverflow,
}

impl fmt::Display for ManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => formatter.write_str("invalid node manifest magic bytes"),
            Self::UnsupportedFormatVersion(version) => {
                write!(
                    formatter,
                    "unsupported node manifest format version {version}"
                )
            }
            Self::TooManyAssets { actual, maximum } => {
                write!(
                    formatter,
                    "manifest has {actual} assets, above maximum {maximum}"
                )
            }
            Self::ConsensusConfigTooLarge { actual, maximum } => write!(
                formatter,
                "manifest consensus configuration has {actual} bytes, above maximum {maximum}"
            ),
            Self::UnknownCometBftIdentityTag(tag) => {
                write!(formatter, "unknown CometBFT identity presence tag {tag}")
            }
            Self::CometBftIdentityTooLarge { actual, maximum } => write!(
                formatter,
                "manifest CometBFT identity has {actual} bytes, above maximum {maximum}"
            ),
            Self::UnknownAssetKind(kind) => write!(formatter, "unknown asset kind tag {kind}"),
            Self::InvalidTickerEncoding { index } => {
                write!(formatter, "asset {index} ticker is not valid UTF-8")
            }
            Self::InvalidAsset { index, error } => {
                write!(formatter, "asset {index} is invalid: {error}")
            }
            Self::InvalidGenesis(error) => {
                write!(formatter, "manifest genesis is invalid: {error}")
            }
            Self::InvalidValidationContext(error) => {
                write!(formatter, "manifest validation context is invalid: {error}")
            }
            Self::InvalidConsensusConfig(error) => {
                write!(
                    formatter,
                    "manifest consensus configuration is invalid: {error}"
                )
            }
            Self::InvalidCometBftIdentity(error) => {
                write!(formatter, "manifest CometBFT identity is invalid: {error}")
            }
            Self::GenesisIdMismatch { .. } => formatter.write_str(
                "manifest genesis identifier does not match its canonical genesis configuration",
            ),
            Self::NonCanonicalEncoding => {
                formatter.write_str("manifest does not use canonical asset ordering or encoding")
            }
            Self::UnexpectedEnd { offset } => {
                write!(formatter, "unexpected end of manifest at byte {offset}")
            }
            Self::TrailingBytes { count } => {
                write!(formatter, "manifest has {count} trailing byte(s)")
            }
            Self::LengthOverflow => {
                formatter.write_str("manifest length overflows platform bounds")
            }
        }
    }
}

impl std::error::Error for ManifestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidAsset { error, .. } => Some(error),
            Self::InvalidGenesis(error) => Some(error),
            Self::InvalidValidationContext(error) => Some(error),
            Self::InvalidConsensusConfig(error) => Some(error),
            Self::InvalidCometBftIdentity(error) => Some(error),
            _ => None,
        }
    }
}

/// Errors while establishing an exclusive, locally durable node runtime.
#[derive(Debug)]
pub enum RuntimeError {
    EmptyDataDirectoryPath,
    DataDirectoryIsNotDirectory(PathBuf),
    CheckpointDirectoryIsNotDirectory(PathBuf),
    DirectoryAlreadyLocked(PathBuf),
    IncompleteDataDirectory,
    GenesisMismatch,
    ManifestGenesisCopyMismatch,
    InvalidGenesisForManifest(ManifestError),
    ManifestFileTooLarge {
        path: PathBuf,
        actual: u64,
        maximum: usize,
    },
    InvalidManifest {
        path: PathBuf,
        error: ManifestError,
    },
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
}

impl RuntimeError {
    fn io(operation: &'static str, path: PathBuf, source: io::Error) -> Self {
        Self::Io {
            operation,
            path,
            source,
        }
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyDataDirectoryPath => formatter.write_str("data directory path cannot be empty"),
            Self::DataDirectoryIsNotDirectory(path) => {
                write!(formatter, "data directory path is not a directory: {}", path.display())
            }
            Self::CheckpointDirectoryIsNotDirectory(path) => {
                write!(formatter, "checkpoint path is not a directory: {}", path.display())
            }
            Self::DirectoryAlreadyLocked(path) => {
                write!(formatter, "data directory is already locked: {}", path.display())
            }
            Self::IncompleteDataDirectory => formatter.write_str(
                "data directory has only one of manifest.noxis and genesis.noxis; refusing recovery",
            ),
            Self::GenesisMismatch => formatter.write_str(
                "existing node manifest does not match requested genesis; refusing to overwrite it",
            ),
            Self::ManifestGenesisCopyMismatch => formatter.write_str(
                "node manifest and immutable genesis copy do not match",
            ),
            Self::InvalidGenesisForManifest(error) => {
                write!(formatter, "requested genesis cannot be persisted: {error}")
            }
            Self::ManifestFileTooLarge {
                path,
                actual,
                maximum,
            } => write!(
                formatter,
                "manifest at {} is {actual} bytes, above maximum {maximum}",
                path.display()
            ),
            Self::InvalidManifest { path, error } => {
                write!(formatter, "invalid manifest at {}: {error}", path.display())
            }
            Self::Io { operation, path, source } => {
                write!(formatter, "cannot {operation} at {}: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for RuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidGenesisForManifest(error) => Some(error),
            Self::InvalidManifest { error, .. } => Some(error),
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use noxis_consensus::{
        CometBftNetworkIdentity, ConsensusConfig, Validator, ValidatorSet, ValidatorVerificationKey,
    };
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use noxis_crypto::CryptoSuite;
    use noxis_types::{AssetKind, MintPolicyId, ProofVerifierId, ValidatorId};

    use super::*;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn asset(id: u8, ticker: &str) -> AssetDefinition {
        AssetDefinition::new(AssetId::new([id; 32]), ticker, AssetKind::Synthetic).unwrap()
    }

    fn consensus_config() -> ConsensusConfig {
        ConsensusConfig::new(
            1,
            100,
            1024,
            0,
            ValidatorSet::new(vec![
                Validator::new(
                    ValidatorId::new([1; 32]),
                    1,
                    ValidatorVerificationKey::new(1, vec![1; 32]).unwrap(),
                )
                .unwrap(),
            ])
            .unwrap(),
        )
        .unwrap()
    }

    fn genesis(depth: u8, id: u8) -> GenesisConfig {
        genesis_with_context(
            depth,
            id,
            ProofVerifierId::new([1; 32]),
            MintPolicyId::new([0; 32]),
        )
    }

    fn genesis_with_context(
        depth: u8,
        id: u8,
        proof_verifier_id: ProofVerifierId,
        mint_policy_id: MintPolicyId,
    ) -> GenesisConfig {
        GenesisConfig::new(
            depth,
            vec![asset(id, "USDX")],
            ValidationContext::new(CryptoSuite::RESEARCH_V1, proof_verifier_id, mint_policy_id),
            consensus_config(),
        )
        .unwrap()
    }

    fn temporary_directory(label: &str) -> PathBuf {
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "noxis-runtime-{label}-{}-{nanos}-{sequence}",
            std::process::id()
        ))
    }

    fn clean_up(path: &Path) {
        if path.exists() {
            fs::remove_dir_all(path).unwrap();
        }
    }

    #[test]
    fn manifest_round_trip_is_exact_and_canonical() {
        let manifest = NodeManifest::from_genesis(genesis(4, 1)).unwrap();
        let encoded = manifest.encode();
        assert_eq!(NodeManifest::decode(&encoded).unwrap(), manifest);
        assert_eq!(NodeManifest::decode(&encoded).unwrap().encode(), encoded);
        assert_eq!(manifest.genesis_id(), manifest.genesis().genesis_id());
    }

    #[test]
    fn manifest_round_trips_a_genesis_bound_comet_identity() {
        let genesis = GenesisConfig::new_with_comet_bft_identity(
            4,
            vec![asset(1, "USDX")],
            ValidationContext::new(
                CryptoSuite::RESEARCH_V1,
                ProofVerifierId::new([1; 32]),
                MintPolicyId::new([0; 32]),
            ),
            consensus_config(),
            CometBftNetworkIdentity::new("noxis-runtime-test", 1, "cometbft-0.38", [7; 32])
                .unwrap(),
        )
        .unwrap();
        let encoded = NodeManifest::from_genesis(genesis.clone())
            .unwrap()
            .encode();
        let decoded = NodeManifest::decode(&encoded).unwrap();
        assert_eq!(decoded.genesis(), &genesis);
        assert_eq!(
            decoded.genesis().comet_bft_identity(),
            genesis.comet_bft_identity()
        );
    }

    #[test]
    fn manifest_rejects_unknown_values_and_trailing_bytes() {
        let manifest = NodeManifest::from_genesis(genesis(3, 2)).unwrap();
        let mut encoded = manifest.encode();
        encoded[4] = 0;
        encoded[5] = 2;
        assert_eq!(
            NodeManifest::decode(&encoded),
            Err(ManifestError::UnsupportedFormatVersion(2))
        );

        let mut encoded = manifest.encode();
        encoded.push(0);
        assert_eq!(
            NodeManifest::decode(&encoded),
            Err(ManifestError::TrailingBytes { count: 1 })
        );

        let mut encoded = manifest.encode();
        let kind_offset = 4
            + 2
            + 32
            + ValidationContext::ENCODED_LENGTH
            + 4
            + encode_consensus_config(manifest.genesis().consensus_config()).len()
            + 1
            + 1
            + 4
            + 32;
        encoded[kind_offset] = 99;
        assert_eq!(
            NodeManifest::decode(&encoded),
            Err(ManifestError::UnknownAssetKind(99))
        );
    }

    #[test]
    fn manifest_rejects_a_forged_genesis_identifier() {
        let manifest = NodeManifest::from_genesis(genesis(3, 9)).unwrap();
        let mut encoded = manifest.encode();
        encoded[6] ^= 1;
        assert!(matches!(
            NodeManifest::decode(&encoded),
            Err(ManifestError::GenesisIdMismatch { .. })
        ));
    }

    #[test]
    fn manifest_rejects_noncanonical_asset_order_even_when_genesis_id_matches() {
        let configured = GenesisConfig::new(
            3,
            vec![asset(1, "USDX"), asset(2, "EURX")],
            ValidationContext::new(
                CryptoSuite::RESEARCH_V1,
                ProofVerifierId::new([1; 32]),
                MintPolicyId::new([0; 32]),
            ),
            consensus_config(),
        )
        .unwrap();
        let manifest = NodeManifest::from_genesis(configured).unwrap();
        let mut encoded = manifest.encode();
        let header = 4
            + 2
            + 32
            + ValidationContext::ENCODED_LENGTH
            + 4
            + encode_consensus_config(manifest.genesis().consensus_config()).len()
            + 1
            + 1
            + 4;
        const ASSET_BYTES: usize = 38;
        let first = encoded[header..header + ASSET_BYTES].to_vec();
        let second = encoded[header + ASSET_BYTES..header + ASSET_BYTES * 2].to_vec();
        encoded[header..header + ASSET_BYTES].copy_from_slice(&second);
        encoded[header + ASSET_BYTES..header + ASSET_BYTES * 2].copy_from_slice(&first);
        assert_eq!(
            NodeManifest::decode(&encoded),
            Err(ManifestError::NonCanonicalEncoding)
        );
    }

    #[test]
    fn initialization_writes_both_manifest_copies_and_reopens() {
        let directory_path = temporary_directory("initialize");
        let data_directory = DataDirectory::new(&directory_path).unwrap();
        let configured_genesis = genesis(4, 3);
        {
            let runtime =
                NodeRuntime::open_or_initialize(data_directory.clone(), configured_genesis.clone())
                    .unwrap();
            assert_eq!(runtime.manifest().genesis(), &configured_genesis);
            assert!(data_directory.manifest_path().is_file());
            assert!(data_directory.genesis_copy_path().is_file());
            assert!(data_directory.checkpoints_path().is_dir());
            assert!(data_directory.lock_path().is_file());
        }
        assert!(!data_directory.lock_path().exists());
        let reopened = NodeRuntime::open_or_initialize(data_directory, configured_genesis).unwrap();
        drop(reopened);
        clean_up(&directory_path);
    }

    #[test]
    fn exclusive_lock_is_released_on_drop() {
        let directory_path = temporary_directory("lock");
        let data_directory = DataDirectory::new(&directory_path).unwrap();
        let configured_genesis = genesis(3, 4);
        let runtime =
            NodeRuntime::open_or_initialize(data_directory.clone(), configured_genesis.clone())
                .unwrap();
        assert!(matches!(
            NodeRuntime::open_or_initialize(data_directory.clone(), configured_genesis.clone()),
            Err(RuntimeError::DirectoryAlreadyLocked(_))
        ));
        drop(runtime);
        NodeRuntime::open_or_initialize(data_directory, configured_genesis).unwrap();
        clean_up(&directory_path);
    }

    #[test]
    fn refuses_changed_or_incomplete_genesis_directory() {
        let directory_path = temporary_directory("mismatch");
        let data_directory = DataDirectory::new(&directory_path).unwrap();
        let runtime =
            NodeRuntime::open_or_initialize(data_directory.clone(), genesis(3, 5)).unwrap();
        drop(runtime);
        assert!(matches!(
            NodeRuntime::open_or_initialize(data_directory.clone(), genesis(3, 6)),
            Err(RuntimeError::GenesisMismatch)
        ));
        fs::remove_file(data_directory.genesis_copy_path()).unwrap();
        assert!(matches!(
            NodeRuntime::open_or_initialize(data_directory, genesis(3, 5)),
            Err(RuntimeError::IncompleteDataDirectory)
        ));
        clean_up(&directory_path);
    }

    #[test]
    fn refuses_a_directory_reopened_with_a_changed_validation_context() {
        let directory_path = temporary_directory("validation-context-mismatch");
        let data_directory = DataDirectory::new(&directory_path).unwrap();
        let original = genesis(3, 5);
        let runtime =
            NodeRuntime::open_or_initialize(data_directory.clone(), original.clone()).unwrap();
        drop(runtime);
        let manifest_before = fs::read(data_directory.manifest_path()).unwrap();
        let changed = genesis_with_context(
            3,
            5,
            ProofVerifierId::new([9; 32]),
            MintPolicyId::new([0; 32]),
        );

        assert!(matches!(
            NodeRuntime::open_or_initialize(data_directory.clone(), changed),
            Err(RuntimeError::GenesisMismatch)
        ));
        assert_eq!(
            fs::read(data_directory.manifest_path()).unwrap(),
            manifest_before
        );
        clean_up(&directory_path);
    }

    #[test]
    fn refuses_a_valid_but_different_genesis_copy() {
        let directory_path = temporary_directory("copy-mismatch");
        let data_directory = DataDirectory::new(&directory_path).unwrap();
        let original = genesis(3, 7);
        let runtime =
            NodeRuntime::open_or_initialize(data_directory.clone(), original.clone()).unwrap();
        drop(runtime);
        let replacement = NodeManifest::from_genesis(genesis(3, 8)).unwrap().encode();
        fs::write(data_directory.genesis_copy_path(), replacement).unwrap();

        assert!(matches!(
            NodeRuntime::open_or_initialize(data_directory.clone(), original),
            Err(RuntimeError::ManifestGenesisCopyMismatch)
        ));
        clean_up(&directory_path);
    }

    #[test]
    fn empty_data_directory_path_is_rejected() {
        assert!(matches!(
            DataDirectory::new(PathBuf::new()),
            Err(RuntimeError::EmptyDataDirectoryPath)
        ));
    }
}
