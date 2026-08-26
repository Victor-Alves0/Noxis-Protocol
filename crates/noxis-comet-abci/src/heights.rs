use std::fmt;

use noxis_consensus::{CometBftGenesis, CometBftNetworkIdentity, EngineIdentityError};

/// Immutable, genesis-bound CometBFT identity used by this application.
///
/// The value is supplied only by the execution context reconstructed from the
/// persisted Noxis genesis. The ABCI adapter never gets to invent it from a
/// socket request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CometIdentity(CometBftGenesis);

impl CometIdentity {
    pub fn from_genesis(genesis: CometBftGenesis) -> Self {
        Self(genesis)
    }

    pub fn chain_id(&self) -> &str {
        self.0.identity().chain_id()
    }

    pub fn initial_height(&self) -> i64 {
        self.0.identity().initial_height()
    }

    pub fn compatibility_version(&self) -> &str {
        self.0.identity().compatibility_version()
    }

    pub fn parameters_sha256(&self) -> [u8; 32] {
        self.0.identity().parameters_sha256()
    }

    pub fn engine_identity(&self) -> &CometBftNetworkIdentity {
        self.0.identity()
    }

    pub fn engine_genesis(&self) -> &CometBftGenesis {
        &self.0
    }

    pub fn noxis_height(&self, engine_height: i64) -> Result<u64, HeightMappingError> {
        let relative = engine_height.checked_sub(self.initial_height()).ok_or(
            HeightMappingError::EngineHeightBeforeGenesis {
                initial: self.initial_height(),
                actual: engine_height,
            },
        )?;
        let height = relative
            .checked_add(1)
            .ok_or(HeightMappingError::HeightOverflow)?;
        u64::try_from(height).map_err(|_| HeightMappingError::HeightOverflow)
    }

    pub fn engine_height(&self, noxis_height: u64) -> Result<i64, HeightMappingError> {
        self.0
            .identity()
            .engine_height_for(noxis_height)
            .map_err(HeightMappingError::Engine)
    }
}

/// A Comet/Noxis height cannot be interpreted safely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeightMappingError {
    EngineHeightBeforeGenesis { initial: i64, actual: i64 },
    HeightOverflow,
    Engine(EngineIdentityError),
}

impl fmt::Display for HeightMappingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EngineHeightBeforeGenesis { initial, actual } => write!(
                formatter,
                "Comet height {actual} precedes configured initial height {initial}"
            ),
            Self::HeightOverflow => formatter.write_str("engine/Noxis height conversion overflows"),
            Self::Engine(error) => write!(formatter, "invalid engine height mapping: {error}"),
        }
    }
}

impl std::error::Error for HeightMappingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Engine(error) => Some(error),
            Self::EngineHeightBeforeGenesis { .. } | Self::HeightOverflow => None,
        }
    }
}
