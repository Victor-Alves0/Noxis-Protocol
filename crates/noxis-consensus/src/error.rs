use std::fmt;

/// Reasons consensus data cannot be accepted as canonical or final.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsensusError {
    InvalidMagic,
    UnsupportedFormatVersion(u16),
    UnexpectedEnd { offset: usize },
    TrailingBytes { count: usize },
    LengthOverflow,
    InvalidProtocolVersion,
    InvalidMaximumBlockRecords,
    InvalidMaximumBlockTransactionBytes { actual: u32, maximum: u32 },
    ByzantineFaultPowerExceedsSafetyLimit { declared: u64, maximum: u64 },
    EmptyValidatorSet,
    TooManyValidators { actual: usize, maximum: usize },
    ZeroVotingPower,
    InvalidSignatureScheme,
    EmptyValidatorKey,
    ValidatorKeyTooLarge { actual: usize, maximum: usize },
    DuplicateValidator,
    NonCanonicalValidatorOrder,
    VotingPowerOverflow,
    InvalidBlockHeight,
    MissingParentBlock,
    UnexpectedParentBlock,
    InvalidFirstRecordSequence,
    RecordCountMismatch { expected: u32, actual: usize },
    RecordCountExceedsConfiguredMaximum { actual: u32, maximum: u32 },
    RecordSequenceOverflow,
    TooManyCommittedRecords { actual: usize, maximum: usize },
    RecordCommitmentMismatch,
    ConsensusConfigMismatch,
    ValidatorSetMismatch,
    BlockFormatMismatch,
    GenesisMismatch,
    ValidationContextMismatch,
    GenesisStateMismatch,
    EmptyCertificate,
    TooManyVotes { actual: usize, maximum: usize },
    SignatureTooLarge { actual: usize, maximum: usize },
    EmptySignature,
    DuplicateVote,
    NonCanonicalVoteOrder,
    CertificateTargetMismatch,
    UnknownValidator,
    InsufficientVotingPower { signed: u64, required: u64 },
    InvalidSignature { validator: noxis_types::ValidatorId },
}

impl fmt::Display for ConsensusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => formatter.write_str("invalid consensus magic bytes"),
            Self::UnsupportedFormatVersion(version) => {
                write!(formatter, "unsupported consensus format version {version}")
            }
            Self::UnexpectedEnd { offset } => {
                write!(
                    formatter,
                    "unexpected end of consensus data at byte {offset}"
                )
            }
            Self::TrailingBytes { count } => {
                write!(formatter, "consensus data has {count} trailing byte(s)")
            }
            Self::LengthOverflow => {
                formatter.write_str("consensus length overflows platform bounds")
            }
            Self::InvalidProtocolVersion => formatter.write_str("protocol version must be nonzero"),
            Self::InvalidMaximumBlockRecords => {
                formatter.write_str("maximum records per block must be nonzero")
            }
            Self::InvalidMaximumBlockTransactionBytes { actual, maximum } => write!(
                formatter,
                "maximum block transaction bytes {actual} must be between 1 and {maximum}"
            ),
            Self::ByzantineFaultPowerExceedsSafetyLimit { declared, maximum } => write!(
                formatter,
                "declared Byzantine fault power {declared} exceeds safety limit {maximum}"
            ),
            Self::EmptyValidatorSet => formatter.write_str("validator set must not be empty"),
            Self::TooManyValidators { actual, maximum } => write!(
                formatter,
                "validator set contains {actual} validators, exceeding maximum {maximum}"
            ),
            Self::ZeroVotingPower => formatter.write_str("validator voting power must be nonzero"),
            Self::InvalidSignatureScheme => {
                formatter.write_str("validator signature scheme identifier must be nonzero")
            }
            Self::EmptyValidatorKey => {
                formatter.write_str("validator public key must not be empty")
            }
            Self::ValidatorKeyTooLarge { actual, maximum } => write!(
                formatter,
                "validator public key has {actual} bytes, exceeding maximum {maximum}"
            ),
            Self::DuplicateValidator => formatter.write_str("validator appears more than once"),
            Self::NonCanonicalValidatorOrder => {
                formatter.write_str("validator entries are not in canonical order")
            }
            Self::VotingPowerOverflow => {
                formatter.write_str("validator voting power overflows u64")
            }
            Self::InvalidBlockHeight => formatter.write_str("block height must be nonzero"),
            Self::MissingParentBlock => {
                formatter.write_str("a non-initial block must identify its parent")
            }
            Self::UnexpectedParentBlock => {
                formatter.write_str("the initial block must not identify a parent")
            }
            Self::InvalidFirstRecordSequence => {
                formatter.write_str("first record sequence must be nonzero")
            }
            Self::RecordCountMismatch { expected, actual } => write!(
                formatter,
                "block declares {expected} records, but received {actual} record hashes"
            ),
            Self::RecordCountExceedsConfiguredMaximum { actual, maximum } => write!(
                formatter,
                "block contains {actual} records, exceeding configured maximum {maximum}"
            ),
            Self::RecordSequenceOverflow => {
                formatter.write_str("block record sequence range overflows u64")
            }
            Self::TooManyCommittedRecords { actual, maximum } => write!(
                formatter,
                "record commitment has {actual} records, exceeding maximum {maximum}"
            ),
            Self::RecordCommitmentMismatch => {
                formatter.write_str("record hashes do not match the block commitment")
            }
            Self::ConsensusConfigMismatch => {
                formatter.write_str("block does not bind the supplied consensus configuration")
            }
            Self::ValidatorSetMismatch => {
                formatter.write_str("block does not bind the supplied validator set")
            }
            Self::BlockFormatMismatch => {
                formatter.write_str("block protocol version does not match configuration")
            }
            Self::GenesisMismatch => {
                formatter.write_str("block does not bind the expected genesis")
            }
            Self::ValidationContextMismatch => {
                formatter.write_str("block does not bind the expected validation context")
            }
            Self::GenesisStateMismatch => {
                formatter.write_str("initial block does not extend the expected genesis state")
            }
            Self::EmptyCertificate => {
                formatter.write_str("finality certificate must contain votes")
            }
            Self::TooManyVotes { actual, maximum } => write!(
                formatter,
                "certificate contains {actual} votes, exceeding maximum {maximum}"
            ),
            Self::SignatureTooLarge { actual, maximum } => write!(
                formatter,
                "vote signature has {actual} bytes, exceeding maximum {maximum}"
            ),
            Self::EmptySignature => formatter.write_str("vote signature must not be empty"),
            Self::DuplicateVote => {
                formatter.write_str("certificate contains more than one vote by a validator")
            }
            Self::NonCanonicalVoteOrder => {
                formatter.write_str("certificate votes are not in canonical validator order")
            }
            Self::CertificateTargetMismatch => {
                formatter.write_str("certificate target does not match the supplied block header")
            }
            Self::UnknownValidator => {
                formatter.write_str("certificate includes a validator outside the configured set")
            }
            Self::InsufficientVotingPower { signed, required } => write!(
                formatter,
                "certificate has voting power {signed}, but needs at least {required}"
            ),
            Self::InvalidSignature { validator } => {
                write!(
                    formatter,
                    "finality signature is invalid for validator {validator}"
                )
            }
        }
    }
}

impl std::error::Error for ConsensusError {}
