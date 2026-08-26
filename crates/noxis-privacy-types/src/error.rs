use std::fmt;

/// A structurally invalid v2 public privacy value or encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivacyTypesError {
    InvalidIntentLength { actual: usize, expected: usize },
    DuplicateInputNullifier,
    DuplicateOutputCommitment,
}

impl fmt::Display for PrivacyTypesError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIntentLength { actual, expected } => write!(
                formatter,
                "private-transfer intent has {actual} bytes; expected {expected}"
            ),
            Self::DuplicateInputNullifier => {
                formatter.write_str("private-transfer intent repeats an input nullifier")
            }
            Self::DuplicateOutputCommitment => {
                formatter.write_str("private-transfer intent repeats an output commitment")
            }
        }
    }
}

impl std::error::Error for PrivacyTypesError {}
