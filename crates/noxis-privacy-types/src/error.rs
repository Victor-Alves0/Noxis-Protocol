use std::fmt;

/// A structurally invalid v2 public privacy value or encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivacyTypesError {
    InvalidIntentLength { actual: usize, expected: usize },
    DuplicateInputNullifier,
    DuplicateOutputCommitment,
    NonCanonicalBabyBearElement { index: usize, value: u32 },
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
            Self::NonCanonicalBabyBearElement { index, value } => write!(
                formatter,
                "private-transfer field element {index} is non-canonical: {value}"
            ),
        }
    }
}

impl std::error::Error for PrivacyTypesError {}
