use std::fmt;

macro_rules! fixed_public_bytes {
    ($name:ident, $length:expr, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; $length]);

        impl $name {
            pub const LENGTH: usize = $length;

            pub const fn new(bytes: [u8; $length]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(self) -> [u8; $length] {
                self.0
            }
        }

        impl From<[u8; $length]> for $name {
            fn from(bytes: [u8; $length]) -> Self {
                Self::new(bytes)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in self.0 {
                    write!(formatter, "{byte:02x}")?;
                }
                Ok(())
            }
        }
    };
}

fixed_public_bytes!(
    CircuitId,
    32,
    "Public identity of one frozen v2 circuit and verifier program."
);
fixed_public_bytes!(
    TreeParametersId,
    32,
    "Public identity of frozen v2 tree and field parameters."
);
fixed_public_bytes!(
    CiphertextDigestV2,
    64,
    "Canonical two-field-element digest binding one recipient envelope to an output."
);
fixed_public_bytes!(
    NoteCommitmentV2,
    64,
    "Canonical two-field-element encoding of a v2 note commitment."
);
fixed_public_bytes!(
    NullifierV2,
    64,
    "Canonical two-field-element encoding of a v2 nullifier."
);
fixed_public_bytes!(
    MerkleRootV2,
    64,
    "Canonical two-field-element encoding of a v2 Merkle root."
);
