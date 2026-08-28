use std::fmt;

use crate::PrivacyTypesError;

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

/// Prime modulus of the BabyBear field used by the research tree representation.
pub const BABYBEAR_MODULUS: u32 = 2_013_265_921;
/// Number of canonical BabyBear elements in every 64-byte v2 field vector.
pub const BABYBEAR_ELEMENTS_PER_VALUE: usize = 16;
/// Byte width of the public v2 commitment, nullifier, root and digest values.
pub const BABYBEAR_VECTOR_BYTES: usize = BABYBEAR_ELEMENTS_PER_VALUE * 4;

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

macro_rules! canonical_babybear_vector {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; BABYBEAR_VECTOR_BYTES]);

        impl $name {
            pub const LENGTH: usize = BABYBEAR_VECTOR_BYTES;

            /// Accepts only sixteen canonical little-endian BabyBear elements.
            pub fn new(bytes: [u8; BABYBEAR_VECTOR_BYTES]) -> Result<Self, PrivacyTypesError> {
                validate_babybear_bytes(&bytes)?;
                Ok(Self(bytes))
            }

            /// Encodes exactly sixteen canonical BabyBear elements.
            pub fn from_elements(
                elements: [u32; BABYBEAR_ELEMENTS_PER_VALUE],
            ) -> Result<Self, PrivacyTypesError> {
                let mut bytes = [0_u8; BABYBEAR_VECTOR_BYTES];
                for (index, element) in elements.into_iter().enumerate() {
                    if element >= BABYBEAR_MODULUS {
                        return Err(PrivacyTypesError::NonCanonicalBabyBearElement {
                            index,
                            value: element,
                        });
                    }
                    bytes[index * 4..index * 4 + 4].copy_from_slice(&element.to_le_bytes());
                }
                Ok(Self(bytes))
            }

            pub const fn as_bytes(self) -> [u8; BABYBEAR_VECTOR_BYTES] {
                self.0
            }

            pub fn elements(self) -> [u32; BABYBEAR_ELEMENTS_PER_VALUE] {
                core::array::from_fn(|index| {
                    u32::from_le_bytes(
                        self.0[index * 4..index * 4 + 4]
                            .try_into()
                            .expect("fixed field element width"),
                    )
                })
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

canonical_babybear_vector!(
    CiphertextDigestV2,
    "Canonical sixteen-element BabyBear digest binding one recipient envelope to an output."
);
canonical_babybear_vector!(
    PrivateTransferIntentCommitmentV2,
    "Canonical sixteen-element BabyBear commitment to all 640 bytes of one v2 private-transfer intent."
);
canonical_babybear_vector!(
    NoteCommitmentV2,
    "Canonical sixteen-element BabyBear encoding of a v2 note commitment."
);
canonical_babybear_vector!(
    RecipientCommitmentV2,
    "Canonical sixteen-element BabyBear commitment to the recipient spending key."
);
canonical_babybear_vector!(
    NullifierV2,
    "Canonical sixteen-element BabyBear encoding of a v2 nullifier."
);
canonical_babybear_vector!(
    MerkleSiblingV2,
    "Canonical sixteen-element BabyBear value used as one private v2 Merkle-path sibling."
);
canonical_babybear_vector!(
    MerkleRootV2,
    "Canonical sixteen-element BabyBear encoding of a v2 Merkle root."
);

fn validate_babybear_bytes(bytes: &[u8; BABYBEAR_VECTOR_BYTES]) -> Result<(), PrivacyTypesError> {
    for (index, chunk) in bytes.chunks_exact(4).enumerate() {
        let value = u32::from_le_bytes(chunk.try_into().expect("fixed field element width"));
        if value >= BABYBEAR_MODULUS {
            return Err(PrivacyTypesError::NonCanonicalBabyBearElement { index, value });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_vectors_round_trip_only_canonical_elements() {
        let values = core::array::from_fn(|index| index as u32 + 1);
        let commitment = NoteCommitmentV2::from_elements(values).unwrap();
        assert_eq!(commitment.elements(), values);
        assert_eq!(
            NoteCommitmentV2::new(commitment.as_bytes()).unwrap(),
            commitment
        );
    }

    #[test]
    fn field_vectors_reject_the_modulus_and_noncanonical_bytes() {
        let mut elements = [0_u32; BABYBEAR_ELEMENTS_PER_VALUE];
        elements[5] = BABYBEAR_MODULUS;
        assert_eq!(
            MerkleRootV2::from_elements(elements),
            Err(PrivacyTypesError::NonCanonicalBabyBearElement {
                index: 5,
                value: BABYBEAR_MODULUS,
            })
        );
        assert_eq!(
            PrivateTransferIntentCommitmentV2::from_elements([7; BABYBEAR_ELEMENTS_PER_VALUE])
                .unwrap()
                .elements(),
            [7; BABYBEAR_ELEMENTS_PER_VALUE]
        );
        assert_eq!(
            NullifierV2::new([255; BABYBEAR_VECTOR_BYTES]),
            Err(PrivacyTypesError::NonCanonicalBabyBearElement {
                index: 0,
                value: u32::MAX,
            })
        );
    }
}
