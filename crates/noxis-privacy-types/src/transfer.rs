use noxis_types::{AssetId, GenesisId, StateId, ValidationContextId};

use crate::{
    CiphertextDigestV2, CircuitId, MerkleRootV2, NoteCommitmentV2, NullifierV2, PrivacyTypesError,
    TreeParametersId,
};

/// Domain reserved for the future transaction-intent identifier calculation.
pub const PRIVATE_TRANSFER_V2_INTENT_DOMAIN: &[u8] = b"NOXIS/PRIVATE-TRANSFER-INTENT/V2\0";
const INPUT_COUNT: usize = 2;
const OUTPUT_COUNT: usize = 2;
/// The only tree depth accepted by the `PrivateTransferV2` circuit design.
pub const PRIVATE_TRANSFER_V2_TREE_DEPTH: u8 = 32;

/// Frozen public tree parameters required by a private-transfer proof.
///
/// The v2 protocol fixes depth to [`PRIVATE_TRANSFER_V2_TREE_DEPTH`]. The
/// parameter identity, rather than a caller-supplied depth, selects the exact
/// field, Poseidon2 constants and empty-node rules in a future backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TreeParametersV2 {
    id: TreeParametersId,
}

impl TreeParametersV2 {
    pub const fn new(id: TreeParametersId) -> Self {
        Self { id }
    }

    pub const fn id(self) -> TreeParametersId {
        self.id
    }

    pub const fn depth(self) -> u8 {
        PRIVATE_TRANSFER_V2_TREE_DEPTH
    }
}

/// Canonical, proof-independent identity of one two-input/two-output transfer.
///
/// A later crypto module hashes [`Self::encode`] with
/// [`PRIVATE_TRANSFER_V2_INTENT_DOMAIN`] to obtain `TransactionIntentId`, then
/// supplies that derived ID to the AIR as a public input. Keeping the derived
/// ID out of this structure prevents self-referential or caller-chosen binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateTransferIntentV2 {
    circuit_id: CircuitId,
    genesis_id: GenesisId,
    validation_context_id: ValidationContextId,
    pre_state_id: StateId,
    tree_parameters: TreeParametersV2,
    pre_state_root: MerkleRootV2,
    asset_id: AssetId,
    nullifiers: [NullifierV2; INPUT_COUNT],
    output_commitments: [NoteCommitmentV2; OUTPUT_COUNT],
    ciphertext_digests: [CiphertextDigestV2; OUTPUT_COUNT],
}

impl PrivateTransferIntentV2 {
    /// Fixed-width size of the v2 canonical intent encoding.
    pub const ENCODED_LENGTH: usize = CircuitId::LENGTH
        + 32 * 5
        + MerkleRootV2::LENGTH
        + NullifierV2::LENGTH * INPUT_COUNT
        + NoteCommitmentV2::LENGTH * OUTPUT_COUNT
        + CiphertextDigestV2::LENGTH * OUTPUT_COUNT;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        circuit_id: CircuitId,
        genesis_id: GenesisId,
        validation_context_id: ValidationContextId,
        pre_state_id: StateId,
        tree_parameters: TreeParametersV2,
        pre_state_root: MerkleRootV2,
        asset_id: AssetId,
        nullifiers: [NullifierV2; INPUT_COUNT],
        output_commitments: [NoteCommitmentV2; OUTPUT_COUNT],
        ciphertext_digests: [CiphertextDigestV2; OUTPUT_COUNT],
    ) -> Result<Self, PrivacyTypesError> {
        if nullifiers[0] == nullifiers[1] {
            return Err(PrivacyTypesError::DuplicateInputNullifier);
        }
        if output_commitments[0] == output_commitments[1] {
            return Err(PrivacyTypesError::DuplicateOutputCommitment);
        }
        Ok(Self {
            circuit_id,
            genesis_id,
            validation_context_id,
            pre_state_id,
            tree_parameters,
            pre_state_root,
            asset_id,
            nullifiers,
            output_commitments,
            ciphertext_digests,
        })
    }

    pub const fn circuit_id(&self) -> CircuitId {
        self.circuit_id
    }

    pub const fn genesis_id(&self) -> GenesisId {
        self.genesis_id
    }

    pub const fn validation_context_id(&self) -> ValidationContextId {
        self.validation_context_id
    }

    pub const fn pre_state_id(&self) -> StateId {
        self.pre_state_id
    }

    pub const fn tree_parameters(&self) -> TreeParametersV2 {
        self.tree_parameters
    }

    pub const fn pre_state_root(&self) -> MerkleRootV2 {
        self.pre_state_root
    }

    pub const fn asset_id(&self) -> AssetId {
        self.asset_id
    }

    pub const fn nullifiers(&self) -> &[NullifierV2; INPUT_COUNT] {
        &self.nullifiers
    }

    pub const fn output_commitments(&self) -> &[NoteCommitmentV2; OUTPUT_COUNT] {
        &self.output_commitments
    }

    pub const fn ciphertext_digests(&self) -> &[CiphertextDigestV2; OUTPUT_COUNT] {
        &self.ciphertext_digests
    }

    /// Encodes all public, semantic transfer fields in their only permitted order.
    pub fn encode(&self) -> [u8; Self::ENCODED_LENGTH] {
        let mut bytes = [0_u8; Self::ENCODED_LENGTH];
        let mut offset = 0;
        write(&mut bytes, &mut offset, &self.circuit_id.as_bytes());
        write(&mut bytes, &mut offset, &self.genesis_id.0);
        write(&mut bytes, &mut offset, &self.validation_context_id.0);
        write(&mut bytes, &mut offset, &self.pre_state_id.0);
        write(
            &mut bytes,
            &mut offset,
            &self.tree_parameters.id().as_bytes(),
        );
        write(&mut bytes, &mut offset, &self.pre_state_root.as_bytes());
        write(&mut bytes, &mut offset, &self.asset_id.0);
        for nullifier in &self.nullifiers {
            write(&mut bytes, &mut offset, &nullifier.as_bytes());
        }
        for commitment in &self.output_commitments {
            write(&mut bytes, &mut offset, &commitment.as_bytes());
        }
        for digest in &self.ciphertext_digests {
            write(&mut bytes, &mut offset, &digest.as_bytes());
        }
        debug_assert_eq!(offset, Self::ENCODED_LENGTH);
        bytes
    }

    /// Decodes exactly one v2 canonical intent and repeats structural checks.
    pub fn decode(bytes: &[u8]) -> Result<Self, PrivacyTypesError> {
        if bytes.len() != Self::ENCODED_LENGTH {
            return Err(PrivacyTypesError::InvalidIntentLength {
                actual: bytes.len(),
                expected: Self::ENCODED_LENGTH,
            });
        }
        let mut offset = 0;
        let circuit_id = CircuitId::new(read(bytes, &mut offset));
        let genesis_id = GenesisId::new(read(bytes, &mut offset));
        let validation_context_id = ValidationContextId::new(read(bytes, &mut offset));
        let pre_state_id = StateId::new(read(bytes, &mut offset));
        let tree_parameters =
            TreeParametersV2::new(TreeParametersId::new(read(bytes, &mut offset)));
        let pre_state_root = MerkleRootV2::new(read(bytes, &mut offset))?;
        let asset_id = AssetId::new(read(bytes, &mut offset));
        let nullifiers = [
            NullifierV2::new(read(bytes, &mut offset))?,
            NullifierV2::new(read(bytes, &mut offset))?,
        ];
        let output_commitments = [
            NoteCommitmentV2::new(read(bytes, &mut offset))?,
            NoteCommitmentV2::new(read(bytes, &mut offset))?,
        ];
        let ciphertext_digests = [
            CiphertextDigestV2::new(read(bytes, &mut offset))?,
            CiphertextDigestV2::new(read(bytes, &mut offset))?,
        ];
        debug_assert_eq!(offset, Self::ENCODED_LENGTH);
        Self::new(
            circuit_id,
            genesis_id,
            validation_context_id,
            pre_state_id,
            tree_parameters,
            pre_state_root,
            asset_id,
            nullifiers,
            output_commitments,
            ciphertext_digests,
        )
    }
}

fn write(destination: &mut [u8], offset: &mut usize, source: &[u8]) {
    destination[*offset..*offset + source.len()].copy_from_slice(source);
    *offset += source.len();
}

fn take<'a>(source: &'a [u8], offset: &mut usize, length: usize) -> &'a [u8] {
    let value = &source[*offset..*offset + length];
    *offset += length;
    value
}

fn read<const LENGTH: usize>(source: &[u8], offset: &mut usize) -> [u8; LENGTH] {
    take(source, offset, LENGTH)
        .try_into()
        .expect("fixed field length")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent() -> PrivateTransferIntentV2 {
        PrivateTransferIntentV2::new(
            CircuitId::new([1; 32]),
            GenesisId::new([2; 32]),
            ValidationContextId::new([3; 32]),
            StateId::new([4; 32]),
            TreeParametersV2::new(TreeParametersId::new([5; 32])),
            MerkleRootV2::new([6; 64]).unwrap(),
            AssetId::new([7; 32]),
            [
                NullifierV2::new([8; 64]).unwrap(),
                NullifierV2::new([9; 64]).unwrap(),
            ],
            [
                NoteCommitmentV2::new([10; 64]).unwrap(),
                NoteCommitmentV2::new([11; 64]).unwrap(),
            ],
            [
                CiphertextDigestV2::new([12; 64]).unwrap(),
                CiphertextDigestV2::new([13; 64]).unwrap(),
            ],
        )
        .unwrap()
    }

    #[test]
    fn intent_is_640_bytes_and_round_trips_in_the_only_canonical_order() {
        let intent = intent();
        assert_eq!(PrivateTransferIntentV2::ENCODED_LENGTH, 640);
        assert_eq!(
            PrivateTransferIntentV2::decode(&intent.encode()).unwrap(),
            intent
        );
    }

    #[test]
    fn every_canonical_intent_byte_is_bound_to_a_decoded_field() {
        let original = intent();
        for index in 0..PrivateTransferIntentV2::ENCODED_LENGTH {
            let mut changed = original.encode();
            changed[index] ^= 1;
            match PrivateTransferIntentV2::decode(&changed) {
                Ok(decoded) => assert_ne!(decoded, original),
                Err(PrivacyTypesError::NonCanonicalBabyBearElement { .. }) => {}
                Err(error) => panic!("single-byte mutation returned unexpected error: {error}"),
            }
        }
    }

    #[test]
    fn decoder_and_constructor_reject_invalid_structure() {
        let encoded = intent().encode();
        assert!(matches!(
            PrivateTransferIntentV2::decode(&encoded[..encoded.len() - 1]),
            Err(PrivacyTypesError::InvalidIntentLength { .. })
        ));
        assert_eq!(
            PrivateTransferIntentV2::new(
                CircuitId::new([1; 32]),
                GenesisId::new([2; 32]),
                ValidationContextId::new([3; 32]),
                StateId::new([4; 32]),
                TreeParametersV2::new(TreeParametersId::new([5; 32])),
                MerkleRootV2::new([6; 64]).unwrap(),
                AssetId::new([7; 32]),
                [
                    NullifierV2::new([8; 64]).unwrap(),
                    NullifierV2::new([8; 64]).unwrap(),
                ],
                [
                    NoteCommitmentV2::new([10; 64]).unwrap(),
                    NoteCommitmentV2::new([11; 64]).unwrap(),
                ],
                [
                    CiphertextDigestV2::new([12; 64]).unwrap(),
                    CiphertextDigestV2::new([13; 64]).unwrap(),
                ],
            ),
            Err(PrivacyTypesError::DuplicateInputNullifier)
        );
    }
}
