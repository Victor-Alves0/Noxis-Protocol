//! Local candidate statement for one fixed two-input/two-output transfer.
//!
//! This module checks the relations a future AIR must prove, but it creates no
//! proof, packet, ledger transition, or authorization. Its witness types stay
//! opaque so note preimages, values, keys, and Merkle paths remain local.

use std::fmt;

use noxis_privacy_types::{PrivateTransferIntentCommitmentV2, PrivateTransferIntentV2};
use noxis_tree_params::{P24_BYTE_PACK_WIDTH, P24_INTENT_COMMITMENT_INPUT_ELEMENTS};

use crate::{
    CandidateP24NoteOpeningEvaluatorV2, DerivedNotePublicV2, NoteOpeningError, NoteOpeningV2,
    SpendingWitnessV2,
};

/// A locally checked candidate witness for the fixed 2×2 private-transfer shape.
///
/// The object has no network representation and cannot authorize a ledger
/// transition. It retains private material only so its relations can be
/// revalidated before a future prover consumes it.
pub struct CandidatePrivateTransferWitnessV2 {
    intent: PrivateTransferIntentV2,
    input_witnesses: [SpendingWitnessV2; 2],
    output_openings: [NoteOpeningV2; 2],
}

impl CandidatePrivateTransferWitnessV2 {
    /// Checks exact public-intent binding, candidate membership, and `u128`
    /// conservation before retaining the local witness.
    pub fn new(
        intent: PrivateTransferIntentV2,
        input_witnesses: [SpendingWitnessV2; 2],
        output_openings: [NoteOpeningV2; 2],
        evaluator: &CandidateP24NoteOpeningEvaluatorV2,
    ) -> Result<Self, PrivateTransferStatementError> {
        validate(&intent, &input_witnesses, &output_openings, evaluator)?;
        Ok(Self {
            intent,
            input_witnesses,
            output_openings,
        })
    }

    /// Returns the already-public canonical intent bound to this witness.
    pub const fn intent(&self) -> &PrivateTransferIntentV2 {
        &self.intent
    }

    /// Rechecks all retained relations without exposing a private field.
    pub fn revalidate(
        &self,
        evaluator: &CandidateP24NoteOpeningEvaluatorV2,
    ) -> Result<(), PrivateTransferStatementError> {
        validate(
            &self.intent,
            &self.input_witnesses,
            &self.output_openings,
            evaluator,
        )
    }

    /// Produces the public frame a future AIR must bind to this local witness.
    ///
    /// This does not create a proof or make the transfer acceptable to any
    /// ledger. It only prevents a future prover from silently pairing the
    /// witness with the commitment of a different canonical intent.
    pub fn air_public_inputs(
        &self,
        evaluator: &CandidateP24NoteOpeningEvaluatorV2,
    ) -> Result<CandidatePrivateTransferAirPublicInputsV1, PrivateTransferStatementError> {
        self.revalidate(evaluator)?;
        CandidatePrivateTransferAirPublicInputsV1::from_intent(self.intent.clone(), evaluator)
    }
}

/// Candidate public frame for the future private-transfer AIR.
///
/// The complete public intent remains available to a verifier, while
/// `intent_commitment` forces the AIR/proof relation to bind exactly its 640
/// canonical bytes. This type has no wire codec and cannot authorize a state
/// transition until a separate private-state and proof deployment are audited.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidatePrivateTransferAirPublicInputsV1 {
    intent: PrivateTransferIntentV2,
    intent_elements: [u32; P24_INTENT_COMMITMENT_INPUT_ELEMENTS],
    intent_commitment: PrivateTransferIntentCommitmentV2,
}

impl CandidatePrivateTransferAirPublicInputsV1 {
    /// Binds a canonical intent to the frozen candidate `H_INTENT` reference.
    pub fn from_intent(
        intent: PrivateTransferIntentV2,
        evaluator: &CandidateP24NoteOpeningEvaluatorV2,
    ) -> Result<Self, PrivateTransferStatementError> {
        if intent.tree_parameters().id() != evaluator.candidate_tree_parameters_id()? {
            return Err(PrivateTransferStatementError::CandidateTreeParametersMismatch);
        }
        let intent_commitment = evaluator.intent_commitment(&intent)?;
        Ok(Self {
            intent_elements: byte_pack3le_intent(&intent),
            intent,
            intent_commitment,
        })
    }

    /// The full canonical public statement whose bytes are committed below.
    pub const fn intent(&self) -> &PrivateTransferIntentV2 {
        &self.intent
    }

    /// Candidate `H_INTENT(intent.encode())` in canonical BabyBear encoding.
    pub const fn intent_commitment(&self) -> PrivateTransferIntentCommitmentV2 {
        self.intent_commitment
    }

    /// The 214 canonical `BytePack3LE` public elements consumed by the AIR.
    ///
    /// The first 213 elements encode three bytes each and the last is below
    /// 256, so the mapping back to the fixed 640-byte intent is unambiguous.
    pub const fn intent_elements(&self) -> &[u32; P24_INTENT_COMMITMENT_INPUT_ELEMENTS] {
        &self.intent_elements
    }

    /// Recomputes the binding before a future prover or verifier consumes it.
    pub fn revalidate(
        &self,
        evaluator: &CandidateP24NoteOpeningEvaluatorV2,
    ) -> Result<(), PrivateTransferStatementError> {
        let expected = Self::from_intent(self.intent.clone(), evaluator)?;
        if expected.intent_commitment != self.intent_commitment {
            return Err(PrivateTransferStatementError::IntentCommitmentMismatch);
        }
        if expected.intent_elements != self.intent_elements {
            return Err(PrivateTransferStatementError::IntentPackingMismatch);
        }
        Ok(())
    }
}

fn byte_pack3le_intent(
    intent: &PrivateTransferIntentV2,
) -> [u32; P24_INTENT_COMMITMENT_INPUT_ELEMENTS] {
    let encoded = intent.encode();
    core::array::from_fn(|index| {
        encoded[index * P24_BYTE_PACK_WIDTH
            ..core::cmp::min((index + 1) * P24_BYTE_PACK_WIDTH, encoded.len())]
            .iter()
            .enumerate()
            .fold(0_u32, |value, (offset, byte)| {
                value | (u32::from(*byte) << (offset * 8))
            })
    })
}

fn validate(
    intent: &PrivateTransferIntentV2,
    input_witnesses: &[SpendingWitnessV2; 2],
    output_openings: &[NoteOpeningV2; 2],
    evaluator: &CandidateP24NoteOpeningEvaluatorV2,
) -> Result<(), PrivateTransferStatementError> {
    if intent.tree_parameters().id() != evaluator.candidate_tree_parameters_id()? {
        return Err(PrivateTransferStatementError::CandidateTreeParametersMismatch);
    }
    let public_inputs = [
        input_witnesses[0].revalidate(evaluator)?,
        input_witnesses[1].revalidate(evaluator)?,
    ];
    validate_input_bindings(intent, public_inputs)?;

    if public_inputs[0].note_commitment() == public_inputs[1].note_commitment()
        || input_witnesses[0].leaf_position == input_witnesses[1].leaf_position
    {
        return Err(PrivateTransferStatementError::DuplicateInputNote);
    }

    for witness in input_witnesses {
        if witness.opening.asset_id != intent.asset_id() {
            return Err(PrivateTransferStatementError::InputAssetMismatch);
        }
    }

    let output_commitments = [
        output_openings[0].note_commitment(evaluator)?,
        output_openings[1].note_commitment(evaluator)?,
    ];
    if output_commitments != intent.output_commitments() {
        return Err(PrivateTransferStatementError::OutputCommitmentMismatch);
    }
    if output_commitments.contains(&public_inputs[0].note_commitment())
        || output_commitments.contains(&public_inputs[1].note_commitment())
    {
        return Err(PrivateTransferStatementError::OutputReintroducesInputCommitment);
    }
    for opening in output_openings {
        if opening.asset_id != intent.asset_id() {
            return Err(PrivateTransferStatementError::OutputAssetMismatch);
        }
    }
    validate_local_randomness_uniqueness(input_witnesses, output_openings)?;

    let input_total = input_witnesses[0]
        .opening
        .value
        .checked_add(input_witnesses[1].opening.value)
        .ok_or(PrivateTransferStatementError::InputValueOverflow)?;
    let output_total = output_openings[0]
        .value
        .checked_add(output_openings[1].value)
        .ok_or(PrivateTransferStatementError::OutputValueOverflow)?;
    if input_total != output_total {
        return Err(PrivateTransferStatementError::ValueNotConserved);
    }
    Ok(())
}

fn validate_local_randomness_uniqueness(
    inputs: &[SpendingWitnessV2; 2],
    outputs: &[NoteOpeningV2; 2],
) -> Result<(), PrivateTransferStatementError> {
    let openings = [
        &inputs[0].opening,
        &inputs[1].opening,
        &outputs[0],
        &outputs[1],
    ];
    for left in 0..openings.len() {
        for right in left + 1..openings.len() {
            if openings[left].has_same_rho(openings[right]) {
                return Err(PrivateTransferStatementError::DuplicateLocalRho);
            }
            if openings[left].has_same_rcm(openings[right]) {
                return Err(PrivateTransferStatementError::DuplicateLocalRcm);
            }
        }
    }
    Ok(())
}

fn validate_input_bindings(
    intent: &PrivateTransferIntentV2,
    public_inputs: [DerivedNotePublicV2; 2],
) -> Result<(), PrivateTransferStatementError> {
    if public_inputs[0].merkle_root() != intent.pre_state_root()
        || public_inputs[1].merkle_root() != intent.pre_state_root()
    {
        return Err(PrivateTransferStatementError::InputRootMismatch);
    }
    if [public_inputs[0].nullifier(), public_inputs[1].nullifier()] != *intent.nullifiers() {
        return Err(PrivateTransferStatementError::InputNullifierMismatch);
    }
    Ok(())
}

/// Fail-closed local-statement errors. They contain no secret bytes or values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrivateTransferStatementError {
    NoteOpening(NoteOpeningError),
    CandidateTreeParametersMismatch,
    IntentCommitmentMismatch,
    IntentPackingMismatch,
    InputRootMismatch,
    InputNullifierMismatch,
    DuplicateInputNote,
    InputAssetMismatch,
    OutputCommitmentMismatch,
    OutputAssetMismatch,
    OutputReintroducesInputCommitment,
    DuplicateLocalRho,
    DuplicateLocalRcm,
    InputValueOverflow,
    OutputValueOverflow,
    ValueNotConserved,
}

impl From<NoteOpeningError> for PrivateTransferStatementError {
    fn from(value: NoteOpeningError) -> Self {
        Self::NoteOpening(value)
    }
}

impl fmt::Display for PrivateTransferStatementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoteOpening(error) => {
                write!(formatter, "invalid candidate note opening: {error}")
            }
            Self::CandidateTreeParametersMismatch => {
                formatter.write_str("intent tree parameters do not bind the local P24 candidate")
            }
            Self::IntentCommitmentMismatch => {
                formatter.write_str("candidate H_INTENT does not bind the canonical intent")
            }
            Self::IntentPackingMismatch => {
                formatter.write_str("candidate BytePack3LE values do not bind the canonical intent")
            }
            Self::InputRootMismatch => {
                formatter.write_str("input witness root does not bind intent")
            }
            Self::InputNullifierMismatch => {
                formatter.write_str("input witness nullifier does not bind intent")
            }
            Self::DuplicateInputNote => {
                formatter.write_str("candidate transfer repeats an input note or position")
            }
            Self::InputAssetMismatch => formatter.write_str("input asset does not bind intent"),
            Self::OutputCommitmentMismatch => {
                formatter.write_str("output commitment does not bind intent")
            }
            Self::OutputAssetMismatch => formatter.write_str("output asset does not bind intent"),
            Self::OutputReintroducesInputCommitment => {
                formatter.write_str("output reintroduces an input commitment")
            }
            Self::DuplicateLocalRho => formatter.write_str("candidate transfer repeats local rho"),
            Self::DuplicateLocalRcm => formatter.write_str("candidate transfer repeats local rcm"),
            Self::InputValueOverflow => formatter.write_str("input value sum overflows u128"),
            Self::OutputValueOverflow => formatter.write_str("output value sum overflows u128"),
            Self::ValueNotConserved => {
                formatter.write_str("private transfer does not conserve value")
            }
        }
    }
}

impl std::error::Error for PrivateTransferStatementError {}

#[cfg(test)]
mod tests {
    use noxis_privacy_types::{
        CiphertextDigestV2, CircuitId, MerkleRootV2, MerkleSiblingV2, NoteCommitmentV2,
        NullifierV2, PrivateTransferOutputV2, RecipientCommitmentV2, TreeParametersId,
        TreeParametersV2,
    };
    use noxis_types::{AssetId, GenesisId, StateId, ValidationContextId};

    use super::*;
    use crate::{CommitmentRandomnessV2, NoteOpeningInputV2, NoteRandomnessV2, NullifierKeyV2};

    fn key(value: u8) -> NullifierKeyV2 {
        NullifierKeyV2::new([value; 32])
    }

    fn opening(
        evaluator: &CandidateP24NoteOpeningEvaluatorV2,
        asset: AssetId,
        value: u128,
        key_value: u8,
        rho: u8,
        rcm: u8,
    ) -> NoteOpeningV2 {
        let recipient: RecipientCommitmentV2 =
            evaluator.recipient_commitment(&key(key_value)).unwrap();
        let input = NoteOpeningInputV2::new(
            asset,
            value,
            recipient,
            NoteRandomnessV2::new([rho; 32]),
            CommitmentRandomnessV2::new([rcm; 32]),
        );
        if value == 0 {
            NoteOpeningV2::new_padding(input).unwrap()
        } else {
            NoteOpeningV2::new_regular(input).unwrap()
        }
    }

    fn input_witnesses(
        evaluator: &CandidateP24NoteOpeningEvaluatorV2,
        asset: AssetId,
    ) -> ([SpendingWitnessV2; 2], MerkleRootV2) {
        let first = opening(evaluator, asset, 20, 10, 11, 12);
        let second = opening(evaluator, asset, 30, 20, 21, 22);
        let commitments = [
            first.note_commitment(evaluator).unwrap(),
            second.note_commitment(evaluator).unwrap(),
        ];
        let (_, first_siblings, root) = evaluator
            .tree_reference
            .small_tree_path(&commitments.map(NoteCommitmentV2::elements), 0)
            .unwrap();
        let (_, second_siblings, second_root) = evaluator
            .tree_reference
            .small_tree_path(&commitments.map(NoteCommitmentV2::elements), 1)
            .unwrap();
        let root = MerkleRootV2::from_elements(root).unwrap();
        assert_eq!(root, MerkleRootV2::from_elements(second_root).unwrap());
        let first = SpendingWitnessV2::new(
            first,
            key(10),
            0,
            first_siblings.map(|value| MerkleSiblingV2::from_elements(value).unwrap()),
            root,
            evaluator,
        )
        .unwrap();
        let second = SpendingWitnessV2::new(
            second,
            key(20),
            1,
            second_siblings.map(|value| MerkleSiblingV2::from_elements(value).unwrap()),
            root,
            evaluator,
        )
        .unwrap();
        let inputs = if first.public_values().nullifier() < second.public_values().nullifier() {
            [first, second]
        } else {
            [second, first]
        };
        (inputs, root)
    }

    fn intent(
        asset: AssetId,
        root: MerkleRootV2,
        tree_parameters: TreeParametersV2,
        nullifiers: [NullifierV2; 2],
        outputs: [NoteCommitmentV2; 2],
    ) -> PrivateTransferIntentV2 {
        PrivateTransferIntentV2::new(
            CircuitId::new([1; 32]),
            GenesisId::new([2; 32]),
            ValidationContextId::new([3; 32]),
            StateId::new([4; 32]),
            tree_parameters,
            root,
            asset,
            nullifiers,
            [
                PrivateTransferOutputV2::new(
                    outputs[0],
                    CiphertextDigestV2::from_elements([6; 16]).unwrap(),
                ),
                PrivateTransferOutputV2::new(
                    outputs[1],
                    CiphertextDigestV2::from_elements([7; 16]).unwrap(),
                ),
            ],
        )
        .unwrap()
    }

    fn valid_parts(
        evaluator: &CandidateP24NoteOpeningEvaluatorV2,
        asset: AssetId,
    ) -> (
        [SpendingWitnessV2; 2],
        MerkleRootV2,
        [NullifierV2; 2],
        [NoteOpeningV2; 2],
        [NoteCommitmentV2; 2],
    ) {
        let (inputs, root) = input_witnesses(evaluator, asset);
        let nullifiers = [
            inputs[0].public_values().nullifier(),
            inputs[1].public_values().nullifier(),
        ];
        let outputs = ordered_outputs(
            evaluator,
            opening(evaluator, asset, 50, 30, 31, 32),
            opening(evaluator, asset, 0, 40, 41, 42),
        );
        let commitments = commitments_for_outputs(evaluator, &outputs);
        (inputs, root, nullifiers, outputs, commitments)
    }

    fn ordered_outputs(
        evaluator: &CandidateP24NoteOpeningEvaluatorV2,
        first: NoteOpeningV2,
        second: NoteOpeningV2,
    ) -> [NoteOpeningV2; 2] {
        if first.note_commitment(evaluator).unwrap() < second.note_commitment(evaluator).unwrap() {
            [first, second]
        } else {
            [second, first]
        }
    }

    fn commitments_for_outputs(
        evaluator: &CandidateP24NoteOpeningEvaluatorV2,
        outputs: &[NoteOpeningV2; 2],
    ) -> [NoteCommitmentV2; 2] {
        [
            outputs[0].note_commitment(evaluator).unwrap(),
            outputs[1].note_commitment(evaluator).unwrap(),
        ]
    }

    #[test]
    fn candidate_statement_binds_every_available_public_intent_relation() {
        let evaluator = CandidateP24NoteOpeningEvaluatorV2::load_candidate().unwrap();
        let asset = AssetId::new([8; 32]);
        let (inputs, root, nullifiers, outputs, output_commitments) =
            valid_parts(&evaluator, asset);
        let candidate_intent = intent(
            asset,
            root,
            TreeParametersV2::new(evaluator.candidate_tree_parameters_id().unwrap()),
            nullifiers,
            output_commitments,
        );
        let witness =
            CandidatePrivateTransferWitnessV2::new(candidate_intent, inputs, outputs, &evaluator)
                .unwrap();
        assert_eq!(witness.intent().asset_id(), asset);
        witness.revalidate(&evaluator).unwrap();
        let air = witness.air_public_inputs(&evaluator).unwrap();
        assert_eq!(air.intent(), witness.intent());
        assert_eq!(air.intent_elements().len(), 214);
        assert!(
            air.intent_elements()[..213]
                .iter()
                .all(|element| *element < (1 << 24))
        );
        assert!(air.intent_elements()[213] < 256);
        air.revalidate(&evaluator).unwrap();
    }

    #[test]
    fn candidate_statement_rejects_public_binding_and_conservation_failures() {
        let evaluator = CandidateP24NoteOpeningEvaluatorV2::load_candidate().unwrap();
        let asset = AssetId::new([8; 32]);
        let ([first, second], root) = input_witnesses(&evaluator, asset);
        let first_public = first.public_values();
        let second_public = second.public_values();
        let outputs = ordered_outputs(
            &evaluator,
            opening(&evaluator, asset, 49, 30, 31, 32),
            opening(&evaluator, asset, 2, 40, 41, 42),
        );
        let candidate_intent = intent(
            asset,
            root,
            TreeParametersV2::new(evaluator.candidate_tree_parameters_id().unwrap()),
            [first_public.nullifier(), second_public.nullifier()],
            commitments_for_outputs(&evaluator, &outputs),
        );
        assert!(matches!(
            CandidatePrivateTransferWitnessV2::new(
                candidate_intent,
                [first, second],
                outputs,
                &evaluator,
            ),
            Err(PrivateTransferStatementError::ValueNotConserved)
        ));
    }

    #[test]
    fn candidate_statement_rejects_changed_candidate_parameters_and_public_bindings() {
        let evaluator = CandidateP24NoteOpeningEvaluatorV2::load_candidate().unwrap();
        let asset = AssetId::new([8; 32]);

        let (inputs, root, nullifiers, outputs, commitments) = valid_parts(&evaluator, asset);
        let candidate_intent = intent(
            asset,
            root,
            TreeParametersV2::new(TreeParametersId::new([5; 32])),
            nullifiers,
            commitments,
        );
        assert!(matches!(
            CandidatePrivateTransferWitnessV2::new(candidate_intent, inputs, outputs, &evaluator),
            Err(PrivateTransferStatementError::CandidateTreeParametersMismatch)
        ));

        let (inputs, root, mut nullifiers, outputs, commitments) = valid_parts(&evaluator, asset);
        nullifiers[0] = NullifierV2::from_elements([0; 16]).unwrap();
        let candidate_intent = intent(
            asset,
            root,
            TreeParametersV2::new(evaluator.candidate_tree_parameters_id().unwrap()),
            nullifiers,
            commitments,
        );
        assert!(matches!(
            CandidatePrivateTransferWitnessV2::new(candidate_intent, inputs, outputs, &evaluator),
            Err(PrivateTransferStatementError::InputNullifierMismatch)
        ));

        let (inputs, root, nullifiers, outputs, mut commitments) = valid_parts(&evaluator, asset);
        commitments[0] = NoteCommitmentV2::from_elements([98; 16]).unwrap();
        let candidate_intent = intent(
            asset,
            root,
            TreeParametersV2::new(evaluator.candidate_tree_parameters_id().unwrap()),
            nullifiers,
            commitments,
        );
        assert!(matches!(
            CandidatePrivateTransferWitnessV2::new(candidate_intent, inputs, outputs, &evaluator),
            Err(PrivateTransferStatementError::OutputCommitmentMismatch)
        ));
    }
}
