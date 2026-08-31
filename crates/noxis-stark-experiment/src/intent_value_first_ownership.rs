//! First composed ownership slice: intent, four-note value conservation and
//! one depth-32 input ownership witness in one AIR.
//!
//! It is deliberately limited to input zero. The point is an executable,
//! auditable first removal of the former cross-proof commitment bridge; it is
//! not a complete transfer proof.

use noxis_poseidon2_privacy_reference::Poseidon2P24PrivacyReference;
use noxis_poseidon2_reference::{BabyBearDigestV2, Poseidon2P24Reference};
use noxis_privacy_types::PrivateTransferIntentV2;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use p3_uni_stark::{prove, verify};

use crate::{
    StarkExperimentError, Val,
    intent::{
        INTENT_BYTES_OFFSET, INTENT_PUBLIC_VALUES, INTENT_TRACE_WIDTH, INTENT_WITNESS_OFFSET,
        Poseidon2P24IntentAir, Poseidon2P24IntentExperimentResult,
        build_p24_intent_trace_with_rows, byte_pack3le as intent_pack,
    },
    make_high_degree_hiding_config,
    ownership::{
        DIGEST_LANES, KEY_BYTES, MEMBERSHIP_DEPTH, NOTE_DIGEST_OFFSET, OWNERSHIP_PUBLIC_VALUES,
        Poseidon2P24OwnershipAir, Poseidon2P24OwnershipExperimentResult,
        TRACE_ROWS as OWNERSHIP_ROWS, TRACE_WIDTH as OWNERSHIP_WIDTH,
        WITNESS_OFFSET as OWNERSHIP_WITNESS_OFFSET, build_ownership_trace_with_rows,
        prepare_ownership_path32,
    },
    value_conservation::{
        INPUT_NOTE_COUNT, NOTE_COMMITMENT_PUBLIC_VALUES, NOTE_COUNT, NOTE_INPUT_BYTES,
        PUBLIC_VALUES as VALUE_PUBLIC_VALUES, Poseidon2P24ValueConservationAir,
        Poseidon2P24ValueConservationExperimentResult, TRACE_WIDTH as VALUE_WIDTH,
        build_trace_with_rows, validate_witness_values,
    },
};

const INTENT_OUTPUT_OFFSET: usize = (32 * 5) + 64 + 32 + (64 * 2);
const COMMITMENT_BYTES: usize = NOTE_COMMITMENT_PUBLIC_VALUES * 4;
const TRACE_ROWS: usize = OWNERSHIP_ROWS;
const TRACE_WIDTH: usize = INTENT_TRACE_WIDTH + VALUE_WIDTH + OWNERSHIP_WIDTH;
const PUBLIC_VALUES: usize = INTENT_PUBLIC_VALUES + VALUE_PUBLIC_VALUES + OWNERSHIP_PUBLIC_VALUES;
const PROVER_STACK_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Poseidon2P24IntentValueFirstOwnershipExperimentResult {
    pub intent: Poseidon2P24IntentExperimentResult,
    pub values: Poseidon2P24ValueConservationExperimentResult,
    pub ownership: Poseidon2P24OwnershipExperimentResult,
    pub trace_rows: usize,
}

#[derive(Clone, Debug)]
struct AirV1 {
    intent: Poseidon2P24IntentAir,
    values: Poseidon2P24ValueConservationAir,
    ownership: Poseidon2P24OwnershipAir,
}
impl AirV1 {
    fn from_reference(reference: &Poseidon2P24Reference) -> Result<Self, StarkExperimentError> {
        Ok(Self {
            intent: Poseidon2P24IntentAir::from_reference(reference)?,
            values: Poseidon2P24ValueConservationAir::from_reference(reference, false)?,
            ownership: Poseidon2P24OwnershipAir::from_reference_with_note_commitment(
                reference, false,
            )?,
        })
    }
}
impl<F> BaseAir<F> for AirV1 {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(10)
    }
}
impl<AB: AirBuilder> Air<AB> for AirV1 {
    fn eval(&self, builder: &mut AB) {
        let public = builder.public_values().to_vec();
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let (intent_public, rest_public) = public.split_at(INTENT_PUBLIC_VALUES);
        let (value_public, ownership_public) = rest_public.split_at(VALUE_PUBLIC_VALUES);
        let (intent_local, rest_local) = local.split_at(INTENT_TRACE_WIDTH);
        let (value_local, ownership_local) = rest_local.split_at(VALUE_WIDTH);
        let (intent_next, rest_next) = next.split_at(INTENT_TRACE_WIDTH);
        let (value_next, ownership_next) = rest_next.split_at(VALUE_WIDTH);
        self.intent
            .eval_relation(builder, intent_local, intent_next, intent_public);
        self.values
            .eval_relation(builder, value_local, value_next, value_public);
        self.ownership
            .eval_relation(builder, ownership_local, ownership_next, ownership_public);
        for output in 0..2 {
            for lane in 0..NOTE_COMMITMENT_PUBLIC_VALUES {
                let start = INTENT_WITNESS_OFFSET
                    + INTENT_BYTES_OFFSET
                    + INTENT_OUTPUT_OFFSET
                    + output * COMMITMENT_BYTES
                    + lane * 4;
                let value: AB::Expr = intent_local[start].into();
                let value = value
                    + intent_local[start + 1] * AB::F::from_u32(1 << 8)
                    + intent_local[start + 2] * AB::F::from_u32(1 << 16)
                    + intent_local[start + 3] * AB::F::from_u32(1 << 24);
                builder.assert_eq(
                    value,
                    value_public
                        [(INPUT_NOTE_COUNT + output) * NOTE_COMMITMENT_PUBLIC_VALUES + lane],
                );
            }
        }
        for lane in 0..DIGEST_LANES {
            builder.assert_eq(
                ownership_local[OWNERSHIP_WITNESS_OFFSET + NOTE_DIGEST_OFFSET + lane],
                value_public[lane],
            );
        }
    }
}

pub fn prove_and_verify_p24_intent_value_first_input_ownership(
    intent: &PrivateTransferIntentV2,
    notes: [[u8; NOTE_INPUT_BYTES]; NOTE_COUNT],
    key: [u8; KEY_BYTES],
    position: u32,
    siblings: [BabyBearDigestV2; MEMBERSHIP_DEPTH],
) -> Result<Poseidon2P24IntentValueFirstOwnershipExperimentResult, StarkExperimentError> {
    let asset = intent.asset_id().0;
    validate_witness_values(&notes, asset, None)?;
    let reference = Poseidon2P24Reference::load_candidate()?;
    let privacy = Poseidon2P24PrivacyReference::load_candidate()?;
    let prepared = prepare_ownership_path32(&reference, key, notes[0], position, siblings)?;
    let note_commitments: [BabyBearDigestV2; NOTE_COUNT] = notes
        .iter()
        .map(|note| privacy.hash_note(note))
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .expect("four notes");
    if prepared.note_commitment != note_commitments[0] {
        return Err(StarkExperimentError::OwnershipNoteCommitmentMismatch);
    }
    let intent_commitment = privacy.hash_private_transfer_intent(intent)?;
    let encoded = intent.encode();
    let air = AirV1::from_reference(&reference)?;
    let intent_trace =
        build_p24_intent_trace_with_rows(&air.intent, encoded, intent_pack(encoded), TRACE_ROWS);
    let value_trace = build_trace_with_rows(&air.values, notes, TRACE_ROWS);
    let ownership_trace =
        build_ownership_trace_with_rows(&air.ownership, &prepared.witness, TRACE_ROWS);
    let trace = combine(intent_trace, value_trace, ownership_trace);
    let mut public = intent_pack(encoded)
        .into_iter()
        .chain(intent_commitment.elements())
        .map(Val::from_u32)
        .collect::<Vec<_>>();
    for c in note_commitments {
        public.extend(c.map(Val::from_u32));
    }
    public.extend(asset.map(Val::from_u8));
    public.extend(prepared.nullifier.map(Val::from_u32));
    public.extend(prepared.root.map(Val::from_u32));
    let prover = std::thread::Builder::new()
        .name("noxis-p24-intent-value-first-ownership-prover".to_owned())
        .stack_size(PROVER_STACK_BYTES)
        .spawn(move || {
            let config = make_high_degree_hiding_config();
            let proof = prove(&config, &air, trace, &public);
            verify(&config, &air, &proof, &public)
                .map_err(|_| StarkExperimentError::VerificationFailed)
        })
        .map_err(|_| StarkExperimentError::ProverThreadFailed)?;
    prover
        .join()
        .map_err(|_| StarkExperimentError::ProverThreadFailed)??;
    Ok(Poseidon2P24IntentValueFirstOwnershipExperimentResult {
        intent: Poseidon2P24IntentExperimentResult {
            intent_commitment,
            trace_rows: TRACE_ROWS,
        },
        values: Poseidon2P24ValueConservationExperimentResult {
            note_commitments,
            asset_id: asset,
            trace_rows: TRACE_ROWS,
        },
        ownership: Poseidon2P24OwnershipExperimentResult {
            nullifier: prepared.nullifier,
            root: prepared.root,
            trace_rows: TRACE_ROWS,
        },
        trace_rows: TRACE_ROWS,
    })
}

fn combine(
    intent: RowMajorMatrix<Val>,
    value: RowMajorMatrix<Val>,
    ownership: RowMajorMatrix<Val>,
) -> RowMajorMatrix<Val> {
    debug_assert_eq!(intent.height(), TRACE_ROWS);
    debug_assert_eq!(value.height(), TRACE_ROWS);
    debug_assert_eq!(ownership.height(), TRACE_ROWS);
    let mut all = Val::zero_vec(TRACE_ROWS * TRACE_WIDTH);
    for row in 0..TRACE_ROWS {
        let target = row * TRACE_WIDTH;
        let i = row * INTENT_TRACE_WIDTH;
        let v = row * VALUE_WIDTH;
        let o = row * OWNERSHIP_WIDTH;
        all[target..target + INTENT_TRACE_WIDTH]
            .copy_from_slice(&intent.values[i..i + INTENT_TRACE_WIDTH]);
        all[target + INTENT_TRACE_WIDTH..target + INTENT_TRACE_WIDTH + VALUE_WIDTH]
            .copy_from_slice(&value.values[v..v + VALUE_WIDTH]);
        all[target + INTENT_TRACE_WIDTH + VALUE_WIDTH..target + TRACE_WIDTH]
            .copy_from_slice(&ownership.values[o..o + OWNERSHIP_WIDTH]);
    }
    RowMajorMatrix::new(all, TRACE_WIDTH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use noxis_privacy_types::{
        CiphertextDigestV2, CircuitId, MerkleRootV2, NoteCommitmentV2, NullifierV2,
        PrivateTransferOutputV2, TreeParametersId, TreeParametersV2,
    };
    use noxis_tree_params::CandidatePoseidon2P24ManifestV2;
    use noxis_types::{AssetId, GenesisId, StateId, ValidationContextId};

    fn note(
        asset: [u8; 32],
        value: u128,
        recipient: [u32; 16],
        seed: u8,
    ) -> [u8; NOTE_INPUT_BYTES] {
        let mut note = core::array::from_fn(|index| (index as u8).wrapping_add(seed));
        note[..2].copy_from_slice(&1_u16.to_be_bytes());
        note[2..34].copy_from_slice(&asset);
        note[34..50].copy_from_slice(&value.to_be_bytes());
        for (lane, element) in recipient.into_iter().enumerate() {
            note[50 + lane * 4..54 + lane * 4].copy_from_slice(&element.to_le_bytes());
        }
        note
    }

    #[test]
    fn composed_air_accepts_one_ownership_witness_and_four_conserved_notes() {
        let privacy = Poseidon2P24PrivacyReference::load_candidate().unwrap();
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        let asset = [7; 32];
        let key = [9; 32];
        let first = note(asset, 40, privacy.hash_addr(&key).unwrap(), 1);
        let second = note(asset, 60, privacy.hash_addr(&[10; 32]).unwrap(), 2);
        let mut outputs = [
            note(asset, 45, privacy.hash_addr(&[11; 32]).unwrap(), 3),
            note(asset, 55, privacy.hash_addr(&[12; 32]).unwrap(), 4),
        ]
        .map(|note| {
            (
                NoteCommitmentV2::from_elements(privacy.hash_note(&note).unwrap()).unwrap(),
                note,
            )
        });
        outputs.sort_by_key(|(commitment, _)| commitment.as_bytes());
        let intent = PrivateTransferIntentV2::new(
            CircuitId::new([1; 32]),
            GenesisId::new([2; 32]),
            ValidationContextId::new([3; 32]),
            StateId::new([4; 32]),
            TreeParametersV2::new(TreeParametersId::new(
                CandidatePoseidon2P24ManifestV2::new()
                    .candidate_id()
                    .unwrap()
                    .as_bytes(),
            )),
            MerkleRootV2::from_elements([5; 16]).unwrap(),
            AssetId::new(asset),
            [
                NullifierV2::from_elements([1; 16]).unwrap(),
                NullifierV2::from_elements([2; 16]).unwrap(),
            ],
            [
                PrivateTransferOutputV2::new(
                    outputs[0].0,
                    CiphertextDigestV2::from_elements([6; 16]).unwrap(),
                ),
                PrivateTransferOutputV2::new(
                    outputs[1].0,
                    CiphertextDigestV2::from_elements([8; 16]).unwrap(),
                ),
            ],
        )
        .unwrap();
        let notes = [first, second, outputs[0].1, outputs[1].1];
        let prepared =
            prepare_ownership_path32(&reference, key, first, 0, [[0; 16]; MEMBERSHIP_DEPTH])
                .unwrap();
        let air = AirV1::from_reference(&reference).unwrap();
        let encoded = intent.encode();
        let trace = combine(
            build_p24_intent_trace_with_rows(
                &air.intent,
                encoded,
                intent_pack(encoded),
                TRACE_ROWS,
            ),
            build_trace_with_rows(&air.values, notes, TRACE_ROWS),
            build_ownership_trace_with_rows(&air.ownership, &prepared.witness, TRACE_ROWS),
        );
        let commitments: [BabyBearDigestV2; NOTE_COUNT] =
            notes.map(|note| privacy.hash_note(&note).unwrap());
        let intent_commitment = privacy.hash_private_transfer_intent(&intent).unwrap();
        let mut public = intent_pack(encoded)
            .into_iter()
            .chain(intent_commitment.elements())
            .map(Val::from_u32)
            .collect::<Vec<_>>();
        for commitment in commitments {
            public.extend(commitment.map(Val::from_u32));
        }
        public.extend(asset.map(Val::from_u8));
        public.extend(prepared.nullifier.map(Val::from_u32));
        public.extend(prepared.root.map(Val::from_u32));
        p3_air::check_constraints(&air, &trace, &public);
        if std::env::var_os("NOXIS_RUN_COMPOSED_OWNERSHIP_PROOF").is_some() {
            let result = prove_and_verify_p24_intent_value_first_input_ownership(
                &intent,
                notes,
                key,
                0,
                [[0; 16]; MEMBERSHIP_DEPTH],
            )
            .unwrap();
            assert_eq!(result.ownership.nullifier, prepared.nullifier);
            assert_eq!(result.ownership.root, prepared.root);
        }
    }
}
