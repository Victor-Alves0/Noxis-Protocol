//! One composed research AIR binding `H_INTENT` output slots to private note
//! commitments and the four-note value-conservation relation.
//!
//! This remains a local, non-portable experiment. It deliberately composes
//! only the relations already executable in this crate: the canonical public
//! intent hash, four private `H_NOTE` openings, one common asset and 2x2
//! `u128` value conservation. Membership, ownership, nullifier absence,
//! envelope authentication and transaction settlement stay outside this AIR.

use noxis_poseidon2_privacy_reference::Poseidon2P24PrivacyReference;
use noxis_poseidon2_reference::{BabyBearDigestV2, Poseidon2P24Reference};
use noxis_privacy_types::PrivateTransferIntentV2;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use p3_uni_stark::{Proof, prove, verify};

use crate::{
    StarkExperimentError, Val,
    intent::{
        INTENT_BYTES_OFFSET, INTENT_PUBLIC_VALUES, INTENT_TRACE_ROWS, INTENT_TRACE_WIDTH,
        INTENT_WITNESS_OFFSET, Poseidon2P24IntentAir, Poseidon2P24IntentExperimentResult,
        build_p24_intent_trace_with_rows, byte_pack3le as intent_byte_pack3le,
    },
    make_hiding_config,
    value_conservation::{
        INPUT_NOTE_COUNT, NOTE_COMMITMENT_PUBLIC_VALUES, NOTE_COUNT, NOTE_INPUT_BYTES,
        PUBLIC_VALUES as VALUE_PUBLIC_VALUES, Poseidon2P24ValueConservationAir,
        Poseidon2P24ValueConservationExperimentResult, TRACE_WIDTH as VALUE_TRACE_WIDTH,
        build_trace_with_rows, validate_witness_values,
    },
};

/// The first output commitment starts after the fixed identities, root, asset
/// and two 64-byte nullifiers in `PrivateTransferIntentV2::encode()`.
const INTENT_OUTPUT_COMMITMENTS_OFFSET: usize = (32 * 5) + 64 + 32 + (64 * 2);
const NOTE_COMMITMENT_BYTES: usize = NOTE_COMMITMENT_PUBLIC_VALUES * 4;
const TRACE_ROWS: usize = INTENT_TRACE_ROWS;
const TRACE_WIDTH: usize = INTENT_TRACE_WIDTH + VALUE_TRACE_WIDTH;
const PUBLIC_VALUES: usize = INTENT_PUBLIC_VALUES + VALUE_PUBLIC_VALUES;

/// Public evidence retained after the composed local experiment succeeds.
/// Values, note preimages and proof material are never returned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Poseidon2P24IntentValueConservationExperimentResult {
    /// Exact public commitment to the canonical 640-byte transfer intent.
    pub intent: Poseidon2P24IntentExperimentResult,
    /// The four public `H_NOTE` commitments and common asset of the local AIR.
    pub values: Poseidon2P24ValueConservationExperimentResult,
    /// Fixed trace height used by the composed prover.
    pub trace_rows: usize,
}

/// Opaque in-memory proof for the composed intent/value relation.
///
/// The exact Plonky3 configuration remains attached to the proof. The pinned
/// research byte helpers are intentionally below any Noxis envelope, verifier
/// key, network frame or production suite ID. A verifier must also supply the
/// exact canonical intent whose bytes are part of the public input.
pub struct Poseidon2P24IntentValueConservationProof {
    config: crate::Config,
    proof: Proof<crate::Config>,
    public_result: Poseidon2P24IntentValueConservationExperimentResult,
}

impl Poseidon2P24IntentValueConservationProof {
    /// Public commitments and trace shape retained beside the opaque proof.
    pub const fn public_result(&self) -> &Poseidon2P24IntentValueConservationExperimentResult {
        &self.public_result
    }

    /// Encodes only the opaque Plonky3 object through the currently pinned
    /// research dependency. The accompanying public result remains a separate
    /// caller responsibility, and these bytes are not a Noxis wire format.
    pub fn encode_pinned_research_bytes(&self) -> Result<Vec<u8>, StarkExperimentError> {
        postcard::to_allocvec(&self.proof)
            .map_err(|_| StarkExperimentError::PinnedResearchProofEncode)
    }

    /// Rebuilds an in-memory proof using a freshly constructed local research
    /// verifier configuration. The caller supplies the public result that
    /// verification will bind; call [`verify_p24_intent_value_conservation_proof`]
    /// before accepting it for any local action.
    pub fn decode_pinned_research_bytes(
        bytes: &[u8],
        public_result: Poseidon2P24IntentValueConservationExperimentResult,
    ) -> Result<Self, StarkExperimentError> {
        let proof = postcard::from_bytes(bytes)
            .map_err(|_| StarkExperimentError::PinnedResearchProofDecode)?;
        Ok(Self {
            config: make_hiding_config(),
            proof,
            public_result,
        })
    }
}

/// AIR that executes the two source relations side by side and then proves
/// that the two output commitments embedded in the canonical intent bytes are
/// exactly the output-note commitments used by the conservation relation.
#[derive(Clone, Debug)]
struct Poseidon2P24IntentValueConservationAir {
    intent: Poseidon2P24IntentAir,
    values: Poseidon2P24ValueConservationAir,
}

impl Poseidon2P24IntentValueConservationAir {
    fn from_reference(reference: &Poseidon2P24Reference) -> Result<Self, StarkExperimentError> {
        Ok(Self {
            intent: Poseidon2P24IntentAir::from_reference(reference)?,
            values: Poseidon2P24ValueConservationAir::from_reference(reference, false)?,
        })
    }
}

impl<F> BaseAir<F> for Poseidon2P24IntentValueConservationAir {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }

    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(8)
    }
}

impl<AB: AirBuilder> Air<AB> for Poseidon2P24IntentValueConservationAir {
    fn eval(&self, builder: &mut AB) {
        let public_values = builder.public_values().to_vec();
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();

        let (intent_public, value_public) = public_values.split_at(INTENT_PUBLIC_VALUES);
        let (intent_local, value_local) = local.split_at(INTENT_TRACE_WIDTH);
        let (intent_next, value_next) = next.split_at(INTENT_TRACE_WIDTH);
        self.intent
            .eval_relation(builder, intent_local, intent_next, intent_public);
        self.values
            .eval_relation(builder, value_local, value_next, value_public);

        // `NoteCommitmentV2` is sixteen canonical little-endian BabyBear
        // elements. Recompose each exact four-byte intent fragment and bind it
        // to the corresponding public output `H_NOTE` commitment.
        for output_index in 0..NOTE_COUNT - INPUT_NOTE_COUNT {
            for lane in 0..NOTE_COMMITMENT_PUBLIC_VALUES {
                let byte_offset = INTENT_WITNESS_OFFSET
                    + INTENT_BYTES_OFFSET
                    + INTENT_OUTPUT_COMMITMENTS_OFFSET
                    + (output_index * NOTE_COMMITMENT_BYTES)
                    + (lane * 4);
                let encoded_element: AB::Expr = intent_local[byte_offset].into();
                let encoded_element = encoded_element
                    + intent_local[byte_offset + 1] * AB::F::from_u32(1 << 8)
                    + intent_local[byte_offset + 2] * AB::F::from_u32(1 << 16)
                    + intent_local[byte_offset + 3] * AB::F::from_u32(1 << 24);
                builder.assert_eq(
                    encoded_element,
                    value_public
                        [(INPUT_NOTE_COUNT + output_index) * NOTE_COMMITMENT_PUBLIC_VALUES + lane],
                );
            }
        }
    }
}

/// Produces one opaque local STARK that binds the public intent outputs to the
/// two private output-note openings while proving four-note value conservation.
/// Call [`verify_p24_intent_value_conservation_proof`] in a verifier context.
pub fn prove_p24_intent_value_conservation(
    intent: &PrivateTransferIntentV2,
    note_preimages: [[u8; NOTE_INPUT_BYTES]; NOTE_COUNT],
) -> Result<Poseidon2P24IntentValueConservationProof, StarkExperimentError> {
    let asset_id = intent.asset_id().0;
    validate_witness_values(&note_preimages, asset_id, None)?;

    let reference = Poseidon2P24Reference::load_candidate()?;
    let private_reference = Poseidon2P24PrivacyReference::load_candidate()?;
    let intent_commitment = private_reference.hash_private_transfer_intent(intent)?;
    let note_commitments: [BabyBearDigestV2; NOTE_COUNT] = note_preimages
        .iter()
        .map(|preimage| private_reference.hash_note(preimage))
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .expect("fixed four-note conservation relation");
    let air = Poseidon2P24IntentValueConservationAir::from_reference(&reference)?;
    let encoded = intent.encode();
    let intent_trace = build_p24_intent_trace_with_rows(
        &air.intent,
        encoded,
        intent_byte_pack3le(encoded),
        TRACE_ROWS,
    );
    let value_trace = build_trace_with_rows(&air.values, note_preimages, TRACE_ROWS);
    let trace = combine_traces(intent_trace, value_trace);
    let mut public_values = intent_byte_pack3le(encoded)
        .into_iter()
        .chain(intent_commitment.elements())
        .map(Val::from_u32)
        .collect::<Vec<_>>();
    for commitment in note_commitments {
        public_values.extend(commitment.map(Val::from_u32));
    }
    public_values.extend(asset_id.map(Val::from_u8));
    debug_assert_eq!(public_values.len(), PUBLIC_VALUES);

    let config = make_hiding_config();
    let proof = prove(&config, &air, trace, &public_values);
    Ok(Poseidon2P24IntentValueConservationProof {
        config,
        proof,
        public_result: Poseidon2P24IntentValueConservationExperimentResult {
            intent: Poseidon2P24IntentExperimentResult {
                intent_commitment,
                trace_rows: TRACE_ROWS,
            },
            values: Poseidon2P24ValueConservationExperimentResult {
                note_commitments,
                asset_id,
                trace_rows: TRACE_ROWS,
            },
            trace_rows: TRACE_ROWS,
        },
    })
}

/// Independently verifies a retained local proof against one exact canonical
/// intent. Every public value is reconstructed rather than trusted from a
/// caller-supplied byte vector.
pub fn verify_p24_intent_value_conservation_proof(
    proof: &Poseidon2P24IntentValueConservationProof,
    intent: &PrivateTransferIntentV2,
) -> Result<Poseidon2P24IntentValueConservationExperimentResult, StarkExperimentError> {
    let reference = Poseidon2P24Reference::load_candidate()?;
    let air = Poseidon2P24IntentValueConservationAir::from_reference(&reference)?;
    let encoded = intent.encode();
    let result = proof.public_result();
    if result.values.asset_id != intent.asset_id().0
        || result.intent.trace_rows != TRACE_ROWS
        || result.values.trace_rows != TRACE_ROWS
        || result.trace_rows != TRACE_ROWS
    {
        return Err(StarkExperimentError::VerificationFailed);
    }
    let mut public_values = intent_byte_pack3le(encoded)
        .into_iter()
        .chain(result.intent.intent_commitment.elements())
        .map(Val::from_u32)
        .collect::<Vec<_>>();
    for commitment in result.values.note_commitments {
        public_values.extend(commitment.map(Val::from_u32));
    }
    public_values.extend(result.values.asset_id.map(Val::from_u8));
    debug_assert_eq!(public_values.len(), PUBLIC_VALUES);
    verify(&proof.config, &air, &proof.proof, &public_values)
        .map_err(|_| StarkExperimentError::VerificationFailed)?;
    Ok(result.clone())
}

/// Compatibility helper that proves and verifies in one process, then drops
/// the opaque proof and returns only its public result.
pub fn prove_and_verify_p24_intent_value_conservation(
    intent: &PrivateTransferIntentV2,
    note_preimages: [[u8; NOTE_INPUT_BYTES]; NOTE_COUNT],
) -> Result<Poseidon2P24IntentValueConservationExperimentResult, StarkExperimentError> {
    let proof = prove_p24_intent_value_conservation(intent, note_preimages)?;
    verify_p24_intent_value_conservation_proof(&proof, intent)
}

fn combine_traces(intent: RowMajorMatrix<Val>, values: RowMajorMatrix<Val>) -> RowMajorMatrix<Val> {
    debug_assert_eq!(intent.height(), TRACE_ROWS);
    debug_assert_eq!(values.height(), TRACE_ROWS);
    let mut combined = Val::zero_vec(TRACE_ROWS * TRACE_WIDTH);
    for row in 0..TRACE_ROWS {
        let destination = row * TRACE_WIDTH;
        let intent_offset = row * INTENT_TRACE_WIDTH;
        let value_offset = row * VALUE_TRACE_WIDTH;
        combined[destination..destination + INTENT_TRACE_WIDTH]
            .copy_from_slice(&intent.values[intent_offset..intent_offset + INTENT_TRACE_WIDTH]);
        combined[destination + INTENT_TRACE_WIDTH..destination + TRACE_WIDTH]
            .copy_from_slice(&values.values[value_offset..value_offset + VALUE_TRACE_WIDTH]);
    }
    RowMajorMatrix::new(combined, TRACE_WIDTH)
}
