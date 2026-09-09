#![no_main]

use libfuzzer_sys::fuzz_target;
use noxis_private_proof_contract::{
    CANDIDATE_PRIVATE_PROOF_BUNDLE_ENVELOPE_CHECKSUM_DOMAIN, CandidatePrivateProofBundleEnvelopeV1,
    CandidatePrivateTransferProofDeploymentV1,
};
use sha2::{Digest, Sha256};

// A fuzzer does not need a valid private statement to exercise the framing
// boundary. A fixed expected value still forces all candidate inputs through
// the full magic/version/flags/deployment/length/checksum path when they reach
// the statement-ID comparison.
const EXPECTED_STATEMENT_ID: [u8; 32] = [0x5a; 32];

fuzz_target!(|bytes: &[u8]| {
    let _ = CandidatePrivateProofBundleEnvelopeV1::validate_framing(bytes, EXPECTED_STATEMENT_ID);
    let frame = structured_frame(bytes);
    let _ = CandidatePrivateProofBundleEnvelopeV1::validate_framing(&frame, EXPECTED_STATEMENT_ID);
});

// Random input almost never begins with `NXPP`. Build a small valid framing
// from every fuzzer input as a second path, so mutations reach canonical
// commitments, lengths and checksum checks from the first execution.
fn structured_frame(input: &[u8]) -> Vec<u8> {
    const FIXED_OVERHEAD: usize = 244;
    const DEPLOYMENT_ID_OFFSET: usize = 8;
    const STATEMENT_ID_OFFSET: usize = DEPLOYMENT_ID_OFFSET + 32;
    const INPUT_COMMITMENTS_OFFSET: usize = STATEMENT_ID_OFFSET + 32;
    const PROOF_LENGTHS_OFFSET: usize = INPUT_COMMITMENTS_OFFSET + 128;
    const PROOF_CHUNKS_OFFSET: usize = PROOF_LENGTHS_OFFSET + 12;
    const CHECKSUM_LENGTH: usize = 32;

    let proof_bytes = input.len().clamp(3, 4096);
    let first_length = proof_bytes / 3;
    let second_length = (proof_bytes - first_length) / 2;
    let lengths = [
        first_length,
        second_length,
        proof_bytes - first_length - second_length,
    ];
    let mut frame = vec![0_u8; FIXED_OVERHEAD + proof_bytes];
    frame[..4].copy_from_slice(b"NXPP");
    frame[4..6].copy_from_slice(&1_u16.to_be_bytes());
    frame[DEPLOYMENT_ID_OFFSET..STATEMENT_ID_OFFSET].copy_from_slice(
        &CandidatePrivateTransferProofDeploymentV1::new()
            .candidate_id()
            .expect("pinned candidate deployment")
            .as_bytes(),
    );
    frame[STATEMENT_ID_OFFSET..INPUT_COMMITMENTS_OFFSET].copy_from_slice(&EXPECTED_STATEMENT_ID);
    for commitment in frame[INPUT_COMMITMENTS_OFFSET..PROOF_LENGTHS_OFFSET].chunks_exact_mut(4) {
        commitment.copy_from_slice(&1_u32.to_le_bytes());
    }
    for (index, length) in lengths.into_iter().enumerate() {
        let start = PROOF_LENGTHS_OFFSET + (index * 4);
        frame[start..start + 4].copy_from_slice(&(length as u32).to_be_bytes());
    }
    let mut cursor = PROOF_CHUNKS_OFFSET;
    for index in 0..proof_bytes {
        frame[cursor] = input.get(index).copied().unwrap_or(index as u8);
        cursor += 1;
    }
    let checksum_start = frame.len() - CHECKSUM_LENGTH;
    let mut hasher = Sha256::new();
    hasher.update(CANDIDATE_PRIVATE_PROOF_BUNDLE_ENVELOPE_CHECKSUM_DOMAIN);
    hasher.update(&frame[..checksum_start]);
    frame[checksum_start..].copy_from_slice(&hasher.finalize());
    frame
}
