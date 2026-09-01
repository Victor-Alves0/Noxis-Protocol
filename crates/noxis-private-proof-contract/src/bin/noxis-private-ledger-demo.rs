//! Command-line entry point for the local private-ledger research demo.

fn main() {
    println!("Noxis private-ledger demo — RESEARCH ONLY");
    println!("No wallet, portable proof, persistence, network or consensus claim is made.\n");
    println!("constructing candidate notes and proving three local STARK relations ...");

    match noxis_private_proof_contract::run_candidate_private_ledger_demo() {
        Ok(report) => {
            println!("private transfer proof bundle ... accepted");
            println!("pre-state ID: {}", report.initial_state_id());
            println!("post-state ID: {}", report.accepted().post_state_id());
            println!(
                "commitments: {} -> {}",
                report.initial_commitment_count(),
                report.final_commitment_count()
            );
            println!(
                "spent 64-byte nullifiers: {} -> {}",
                report.initial_spent_nullifier_count(),
                report.final_spent_nullifier_count()
            );
            println!("submitted same private transfer ... rejected: StateTransition");
        }
        Err(error) => {
            eprintln!("Noxis private-ledger demo failed: {error}");
            std::process::exit(1);
        }
    }
}
