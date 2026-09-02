//! Command-line entry point for the local private-ledger research demo.

fn main() {
    println!("Noxis private-ledger demo — RESEARCH ONLY");
    println!("No wallet, portable proof, network or consensus claim is made.");
    println!("With --data-dir it persists one local candidate snapshot and reopens it.\n");
    println!("constructing candidate notes and proving three local STARK relations ...");

    let mut arguments = std::env::args().skip(1);
    let persistent_path = match arguments.next().as_deref() {
        None => None,
        Some("--data-dir") => match arguments.next() {
            Some(path) if arguments.next().is_none() => Some(std::path::PathBuf::from(path)),
            _ => {
                eprintln!("usage: noxis-private-ledger-demo [--data-dir PATH]");
                std::process::exit(2);
            }
        },
        Some(_) => {
            eprintln!("usage: noxis-private-ledger-demo [--data-dir PATH]");
            std::process::exit(2);
        }
    };
    let result = match persistent_path.as_deref() {
        Some(directory) => {
            noxis_private_proof_contract::run_candidate_private_ledger_persistent_demo(
                directory.join("private-state.nxpr"),
            )
        }
        None => noxis_private_proof_contract::run_candidate_private_ledger_demo(),
    };
    match result {
        Ok(report) => {
            println!("private transfer proof bundle ... accepted");
            println!(
                "candidate proof bundle envelope bytes: {}",
                report.proof_envelope_bytes()
            );
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
            println!("submitted same private transfer bytes ... rejected: stale state");
            if let Some(recovered) = report.recovered_state_id() {
                println!("reopened private state ... recovered: {recovered}");
            }
        }
        Err(error) => {
            eprintln!("Noxis private-ledger demo failed: {error}");
            std::process::exit(1);
        }
    }
}
