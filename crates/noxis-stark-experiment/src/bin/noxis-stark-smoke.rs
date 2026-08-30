use noxis_stark_experiment::{
    run_p24_addr_research_smoke, run_p24_leaf_research_smoke, run_p24_merkle_path2_research_smoke,
    run_p24_merkle_path32_research_smoke, run_p24_merkle_step_research_smoke,
    run_p24_node_research_smoke, run_p24_note_ownership_research_smoke,
    run_p24_note_research_smoke,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match parse_smoke_mode(std::env::args().skip(1))? {
        SmokeMode::Default => run_default_smoke(),
        SmokeMode::NxsmPreflight => run_nxsm_preflight(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SmokeMode {
    Default,
    NxsmPreflight,
}

fn parse_smoke_mode(
    arguments: impl IntoIterator<Item = String>,
) -> Result<SmokeMode, Box<dyn std::error::Error>> {
    let arguments: Vec<String> = arguments.into_iter().collect();
    match arguments.as_slice() {
        [] => Ok(SmokeMode::Default),
        [command] if command == "nxsm-preflight" => Ok(SmokeMode::NxsmPreflight),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "usage: noxis-stark-smoke [nxsm-preflight]",
        )
        .into()),
    }
}

fn run_default_smoke() -> Result<(), Box<dyn std::error::Error>> {
    let addr = run_p24_addr_research_smoke()?;
    let note = run_p24_note_research_smoke()?;
    let ownership = run_p24_note_ownership_research_smoke()?;
    let leaf = run_p24_leaf_research_smoke()?;
    let node = run_p24_node_research_smoke()?;
    let merkle_step = run_p24_merkle_step_research_smoke()?;
    let merkle_path2 = run_p24_merkle_path2_research_smoke()?;
    let merkle_path32 = run_p24_merkle_path32_research_smoke()?;
    println!("Noxis Poseidon2-P24 private H_ADDR STARK proof accepted");
    println!(
        "Public recipient commitment lane 0: {}",
        addr.recipient_commitment[0]
    );
    println!("Noxis Poseidon2-P24 private H_NOTE STARK proof accepted");
    println!("Public note commitment lane 0: {}", note.note_commitment[0]);
    println!("Noxis Poseidon2-P24 private ownership-and-depth-32-membership STARK proof accepted");
    println!("Public nullifier lane 0: {}", ownership.nullifier[0]);
    println!(
        "Public ownership-membership root lane 0: {}",
        ownership.root[0]
    );
    println!("Noxis Poseidon2-P24 leaf STARK proof accepted");
    println!("Public commitment lane 0: {}", leaf.commitment[0]);
    println!("Public leaf lane 0: {}", leaf.leaf[0]);
    println!("Noxis Poseidon2-P24 ordered node STARK proof accepted");
    println!(
        "Public left/right lane 0: {}/{}",
        node.left[0], node.right[0]
    );
    println!("Public parent lane 0: {}", node.parent[0]);
    println!("Noxis Poseidon2-P24 private Merkle-step STARK proof accepted");
    println!(
        "Public Merkle-step parent lane 0: {}",
        merkle_step.parent[0]
    );
    println!("Noxis Poseidon2-P24 private two-level Merkle-path STARK proof accepted");
    println!("Public Merkle-path root lane 0: {}", merkle_path2.root[0]);
    println!("Noxis Poseidon2-P24 private depth-32 Merkle-path STARK proof accepted");
    println!("Public depth-32 root lane 0: {}", merkle_path32.root[0]);
    println!(
        "Private sponge trace rows (addr/note/ownership/leaf/node/step/path2/path32): {}/{}/{}/{}/{}/{}/{}/{}",
        addr.trace_rows,
        note.trace_rows,
        ownership.trace_rows,
        leaf.trace_rows,
        node.trace_rows,
        merkle_step.trace_rows,
        merkle_path2.trace_rows,
        merkle_path32.trace_rows
    );
    Ok(())
}

#[cfg(feature = "local-nxsm-preflight")]
fn run_nxsm_preflight() -> Result<(), Box<dyn std::error::Error>> {
    use noxis_nullifier_tree_state::NullifierSparseTreeStateV1;
    use noxis_poseidon2_reference::BabyBearDigestV2;
    use noxis_privacy_types::NullifierV2;
    use noxis_stark_experiment::run_p24_nxsm_absence_path512_sequential_preflight;

    if cfg!(debug_assertions) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "NXSM preflight requires an optimized build; rerun with --release",
        )
        .into());
    }

    let nullifier = NullifierV2::from_elements([10; 16])?;
    let mut tree = NullifierSparseTreeStateV1::new_candidate()?;
    tree.mark_spent(NullifierV2::from_elements([3; 16])?)?;
    tree.mark_spent(NullifierV2::from_elements([9; 16])?)?;
    let siblings: [BabyBearDigestV2; 512] = tree.prove(nullifier).siblings().try_into()?;
    let root = tree.root()?.elements();

    println!("Noxis NXSM local sequential preflight started");
    println!("Verifying 64 private eight-level segments; this can take about 32 minutes.");
    let result = run_p24_nxsm_absence_path512_sequential_preflight(nullifier, siblings, root)?;
    println!("Noxis NXSM local sequential preflight accepted");
    println!(
        "Verified and discarded private segments: {}",
        result.segments_verified
    );
    println!("Candidate root lane 0: {}", result.root[0]);
    println!(
        "Research-only local receipt: not a serialized, portable, aggregate, wallet, validator, or network proof."
    );
    Ok(())
}

#[cfg(not(feature = "local-nxsm-preflight"))]
fn run_nxsm_preflight() -> Result<(), Box<dyn std::error::Error>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "NXSM preflight is opt-in; rerun with --features local-nxsm-preflight --release",
    )
    .into())
}

#[cfg(test)]
mod tests {
    use super::{SmokeMode, parse_smoke_mode};

    #[test]
    fn defaults_to_the_regular_research_smoke() {
        assert_eq!(parse_smoke_mode([]).unwrap(), SmokeMode::Default);
    }

    #[test]
    fn accepts_only_the_explicit_nxsm_preflight_command() {
        assert_eq!(
            parse_smoke_mode([String::from("nxsm-preflight")]).unwrap(),
            SmokeMode::NxsmPreflight
        );
        assert!(parse_smoke_mode([String::from("nxsm-preflight"), String::from("extra")]).is_err());
    }
}
