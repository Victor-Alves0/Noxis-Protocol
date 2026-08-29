use noxis_stark_experiment::{
    run_p24_addr_research_smoke, run_p24_leaf_research_smoke, run_p24_merkle_path2_research_smoke,
    run_p24_merkle_path32_research_smoke, run_p24_merkle_step_research_smoke,
    run_p24_node_research_smoke, run_p24_note_ownership_research_smoke,
    run_p24_note_research_smoke,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
