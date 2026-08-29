use noxis_stark_experiment::{run_p24_leaf_research_smoke, run_p24_node_research_smoke};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let leaf = run_p24_leaf_research_smoke()?;
    let node = run_p24_node_research_smoke()?;
    println!("Noxis Poseidon2-P24 leaf STARK proof accepted");
    println!("Public commitment lane 0: {}", leaf.commitment[0]);
    println!("Public leaf lane 0: {}", leaf.leaf[0]);
    println!("Noxis Poseidon2-P24 ordered node STARK proof accepted");
    println!(
        "Public left/right lane 0: {}/{}",
        node.left[0], node.right[0]
    );
    println!("Public parent lane 0: {}", node.parent[0]);
    println!(
        "Private sponge trace rows (leaf/node): {}/{}",
        leaf.trace_rows, node.trace_rows
    );
    Ok(())
}
