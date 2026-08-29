use noxis_stark_experiment::run_p24_leaf_research_smoke;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let result = run_p24_leaf_research_smoke()?;
    println!("Noxis Poseidon2-P24 leaf STARK proof accepted");
    println!("Public commitment lane 0: {}", result.commitment[0]);
    println!("Public leaf lane 0: {}", result.leaf[0]);
    println!("Private sponge trace rows: {}", result.trace_rows);
    Ok(())
}
