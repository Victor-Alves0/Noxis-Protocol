use noxis_stark_experiment::run_p24_research_smoke;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let result = run_p24_research_smoke()?;
    println!("Noxis Poseidon2-P24 STARK proof accepted");
    println!("Public input lane 0: {}", result.input[0]);
    println!("Public output lane 0: {}", result.output[0]);
    println!("Private permutation trace rows: {}", result.trace_rows);
    Ok(())
}
