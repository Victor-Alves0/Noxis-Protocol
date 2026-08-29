use noxis_stark_experiment::run_research_smoke;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let result = run_research_smoke()?;
    println!("Noxis STARK research proof accepted");
    println!("Public initial state: {}", result.initial_state);
    println!("Public final state: {}", result.final_state);
    println!("Private transition rows: {}", result.trace_rows);
    Ok(())
}
