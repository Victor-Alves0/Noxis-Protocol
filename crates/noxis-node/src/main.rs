//! Local Noxis node executable.

#[cfg(feature = "research-testing")]
fn main() {
    if let Err(error) = run() {
        eprintln!("Noxis demo failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(feature = "research-testing")]
fn run() -> Result<(), String> {
    use std::path::PathBuf;

    use noxis_node::research_demo::run_local;
    use noxis_runtime::DataDirectory;

    let mut arguments = std::env::args().skip(1);
    match arguments.next().as_deref() {
        Some("demo-local") | Some("demo") => {}
        _ => return Err("usage: noxis-node demo-local [--data-dir PATH]".to_owned()),
    }
    let directory = match arguments.next().as_deref() {
        None => default_demo_directory(),
        Some("--data-dir") => arguments
            .next()
            .map(PathBuf::from)
            .ok_or_else(|| "--data-dir requires a path".to_owned())?,
        Some(argument) => return Err(format!("unknown demo argument: {argument}")),
    };
    if arguments.next().is_some() {
        return Err("too many demo arguments".to_owned());
    }
    let report = run_local(DataDirectory::new(&directory).map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())?;
    println!("Noxis local demo — RESEARCH ONLY");
    println!("No consensus, custody or privacy claim is made by this fixture.\n");
    println!("Noxis node initialized");
    println!("Data directory: {}", directory.display());
    println!("Genesis ID: {}", report.initial.genesis_id);
    println!("Height: {}", report.initial.sequence);
    println!("AppHash: not applicable (local admission is not a consensus block)");
    println!("State ID: {}\n", report.initial.state_id);
    println!(
        "submitted mint ... accepted (local sequence {})",
        report.mint.sequence
    );
    println!(
        "submitted research transfer ... accepted (local sequence {})",
        report.transfer.sequence
    );
    println!("submitted same nullifier ... rejected: NullifierAlreadySpent");
    println!(
        "reopened node ... recovered durable sequence {}",
        report.recovered.sequence
    );
    Ok(())
}

#[cfg(feature = "research-testing")]
fn default_demo_directory() -> std::path::PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time is after Unix epoch")
        .as_nanos();
    std::path::PathBuf::from("target")
        .join("noxis-demo-local")
        .join(format!("{}-{nonce}", std::process::id()))
}

#[cfg(not(feature = "research-testing"))]
fn main() {
    eprintln!(
        "Noxis local-node library is available. For the explicit research-only operational demo, run: cargo run -p noxis-node --features research-testing -- demo-local"
    );
}
