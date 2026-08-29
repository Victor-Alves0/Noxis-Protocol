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
    use noxis_node::research_demo::{initialize_local, run_local, status_local};
    use noxis_runtime::DataDirectory;

    let mut arguments = std::env::args().skip(1);
    match arguments.next().as_deref() {
        Some("demo-local") | Some("demo") => {
            let directory = optional_demo_directory(&mut arguments)?;
            let report =
                run_local(DataDirectory::new(&directory).map_err(|error| error.to_string())?)
                    .map_err(|error| error.to_string())?;
            print_demo(&directory, report);
        }
        Some("research") => match arguments.next().as_deref() {
            Some("init") => {
                let directory = required_data_directory(&mut arguments)?;
                let status = initialize_local(
                    DataDirectory::new(&directory).map_err(|error| error.to_string())?,
                )
                .map_err(|error| error.to_string())?;
                print_status("Noxis research node initialized", &directory, &status);
            }
            Some("status") => {
                let directory = required_data_directory(&mut arguments)?;
                let status = status_local(
                    DataDirectory::new(&directory).map_err(|error| error.to_string())?,
                )
                .map_err(|error| error.to_string())?;
                print_status("Noxis research node status", &directory, &status);
            }
            Some("demo") => {
                let directory = required_data_directory(&mut arguments)?;
                let report =
                    run_local(DataDirectory::new(&directory).map_err(|error| error.to_string())?)
                        .map_err(|error| error.to_string())?;
                print_demo(&directory, report);
            }
            _ => return Err(research_usage()),
        },
        _ => return Err(research_usage()),
    }
    Ok(())
}

#[cfg(feature = "research-testing")]
fn print_demo(directory: &std::path::Path, report: noxis_node::research_demo::ResearchDemoReport) {
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
}

#[cfg(feature = "research-testing")]
fn print_status(title: &str, directory: &std::path::Path, status: &noxis_node::LocalNodeStatus) {
    println!("{title} — RESEARCH ONLY");
    println!("No consensus, custody or privacy claim is made by this fixture.\n");
    println!("Data directory: {}", directory.display());
    println!("Genesis ID: {}", status.genesis_id);
    println!("Local sequence: {}", status.sequence);
    println!("State ID: {}", status.state_id);
}

#[cfg(feature = "research-testing")]
fn optional_demo_directory(
    arguments: &mut impl Iterator<Item = String>,
) -> Result<std::path::PathBuf, String> {
    let directory = match arguments.next().as_deref() {
        None => Ok(default_demo_directory()),
        Some("--data-dir") => arguments
            .next()
            .map(std::path::PathBuf::from)
            .ok_or_else(|| "--data-dir requires a path".to_owned()),
        Some(argument) => Err(format!("unknown demo argument: {argument}")),
    }?;
    if arguments.next().is_some() {
        return Err("too many command arguments".to_owned());
    }
    Ok(directory)
}

#[cfg(feature = "research-testing")]
fn required_data_directory(
    arguments: &mut impl Iterator<Item = String>,
) -> Result<std::path::PathBuf, String> {
    let directory = match arguments.next().as_deref() {
        Some("--data-dir") => arguments
            .next()
            .map(std::path::PathBuf::from)
            .ok_or_else(|| "--data-dir requires a path".to_owned())?,
        _ => {
            return Err(
                "--data-dir PATH is required for persistent research-node commands".to_owned(),
            );
        }
    };
    if arguments.next().is_some() {
        return Err("too many command arguments".to_owned());
    }
    Ok(directory)
}

#[cfg(feature = "research-testing")]
fn research_usage() -> String {
    "usage:\n  noxis-node demo-local [--data-dir PATH]\n  noxis-node research init --data-dir PATH\n  noxis-node research status --data-dir PATH\n  noxis-node research demo --data-dir PATH"
        .to_owned()
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
