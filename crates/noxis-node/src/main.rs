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
    use noxis_node::{
        SubmissionOutcome,
        research_demo::{
            fixture_duplicate_nullifier_bytes, fixture_mint_bytes, fixture_transfer_bytes,
            initialize_local, run_local, status_local, submit_local,
        },
    };
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
            Some("fixture") => match arguments.next().as_deref() {
                Some("mint-hex") => print_fixture_hex(
                    "mint",
                    fixture_mint_bytes().map_err(|error| error.to_string())?,
                ),
                Some("transfer-hex") => print_fixture_hex(
                    "transfer",
                    fixture_transfer_bytes().map_err(|error| error.to_string())?,
                ),
                Some("duplicate-nullifier-hex") => print_fixture_hex(
                    "duplicate-nullifier transfer",
                    fixture_duplicate_nullifier_bytes().map_err(|error| error.to_string())?,
                ),
                _ => return Err(research_usage()),
            },
            Some("submit") => {
                let (directory, transaction_bytes) = required_submission(&mut arguments)?;
                match submit_local(
                    DataDirectory::new(&directory).map_err(|error| error.to_string())?,
                    &transaction_bytes,
                )
                .map_err(|error| error.to_string())?
                {
                    SubmissionOutcome::LocallyDurable(receipt) => {
                        println!("Noxis research submission accepted — RESEARCH ONLY");
                        println!("Local sequence: {}", receipt.sequence);
                        println!("State ID: {}", receipt.state_id);
                        println!("Transaction intent ID: {}", receipt.transaction_intent_id);
                    }
                    SubmissionOutcome::Rejected(rejection) => {
                        println!("Noxis research submission rejected — RESEARCH ONLY");
                        println!("Reason: {rejection:?}");
                    }
                    SubmissionOutcome::Unavailable(unavailable) => {
                        return Err(format!("research node unavailable: {unavailable:?}"));
                    }
                }
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
fn required_submission(
    arguments: &mut impl Iterator<Item = String>,
) -> Result<(std::path::PathBuf, Vec<u8>), String> {
    let directory = match arguments.next().as_deref() {
        Some("--data-dir") => arguments
            .next()
            .map(std::path::PathBuf::from)
            .ok_or_else(|| "--data-dir requires a path".to_owned())?,
        _ => return Err("--data-dir PATH is required for research submit".to_owned()),
    };
    let hex = match arguments.next().as_deref() {
        Some("--transaction-hex") => arguments
            .next()
            .ok_or_else(|| "--transaction-hex requires canonical hexadecimal bytes".to_owned())?,
        _ => return Err("--transaction-hex HEX is required for research submit".to_owned()),
    };
    if arguments.next().is_some() {
        return Err("too many command arguments".to_owned());
    }
    Ok((directory, decode_hex(&hex)?))
}

#[cfg(feature = "research-testing")]
fn print_fixture_hex(kind: &str, bytes: Vec<u8>) {
    println!("Noxis {kind} fixture bytes — RESEARCH ONLY");
    println!("Use only with the matching explicit research node configuration.");
    println!("{}", encode_hex(&bytes));
}

#[cfg(feature = "research-testing")]
fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}

#[cfg(feature = "research-testing")]
fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return Err(
            "transaction hex must be non-empty and have an even number of digits".to_owned(),
        );
    }
    fn nibble(value: u8) -> Option<u8> {
        match value {
            b'0'..=b'9' => Some(value - b'0'),
            b'a'..=b'f' => Some(value - b'a' + 10),
            b'A'..=b'F' => Some(value - b'A' + 10),
            _ => None,
        }
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = nibble(pair[0]).ok_or_else(|| {
            format!(
                "transaction hex contains an invalid digit at position {}",
                index * 2
            )
        })?;
        let low = nibble(pair[1]).ok_or_else(|| {
            format!(
                "transaction hex contains an invalid digit at position {}",
                (index * 2) + 1
            )
        })?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

#[cfg(feature = "research-testing")]
fn research_usage() -> String {
    "usage:\n  noxis-node demo-local [--data-dir PATH]\n  noxis-node research init --data-dir PATH\n  noxis-node research status --data-dir PATH\n  noxis-node research demo --data-dir PATH\n  noxis-node research fixture mint-hex|transfer-hex|duplicate-nullifier-hex\n  noxis-node research submit --data-dir PATH --transaction-hex HEX"
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

#[cfg(all(test, feature = "research-testing"))]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip_and_rejects_ambiguous_input() {
        assert_eq!(
            decode_hex(&encode_hex(&[0, 0xab, 0xff])).unwrap(),
            [0, 0xab, 0xff]
        );
        assert!(decode_hex("").is_err());
        assert!(decode_hex("0").is_err());
        assert!(decode_hex("0g").is_err());
    }
}
