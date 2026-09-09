//! Read and validate compact local status for a candidate `NXPL v2` store.

use std::path::PathBuf;

fn main() {
    let state_path = match arguments() {
        Ok(path) => path,
        Err(message) => {
            eprintln!("{message}");
            eprintln!("usage: noxis-private-state-status --state PATH");
            std::process::exit(2);
        }
    };
    match noxis_storage::PrivateSubmissionStoreV2::open(&state_path) {
        Ok(mut store) => match store.status() {
            Ok(status) => {
                println!("Noxis private-state status — RESEARCH ONLY");
                println!("state path: {}", state_path.display());
                println!("state ID: {}", status.state_id());
                println!("commitments: {}", status.commitment_count());
                println!(
                    "spent 64-byte nullifiers: {}",
                    status.spent_nullifier_count()
                );
                println!(
                    "durable local receipt/state frames: {}",
                    status.durable_submission_count()
                );
            }
            Err(error) => rejected(error),
        },
        Err(error) => rejected(error),
    }
}

fn rejected(error: impl std::fmt::Display) -> ! {
    eprintln!("private-state status ... rejected: {error}");
    eprintln!("this command accepts only a validated local NXPL v2 store.");
    std::process::exit(1);
}

fn arguments() -> Result<PathBuf, &'static str> {
    arguments_from(std::env::args().skip(1))
}

fn arguments_from(values: impl IntoIterator<Item = String>) -> Result<PathBuf, &'static str> {
    let mut values = values.into_iter();
    match (values.next().as_deref(), values.next(), values.next()) {
        (Some("--state"), Some(path), None) => Ok(PathBuf::from(path)),
        (Some("--state"), None, _) => Err("--state requires a path"),
        _ => Err("expected exactly one --state PATH pair"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(parts: &[&str]) -> Vec<String> {
        parts.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn accepts_only_one_state_argument() {
        assert_eq!(
            arguments_from(values(&["--state", "store/state.nxpr"])).unwrap(),
            PathBuf::from("store/state.nxpr")
        );
        assert_eq!(
            arguments_from(values(&["--state"])),
            Err("--state requires a path")
        );
        assert_eq!(
            arguments_from(values(&["--state", "a", "--state", "b"])),
            Err("expected exactly one --state PATH pair")
        );
    }
}
