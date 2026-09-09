//! Explicit operator command for the candidate private-store v1-to-v2 copy.

use std::path::PathBuf;

fn main() {
    let (source, target) = match arguments() {
        Ok(paths) => paths,
        Err(message) => {
            eprintln!("{message}");
            eprintln!("usage: noxis-private-state-migrate --source PATH --target PATH");
            std::process::exit(2);
        }
    };
    println!("Noxis private-state migration — RESEARCH ONLY");
    println!("source: {}", source.display());
    println!("target: {}", target.display());
    println!("the source is retained; no historic receipt will be invented.");

    match noxis_storage::migrate_private_state_store_v1_to_submission_store_v2(&source, &target) {
        Ok(receipt) => {
            println!("migration ... accepted");
            println!("source final state: {}", receipt.source_state_id());
            println!("target final state: {}", receipt.target_state_id());
            println!("target durable receipt/state frames: 0");
        }
        Err(error) => {
            eprintln!("migration ... rejected: {error}");
            eprintln!("the target must be investigated or replaced; do not reuse it blindly.");
            std::process::exit(1);
        }
    }
}

fn arguments() -> Result<(PathBuf, PathBuf), &'static str> {
    arguments_from(std::env::args().skip(1))
}

fn arguments_from(
    values: impl IntoIterator<Item = String>,
) -> Result<(PathBuf, PathBuf), &'static str> {
    let mut source = None;
    let mut target = None;
    let mut values = values.into_iter();
    while let Some(argument) = values.next() {
        let value = values.next().ok_or("option requires a path")?;
        match argument.as_str() {
            "--source" if source.is_none() => source = Some(PathBuf::from(value)),
            "--target" if target.is_none() => target = Some(PathBuf::from(value)),
            "--source" | "--target" => return Err("option supplied more than once"),
            _ => return Err("unknown option"),
        }
    }
    match (source, target) {
        (Some(source), Some(target)) => Ok((source, target)),
        _ => Err("both --source and --target are required"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(parts: &[&str]) -> Vec<String> {
        parts.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn accepts_exact_source_and_target_pair() {
        let (source, target) = arguments_from(values(&[
            "--source",
            "old/state.nxpr",
            "--target",
            "new/state.nxpr",
        ]))
        .unwrap();
        assert_eq!(source, PathBuf::from("old/state.nxpr"));
        assert_eq!(target, PathBuf::from("new/state.nxpr"));
    }

    #[test]
    fn rejects_missing_duplicate_and_unknown_options() {
        assert_eq!(
            arguments_from(values(&["--source", "old"])),
            Err("both --source and --target are required")
        );
        assert_eq!(
            arguments_from(values(&[
                "--source", "old", "--source", "other", "--target", "new"
            ])),
            Err("option supplied more than once")
        );
        assert_eq!(
            arguments_from(values(&["--invalid", "old", "--target", "new"])),
            Err("unknown option")
        );
    }
}
