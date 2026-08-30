//! Research-only operational demonstration for synthetic keystore recovery.
//!
//! This binary never creates, receives or unlocks a user wallet secret. Its
//! fixed synthetic root and password exist only to exercise the public/opaque
//! `NXKS` + `NXKP` + `NXKB` + external `NXKA` lifecycle across processes.

use std::{
    error::Error,
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
};

use noxis_wallet_keystore::{
    CandidateKeystoreHeaderStore, CandidateKeystorePayloadV1, CandidateSyntheticRecoveryBundleV1,
    EXTERNAL_ROLLBACK_ANCHOR_V1_LENGTH, ExternalRollbackAnchorV1, HeaderStoreInitializeOutcome,
    KeystoreHeaderV2, PayloadStorePublishOutcome, SYNTHETIC_RECOVERY_BUNDLE_V1_LENGTH,
};
use rand_core::{OsRng, RngCore as _};

const SYNTHETIC_PASSWORD: &[u8] = b"noxis-research-demo-not-a-user-password";
const SYNTHETIC_ROOT: [u8; 64] = [0xA5; 64];

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = parse_command(&args)?;
    match command {
        Command::Create {
            wallet_dir,
            bundle,
            anchor,
        } => create(wallet_dir, bundle, anchor),
        Command::Restore {
            wallet_dir,
            bundle,
            anchor,
            stop_after_header,
        } => restore(wallet_dir, bundle, anchor, stop_after_header),
    }
}

enum Command {
    Create {
        wallet_dir: PathBuf,
        bundle: PathBuf,
        anchor: PathBuf,
    },
    Restore {
        wallet_dir: PathBuf,
        bundle: PathBuf,
        anchor: PathBuf,
        stop_after_header: bool,
    },
}

fn parse_command(args: &[String]) -> Result<Command, Box<dyn Error>> {
    if args.len() != 7 && args.len() != 8 {
        return Err(usage().into());
    }
    let wallet_dir = value_after(args, "--wallet-dir")?;
    let bundle = value_after(args, "--bundle")?;
    let anchor = value_after(args, "--anchor")?;
    match args[0].as_str() {
        "create" if args.len() == 7 => Ok(Command::Create {
            wallet_dir,
            bundle,
            anchor,
        }),
        "restore" => Ok(Command::Restore {
            wallet_dir,
            bundle,
            anchor,
            stop_after_header: optional_stop_after_header(args)?,
        }),
        _ => Err(usage().into()),
    }
}

fn optional_stop_after_header(args: &[String]) -> Result<bool, Box<dyn Error>> {
    match args.len() {
        7 => Ok(false),
        8 if args[7] == "--stop-after-header" => Ok(true),
        _ => Err(usage().into()),
    }
}

fn value_after(args: &[String], flag: &str) -> Result<PathBuf, Box<dyn Error>> {
    let Some(index) = args.iter().position(|arg| arg == flag) else {
        return Err(usage().into());
    };
    let Some(value) = args.get(index + 1) else {
        return Err(usage().into());
    };
    Ok(PathBuf::from(value))
}

fn create(wallet_dir: PathBuf, bundle: PathBuf, anchor: PathBuf) -> Result<(), Box<dyn Error>> {
    let store = CandidateKeystoreHeaderStore::open(&wallet_dir)?;
    ensure_external_to_wallet(&bundle, store.path())?;
    ensure_external_to_wallet(&anchor, store.path())?;
    let header = fresh_header()?;
    if store.initialize(header)? != HeaderStoreInitializeOutcome::Initialized {
        return Err("research demo wallet directory is already initialized".into());
    }
    let payload = CandidateKeystorePayloadV1::seal_research_synthetic_fixture(
        header,
        1,
        fresh_nonce(),
        SYNTHETIC_PASSWORD,
        &SYNTHETIC_ROOT,
    )?;
    let external_anchor =
        ExternalRollbackAnchorV1::new(header.id(), payload.generation(), payload.ciphertext_id())?;
    if store.open_payloads()?.publish(payload, external_anchor)?
        != PayloadStorePublishOutcome::Published
    {
        return Err("research demo synthetic payload was unexpectedly already published".into());
    }
    let recovery_bundle = CandidateSyntheticRecoveryBundleV1::capture(&store, external_anchor)?;
    write_new_synchronized(&bundle, &recovery_bundle.encode())?;
    write_new_synchronized(&anchor, &external_anchor.encode())?;

    println!("Noxis synthetic keystore backup created");
    println!("Wallet directory: {}", store.path().display());
    println!("Bundle (NXKB): {}", bundle.display());
    println!("External anchor (NXKA): {}", anchor.display());
    println!("Generation: {}", payload.generation());
    println!("accepted: synthetic ciphertext only; no user wallet secret exists");
    Ok(())
}

fn restore(
    wallet_dir: PathBuf,
    bundle: PathBuf,
    anchor: PathBuf,
    stop_after_header: bool,
) -> Result<(), Box<dyn Error>> {
    let store = CandidateKeystoreHeaderStore::open(&wallet_dir)?;
    ensure_external_to_wallet(&bundle, store.path())?;
    ensure_external_to_wallet(&anchor, store.path())?;
    let recovery_bundle = CandidateSyntheticRecoveryBundleV1::decode(&read_exact(
        &bundle,
        SYNTHETIC_RECOVERY_BUNDLE_V1_LENGTH,
    )?)?;
    let external_anchor = ExternalRollbackAnchorV1::decode(&read_exact(
        &anchor,
        EXTERNAL_ROLLBACK_ANCHOR_V1_LENGTH,
    )?)?;
    if stop_after_header {
        recovery_bundle.verify_external_anchor(external_anchor)?;
        let header = store.initialize(recovery_bundle.header())?;
        println!("Noxis synthetic restore failpoint reached");
        println!("Header publication: {:?}", header);
        println!("process intentionally stopped before payload publication");
        std::process::exit(86);
    }
    let outcome = recovery_bundle.restore(&store, external_anchor)?;

    println!("Noxis synthetic keystore restore accepted");
    println!("Wallet directory: {}", store.path().display());
    println!("Header publication: {:?}", outcome.header);
    println!("Payload publication: {:?}", outcome.payload);
    println!("accepted: external NXKA matched the exact synthetic payload");
    Ok(())
}

fn fresh_header() -> Result<KeystoreHeaderV2, Box<dyn Error>> {
    let mut wallet_id = [0_u8; 32];
    OsRng.fill_bytes(&mut wallet_id);
    if wallet_id.iter().all(|byte| *byte == 0) {
        wallet_id[0] = 1;
    }
    Ok(KeystoreHeaderV2::generate(wallet_id, 0)?)
}

fn fresh_nonce() -> [u8; 24] {
    let mut nonce = [0_u8; 24];
    OsRng.fill_bytes(&mut nonce);
    if nonce.iter().all(|byte| *byte == 0) {
        nonce[0] = 1;
    }
    nonce
}

fn ensure_external_to_wallet(path: &Path, wallet_dir: &Path) -> Result<(), Box<dyn Error>> {
    let wallet_dir = fs::canonicalize(wallet_dir)?;
    let parent = path
        .parent()
        .ok_or("research demo external artifact requires a parent directory")?;
    let parent = fs::canonicalize(parent)?;
    if parent.starts_with(&wallet_dir) {
        return Err("research demo NXKA/NXKB artifact must be outside the wallet directory".into());
    }
    Ok(())
}

fn write_new_synchronized(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn read_exact(path: &Path, expected_length: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let metadata = fs::metadata(path)?;
    if metadata.len() != expected_length as u64 {
        return Err(format!(
            "research demo artifact {} has {} bytes; expected {expected_length}",
            path.display(),
            metadata.len(),
        )
        .into());
    }
    Ok(fs::read(path)?)
}

fn usage() -> String {
    "usage:\n  noxis-keystore-synthetic-demo create --wallet-dir <dir> --bundle <external.nxkb> --anchor <external.nxka>\n  noxis-keystore-synthetic-demo restore --wallet-dir <new-dir> --bundle <external.nxkb> --anchor <external.nxka> [--stop-after-header]".to_owned()
}
