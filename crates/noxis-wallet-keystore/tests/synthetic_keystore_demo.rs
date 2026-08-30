#![cfg(feature = "research-testing")]

use std::{
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[test]
fn separate_create_and_restore_processes_complete_the_synthetic_backup_flow() {
    let root = std::env::temp_dir().join(format!(
        "noxis-keystore-synthetic-demo-process-{}-{}",
        std::process::id(),
        TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&root).unwrap();
    let source_wallet = root.join("source-wallet");
    let destination_wallet = root.join("destination-wallet");
    let bundle = root.join("backup.nxkb");
    let anchor = root.join("anchor.nxka");
    let binary = env!("CARGO_BIN_EXE_noxis-keystore-synthetic-demo");

    let create = Command::new(binary)
        .args([
            "create",
            "--wallet-dir",
            source_wallet.to_str().unwrap(),
            "--bundle",
            bundle.to_str().unwrap(),
            "--anchor",
            anchor.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        create.status.success(),
        "create failed: {}",
        String::from_utf8_lossy(&create.stderr)
    );
    assert!(String::from_utf8_lossy(&create.stdout).contains("backup created"));
    assert_eq!(std::fs::metadata(&bundle).unwrap().len(), 232);
    assert_eq!(std::fs::metadata(&anchor).unwrap().len(), 78);

    let restore = Command::new(binary)
        .args([
            "restore",
            "--wallet-dir",
            destination_wallet.to_str().unwrap(),
            "--bundle",
            bundle.to_str().unwrap(),
            "--anchor",
            anchor.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        restore.status.success(),
        "restore failed: {}",
        String::from_utf8_lossy(&restore.stderr)
    );
    assert!(String::from_utf8_lossy(&restore.stdout).contains("restore accepted"));
    assert!(destination_wallet.join("wallet-header.nxks").is_file());
    assert!(
        destination_wallet
            .join("payload-00000000000000000001.nxkp")
            .is_file()
    );

    assert!(root.starts_with(std::env::temp_dir()));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_real_process_stop_after_header_is_resumed_by_a_second_restore_process() {
    let root = std::env::temp_dir().join(format!(
        "noxis-keystore-synthetic-demo-stop-{}-{}",
        std::process::id(),
        TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&root).unwrap();
    let source_wallet = root.join("source-wallet");
    let destination_wallet = root.join("destination-wallet");
    let bundle = root.join("backup.nxkb");
    let anchor = root.join("anchor.nxka");
    let binary = env!("CARGO_BIN_EXE_noxis-keystore-synthetic-demo");

    let create = Command::new(binary)
        .args([
            "create",
            "--wallet-dir",
            source_wallet.to_str().unwrap(),
            "--bundle",
            bundle.to_str().unwrap(),
            "--anchor",
            anchor.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(create.status.success());

    let stopped = Command::new(binary)
        .args([
            "restore",
            "--wallet-dir",
            destination_wallet.to_str().unwrap(),
            "--bundle",
            bundle.to_str().unwrap(),
            "--anchor",
            anchor.to_str().unwrap(),
            "--stop-after-header",
        ])
        .output()
        .unwrap();
    assert_eq!(stopped.status.code(), Some(86));
    assert!(String::from_utf8_lossy(&stopped.stdout).contains("failpoint reached"));
    assert!(destination_wallet.join("wallet-header.nxks").is_file());
    assert!(
        !destination_wallet
            .join("payload-00000000000000000001.nxkp")
            .exists()
    );

    let resumed = Command::new(binary)
        .args([
            "restore",
            "--wallet-dir",
            destination_wallet.to_str().unwrap(),
            "--bundle",
            bundle.to_str().unwrap(),
            "--anchor",
            anchor.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        resumed.status.success(),
        "resume failed: {}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    let resumed_stdout = String::from_utf8_lossy(&resumed.stdout);
    assert!(resumed_stdout.contains("Header publication: AlreadyInitialized"));
    assert!(resumed_stdout.contains("Payload publication: Published"));
    assert!(
        destination_wallet
            .join("payload-00000000000000000001.nxkp")
            .is_file()
    );

    assert!(root.starts_with(std::env::temp_dir()));
    std::fs::remove_dir_all(root).unwrap();
}
