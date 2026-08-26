//! Unix-only process integration against a real pinned CometBFT v0.38 binary.
//!
//! This is intentionally an ignored test because it requires the external
//! CometBFT executable and Go fixture module. CI invokes it explicitly after
//! provisioning the pinned engine. The test does not grant the production node
//! any permissive proof verifier: its accepting verifier is private to this
//! test process and only makes it possible to exercise an empty consensus
//! block without a wallet or production proving system.
//!
//! It proves both a CometBFT process restart and a Noxis ABCI service restart
//! against the same durable journal. The application listener is stopped via
//! the explicit, controlled supervisor signal before the second service opens
//! the directory.

#![cfg(all(unix, feature = "research-testing"))]

use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use noxis_config::GenesisConfig;
use noxis_consensus::{
    CometBftNetworkIdentity, ConsensusConfig, Validator, ValidatorSet, ValidatorVerificationKey,
};
use noxis_crypto::{
    CryptoSuite, Proof, ProofVerifier, TransferStatement, ValidationContext, VerificationError,
};
use noxis_ledger::{DenyAllMints, MintPolicy};
use noxis_node::{CometNodeService, CometNodeServiceConfig, LocalAbciEndpoint};
use noxis_runtime::DataDirectory;
use noxis_types::{AssetDefinition, AssetId, AssetKind, ProofVerifierId, ValidatorId};

const COMETBFT_VERSION: &str = "0.38.17";
const MAXIMUM_BLOCK_RECORDS: u32 = 100;
const MAXIMUM_BLOCK_TRANSACTION_BYTES: u32 = 1_024;
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(15);

static TEMPORARY_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TemporaryDirectory(PathBuf);

impl TemporaryDirectory {
    fn new() -> Self {
        let sequence = TEMPORARY_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the current time must be after the Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "noxis-cometbft-e2e-{}-{nanos}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("test directory can be created");
        Self(path)
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Test-only verifier. It is deliberately not exported by any production crate.
struct EmptyBlockVerifier;

impl ProofVerifier for EmptyBlockVerifier {
    fn proof_verifier_id(&self) -> ProofVerifierId {
        ProofVerifierId::new([0xA1; 32])
    }

    fn verify_transfer(&self, _: &TransferStatement, _: &Proof) -> Result<(), VerificationError> {
        Ok(())
    }
}

#[derive(Debug)]
struct Fixture {
    chain_id: String,
    validator_key: [u8; 32],
    parameters_sha256: [u8; 32],
}

/// Runs only in the CI job that installs a real v0.38.17 CometBFT binary.
#[test]
#[ignore = "requires COMETBFT_BIN and the Go CometBFT v0.38 fixture"]
fn real_cometbft_handshake_empty_block_and_process_restart() {
    let workspace = TemporaryDirectory::new();
    let comet_binary = comet_binary();
    assert_comet_version(&comet_binary);

    let abci_address = reserve_loopback_address();
    let rpc_address = reserve_loopback_address();
    let p2p_address = reserve_loopback_address();
    let home = workspace.0.join("comet-home");
    let chain_id = format!("noxis-e2e-{}", std::process::id());
    let fixture = create_comet_fixture(
        &comet_binary,
        &home,
        &chain_id,
        abci_address,
        rpc_address,
        p2p_address,
    );
    assert_eq!(fixture.chain_id, chain_id);

    let node_directory =
        DataDirectory::new(workspace.0.join("noxis-node")).expect("test data directory is valid");
    let genesis = genesis_for_fixture(&fixture);
    let authorization = genesis
        .validation_context()
        .authorize_research_testing()
        .expect("fixture uses the explicitly enabled research suite");
    let service = Arc::new(
        CometNodeService::open(
            CometNodeServiceConfig::new(
                node_directory.clone(),
                genesis.clone(),
                LocalAbciEndpoint::new(abci_address).expect("reserved local address is loopback"),
            ),
            EmptyBlockVerifier,
            DenyAllMints,
            authorization,
        )
        .expect("test service can bind and initialize"),
    );
    assert_eq!(
        service.local_addr().expect("listener has local address"),
        abci_address
    );

    let application_thread = serve(Arc::clone(&service));

    let mut first = start_comet(&comet_binary, &home);
    // A Comet status height of one is the configured genesis height; wait for
    // the next height to prove the ABCI `FinalizeBlock`/`Commit` path ran.
    wait_for_height(rpc_address, 2, "first CometBFT startup");
    assert_application_height(rpc_address, 1);
    stop_comet(&mut first);
    stop_service(service, application_thread);

    // Opening a fresh service on the same data directory replays the durable
    // `NXCB` journal before it accepts the restarted engine's Info handshake.
    let authorization = genesis
        .validation_context()
        .authorize_research_testing()
        .expect("fixture uses the explicitly enabled research suite");
    let service = Arc::new(
        CometNodeService::open(
            CometNodeServiceConfig::new(
                node_directory.clone(),
                genesis,
                LocalAbciEndpoint::new(abci_address).expect("reserved local address is loopback"),
            ),
            EmptyBlockVerifier,
            DenyAllMints,
            authorization,
        )
        .expect("restarted service can recover the same journal"),
    );
    let application_thread = serve(Arc::clone(&service));
    let mut restarted = start_comet(&comet_binary, &home);
    wait_for_height(rpc_address, 3, "restarted CometBFT startup");
    assert_application_height(rpc_address, 2);
    stop_comet(&mut restarted);
    stop_service(service, application_thread);

    assert!(node_directory.block_journal_path().is_file());
}

fn comet_binary() -> PathBuf {
    std::env::var_os("COMETBFT_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("cometbft"))
}

fn assert_comet_version(binary: &Path) {
    let output = Command::new(binary)
        .arg("version")
        .output()
        .unwrap_or_else(|error| panic!("cannot execute {}: {error}", binary.display()));
    assert!(
        output.status.success(),
        "{} version failed: {}",
        binary.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        COMETBFT_VERSION,
        "the process fixture is reviewed only for CometBFT {COMETBFT_VERSION}"
    );
}

fn reserve_loopback_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback port is available");
    listener
        .local_addr()
        .expect("ephemeral listener has an address")
}

fn create_comet_fixture(
    comet_binary: &Path,
    home: &Path,
    chain_id: &str,
    abci_address: SocketAddr,
    rpc_address: SocketAddr,
    p2p_address: SocketAddr,
) -> Fixture {
    let fixture_directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("support")
        .join("comet_fixture");
    let output = Command::new("go")
        .arg("run")
        .arg(".")
        .arg("--home")
        .arg(home)
        .arg("--comet-binary")
        .arg(comet_binary)
        .arg("--chain-id")
        .arg(chain_id)
        .arg("--abci-address")
        .arg(abci_address.to_string())
        .arg("--rpc-address")
        .arg(rpc_address.to_string())
        .arg("--p2p-address")
        .arg(p2p_address.to_string())
        .current_dir(&fixture_directory)
        .output()
        .expect("Go is required to run the pinned CometBFT fixture");
    assert!(
        output.status.success(),
        "CometBFT fixture failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let fixture_output = String::from_utf8(output.stdout).expect("fixture output is UTF-8");
    let values = parse_fixture_output(&fixture_output);
    Fixture {
        chain_id: required_value(&values, "chain_id").to_owned(),
        validator_key: decode_fixed_hex(required_value(&values, "validator_key_hex")),
        parameters_sha256: decode_fixed_hex(required_value(&values, "parameters_sha256_hex")),
    }
}

fn parse_fixture_output(output: &str) -> BTreeMap<&str, &str> {
    output
        .lines()
        .map(|line| {
            line.split_once('=')
                .expect("fixture output uses key=value lines")
        })
        .collect()
}

fn required_value<'a>(values: &'a BTreeMap<&str, &str>, key: &str) -> &'a str {
    values
        .get(key)
        .copied()
        .unwrap_or_else(|| panic!("fixture did not return {key}"))
}

fn decode_fixed_hex(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64, "fixture must emit a 32-byte value in hex");
    let mut result = [0_u8; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .expect("fixture hex must contain valid bytes");
    }
    result
}

fn genesis_for_fixture(fixture: &Fixture) -> GenesisConfig {
    let verifier = EmptyBlockVerifier;
    let mint_policy = DenyAllMints;
    let validator = Validator::new(
        ValidatorId::new([0xB2; 32]),
        10,
        ValidatorVerificationKey::new(1, fixture.validator_key.to_vec())
            .expect("CometBFT supplies a 32-byte Ed25519 public key"),
    )
    .expect("test validator is valid");
    GenesisConfig::new_with_comet_bft_identity(
        4,
        vec![
            AssetDefinition::new(AssetId::new([0xC3; 32]), "ETE", AssetKind::Synthetic)
                .expect("test asset is valid"),
        ],
        ValidationContext::new(
            CryptoSuite::RESEARCH_V1,
            verifier.proof_verifier_id(),
            mint_policy.mint_policy_id(),
        ),
        ConsensusConfig::new(
            1,
            MAXIMUM_BLOCK_RECORDS,
            MAXIMUM_BLOCK_TRANSACTION_BYTES,
            0,
            ValidatorSet::new(vec![validator]).expect("test validator set is valid"),
        )
        .expect("test consensus configuration is valid"),
        CometBftNetworkIdentity::new(
            fixture.chain_id.clone(),
            1,
            "cometbft-0.38",
            fixture.parameters_sha256,
        )
        .expect("fixture engine identity is valid"),
    )
    .expect("test genesis is valid")
}

fn start_comet(binary: &Path, home: &Path) -> Child {
    Command::new(binary)
        .arg("start")
        .arg("--home")
        .arg(home)
        .arg("--log_level")
        .arg("error")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|error| panic!("cannot start CometBFT: {error}"))
}

fn stop_comet(process: &mut Child) {
    assert!(
        process
            .try_wait()
            .expect("CometBFT process status can be queried")
            .is_none(),
        "CometBFT exited before the test requested its restart"
    );
    process
        .kill()
        .expect("running CometBFT process can be terminated");
    let _ = process.wait().expect("CometBFT process can be reaped");
}

fn serve(service: Arc<CometNodeService>) -> thread::JoinHandle<()> {
    thread::spawn(move || service.serve().expect("ABCI serving loop is healthy"))
}

fn stop_service(service: Arc<CometNodeService>, task: thread::JoinHandle<()>) {
    service.request_shutdown();
    task.join()
        .expect("ABCI serving thread does not panic during controlled shutdown");
    drop(service);
}

fn wait_for_height(rpc_address: SocketAddr, minimum_height: u64, phase: &str) {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    let mut last_response = String::new();
    while Instant::now() < deadline {
        if let Ok(response) = rpc_get(rpc_address, "/status") {
            last_response = response;
            if json_integer(&last_response, "latest_block_height")
                .is_some_and(|height| height >= minimum_height)
            {
                return;
            }
        }
        thread::sleep(POLL_INTERVAL);
    }
    panic!(
        "{phase} did not reach height {minimum_height} within {:?}; last RPC response: {last_response}",
        STARTUP_TIMEOUT
    );
}

fn assert_application_height(rpc_address: SocketAddr, minimum_height: u64) {
    let response =
        rpc_get(rpc_address, "/abci_info").expect("CometBFT ABCI Info endpoint responds");
    let height = json_integer(&response, "last_block_height")
        .unwrap_or_else(|| panic!("ABCI Info did not expose last_block_height: {response}"));
    assert!(
        height >= minimum_height,
        "ABCI durable height {height} is below expected {minimum_height}: {response}"
    );
    assert!(
        response.contains("app_hash"),
        "ABCI Info must report the durable Noxis AppHash: {response}"
    );
}

fn rpc_get(address: SocketAddr, path: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(1))?;
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    stream.set_write_timeout(Some(Duration::from_secs(1)))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        address
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

fn json_integer(response: &str, key: &str) -> Option<u64> {
    let marker = format!("\"{key}\"");
    let (_, value) = response.split_once(&marker)?;
    let value = value.strip_prefix(':')?.trim_start();
    let value = value.strip_prefix('"').unwrap_or(value);
    let digits = value
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    digits.parse().ok()
}
