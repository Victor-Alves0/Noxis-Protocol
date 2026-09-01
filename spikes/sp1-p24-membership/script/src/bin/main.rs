use clap::{Parser, ValueEnum};
use noxis_poseidon2_core::root_from_note_path;
use noxis_poseidon2_reference::{BabyBearDigestV2, Poseidon2P24Reference};
use noxis_sp1_p24_membership_lib::{root_public_bytes, P24MembershipWitnessV1};
use sp1_core_executor::{SP1CoreOpts, ShardingThreshold};
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, ProvingKey, SP1ProofMode, SP1Stdin,
};

const MEMBERSHIP_ELF: Elf = include_elf!("noxis-sp1-p24-membership-program");
const DEFAULT_LOCAL_SHARD_SIZE: usize = 500_000;
const DEFAULT_LOCAL_ELEMENT_THRESHOLD: u64 = 1 << 26;
const DEFAULT_LOCAL_HEIGHT_THRESHOLD: u64 = 1 << 20;
// This lowers peak prover memory by recomputing codewords for the query phase.
// It is a local proving-resource choice; it does not alter the guest relation.
const LOCAL_DROP_LDES: bool = true;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliProofMode {
    /// A proof per core shard. Its total size grows with execution length.
    Core,
    /// Recursively reduce core shards into one constant-size SP1 proof.
    Compressed,
}

impl CliProofMode {
    const fn as_sp1(self) -> SP1ProofMode {
        match self {
            Self::Core => SP1ProofMode::Core,
            Self::Compressed => SP1ProofMode::Compressed,
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    execute: bool,

    #[arg(long)]
    prove: bool,

    /// SP1 proof pipeline used after executing the unchanged guest relation.
    ///
    /// Compressed is the relevant recursion experiment: it reduces the core
    /// shards inside SP1 instead of returning a linearly growing core proof.
    #[arg(long, value_enum, default_value_t = CliProofMode::Compressed)]
    proof_mode: CliProofMode,

    /// Maximum cycles per internal SP1 shard in the local CPU prover.
    ///
    /// The full P24 relation is one guest program and one SP1 proof request;
    /// this limits per-shard prover memory, rather than stitching statements
    /// together in the host.
    #[arg(long, default_value_t = DEFAULT_LOCAL_SHARD_SIZE)]
    shard_size: usize,

    /// Trace-area limit that causes SP1 to start a fresh internal shard.
    ///
    /// This is a local prover resource setting, not part of the guest
    /// statement or the public output.
    #[arg(long, default_value_t = DEFAULT_LOCAL_ELEMENT_THRESHOLD)]
    element_threshold: u64,

    /// Trace-height limit that causes SP1 to start a fresh internal shard.
    ///
    /// This is a local prover resource setting, not part of the guest
    /// statement or the public output.
    #[arg(long, default_value_t = DEFAULT_LOCAL_HEIGHT_THRESHOLD)]
    height_threshold: u64,
}

fn fixture() -> (P24MembershipWitnessV1, BabyBearDigestV2) {
    let reference = Poseidon2P24Reference::load_candidate().expect("frozen P24 candidate");
    let commitments = [
        core::array::from_fn(|index| (index as u32) + 7),
        core::array::from_fn(|index| (index as u32) + 107),
    ];
    let (_leaf, siblings, root) = reference
        .small_tree_path(&commitments, 1)
        .expect("fixed P24 path");
    (
        P24MembershipWitnessV1 {
            note_commitment: commitments[1],
            leaf_index: 1,
            siblings,
        },
        root,
    )
}

fn main() {
    sp1_sdk::utils::setup_logger();
    let args = Args::parse();
    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    let (witness, expected_root) = fixture();
    assert_eq!(
        root_from_note_path(
            witness.note_commitment,
            witness.leaf_index,
            witness.siblings
        )
        .expect("canonical fixture"),
        expected_root
    );
    let expected = root_public_bytes(expected_root);
    let mut stdin = SP1Stdin::new();
    stdin.write(&witness);

    println!("Noxis SP1 P24 membership spike");
    println!("relation: private note commitment + depth-32 sibling path");
    println!("public root: {}", hex::encode(expected));
    println!("local SP1 shard size: {} cycles", args.shard_size);
    println!(
        "local SP1 trace thresholds: {} elements / {} rows",
        args.element_threshold, args.height_threshold
    );
    println!(
        "local SP1 query codewords: {}",
        if LOCAL_DROP_LDES {
            "recomputed to reduce peak memory"
        } else {
            "retained"
        }
    );
    if args.prove {
        println!("SP1 proof mode: {:?}", args.proof_mode);
    }

    let client = ProverClient::from_env().with_opts(SP1CoreOpts {
        shard_size: args.shard_size,
        sharding_threshold: ShardingThreshold {
            element_threshold: args.element_threshold,
            height_threshold: args.height_threshold,
        },
        drop_ldes: LOCAL_DROP_LDES,
        ..Default::default()
    });
    if args.execute {
        let (output, report) = client.execute(MEMBERSHIP_ELF, stdin).run().unwrap();
        assert_eq!(output.as_slice(), expected);
        println!("execution accepted; public root matches the Noxis P24 reference path");
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        let pk = client.setup(MEMBERSHIP_ELF).expect("failed to setup elf");
        let proof = client
            .prove(&pk, stdin)
            .mode(args.proof_mode.as_sp1())
            .run()
            .expect("failed to generate proof");
        assert_eq!(proof.public_values.as_slice(), expected);
        client
            .verify(&proof, pk.verifying_key(), None)
            .expect("failed to verify proof");
        println!(
            "{} proof accepted and locally verified",
            match args.proof_mode {
                CliProofMode::Core => "core",
                CliProofMode::Compressed => "compressed",
            }
        );
    }
}
