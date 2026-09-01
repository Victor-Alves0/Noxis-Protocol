use clap::Parser;
use noxis_poseidon2_core::root_from_note_path;
use noxis_poseidon2_reference::{BabyBearDigestV2, Poseidon2P24Reference};
use noxis_sp1_p24_membership_lib::{root_public_bytes, P24MembershipWitnessV1};
use sp1_core_executor::{SP1CoreOpts, ShardingThreshold};
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, ProvingKey, SP1Stdin,
};

const MEMBERSHIP_ELF: Elf = include_elf!("noxis-sp1-p24-membership-program");
const LOCAL_SHARD_SIZE: usize = 500_000;
const LOCAL_ELEMENT_THRESHOLD: u64 = 1 << 26;
const LOCAL_HEIGHT_THRESHOLD: u64 = 1 << 20;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    execute: bool,

    #[arg(long)]
    prove: bool,

    /// Maximum cycles per internal SP1 shard in the local CPU prover.
    ///
    /// The full P24 relation is one guest program and one SP1 proof request;
    /// this limits per-shard prover memory, rather than stitching statements
    /// together in the host.
    #[arg(long, default_value_t = LOCAL_SHARD_SIZE)]
    shard_size: usize,
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
        LOCAL_ELEMENT_THRESHOLD, LOCAL_HEIGHT_THRESHOLD
    );

    let client = ProverClient::from_env().with_opts(SP1CoreOpts {
        shard_size: args.shard_size,
        sharding_threshold: ShardingThreshold {
            element_threshold: LOCAL_ELEMENT_THRESHOLD,
            height_threshold: LOCAL_HEIGHT_THRESHOLD,
        },
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
            .run()
            .expect("failed to generate proof");
        assert_eq!(proof.public_values.as_slice(), expected);
        client
            .verify(&proof, pk.verifying_key(), None)
            .expect("failed to verify proof");
        println!("core proof accepted and locally verified");
    }
}
