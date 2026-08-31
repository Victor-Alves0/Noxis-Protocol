use clap::Parser;
use noxis_poseidon2_core::root_from_note_path;
use noxis_poseidon2_reference::{BabyBearDigestV2, Poseidon2P24Reference};
use noxis_sp1_p24_membership_lib::{root_public_bytes, P24MembershipWitnessV1};
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, ProvingKey, SP1Stdin,
};

const MEMBERSHIP_ELF: Elf = include_elf!("noxis-sp1-p24-membership-program");

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    execute: bool,

    #[arg(long)]
    prove: bool,
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

    let client = ProverClient::from_env();
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
