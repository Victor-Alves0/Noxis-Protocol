use clap::Parser;
use noxis_private_proof_contract::{
    candidate_inner_relation_receipt_id_from_statement_id, CandidateInnerRelationKindV1,
};
use noxis_sp1_inner_receipt_lib::{derive_inner_receipt_id, InnerReceiptWitnessV1};
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, ProvingKey, SP1Stdin,
};

const INNER_RECEIPT_ELF: Elf = include_elf!("noxis-sp1-inner-receipt-program");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    execute: bool,

    #[arg(long)]
    prove: bool,
}

fn fixture() -> InnerReceiptWitnessV1 {
    InnerReceiptWitnessV1 {
        statement_id: [42; 32],
        relation_kind: CandidateInnerRelationKindV1::InputOwnership as u8,
        input_index_tag: 0,
    }
}

fn main() {
    sp1_sdk::utils::setup_logger();
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    let client = ProverClient::from_env();
    let witness = fixture();
    let expected = candidate_inner_relation_receipt_id_from_statement_id(
        witness.statement_id,
        CandidateInnerRelationKindV1::InputOwnership,
        Some(0),
    )
    .as_bytes();
    assert_eq!(derive_inner_receipt_id(witness), expected);
    let mut stdin = SP1Stdin::new();
    stdin.write(&witness);

    println!("Noxis SP1 inner-receipt spike");
    println!("relation: input-ownership (input 0)");
    println!("expected receipt id: {}", hex::encode(expected));

    if args.execute {
        let (output, report) = client.execute(INNER_RECEIPT_ELF, stdin).run().unwrap();
        assert_eq!(output.as_slice(), expected);
        println!("execution accepted; public receipt id matches Noxis derivation");
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        let pk = client
            .setup(INNER_RECEIPT_ELF)
            .expect("failed to setup elf");
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
