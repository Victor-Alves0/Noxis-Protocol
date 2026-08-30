//! Local, non-persistent demonstration of the experimental hybrid wallet
//! recipient components.

use noxis_wallet_crypto::{
    CANDIDATE_PRIVATE_NOTE_PREIMAGE_LENGTH, CandidatePrivateNoteEnvelopeV1,
    CandidatePrivateOutputSlotV1, HybridIdentityKeypair, HybridPaymentAddressEntry,
    PaymentAddressError, PublicAddressBook, RecipientEnvelopeContext,
    decode_hybrid_recipient_envelope, decode_payment_address, decrypt_candidate_private_note,
    encode_hybrid_recipient_envelope, encode_payment_address, encrypt_candidate_private_note,
};

const DEMO_CHAIN_ID: &[u8] = b"noxis-local-wallet-research";
const DEMO_KEY_EPOCH: u64 = 1;
const DEMO_PAYLOAD: &[u8] = b"noxis local recipient payload v1";
const IDENTITY_PAYLOAD: &[u8] = b"noxis local hybrid identity check v1";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match parse_mode(std::env::args().skip(1))? {
        DemoMode::Run => run_demo(),
        DemoMode::PrivateNote => run_private_note_demo(),
        DemoMode::AddressBook { directory } => run_address_book_demo(directory),
        DemoMode::AddressBookList { directory } => run_address_book_list(directory),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DemoMode {
    Run,
    PrivateNote,
    AddressBook { directory: std::path::PathBuf },
    AddressBookList { directory: std::path::PathBuf },
}

fn parse_mode(arguments: impl IntoIterator<Item = String>) -> Result<DemoMode, std::io::Error> {
    let arguments: Vec<String> = arguments.into_iter().collect();
    match arguments.as_slice() {
        [] => Ok(DemoMode::Run),
        [command] if command == "demo" => Ok(DemoMode::Run),
        [command] if command == "private-note" => Ok(DemoMode::PrivateNote),
        [command, flag, directory] if command == "address-book" && flag == "--data-dir" => {
            Ok(DemoMode::AddressBook {
                directory: std::path::PathBuf::from(directory),
            })
        }
        [command, list, flag, directory]
            if command == "address-book" && list == "list" && flag == "--data-dir" =>
        {
            Ok(DemoMode::AddressBookList {
                directory: std::path::PathBuf::from(directory),
            })
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "usage:\n  noxis-wallet-crypto-demo [demo]\n  noxis-wallet-crypto-demo private-note\n  noxis-wallet-crypto-demo address-book --data-dir PATH\n  noxis-wallet-crypto-demo address-book list --data-dir PATH",
        )),
    }
}

fn run_private_note_demo() -> Result<(), Box<dyn std::error::Error>> {
    let context = RecipientEnvelopeContext::new(DEMO_CHAIN_ID, DEMO_KEY_EPOCH)?;
    let recipient = HybridPaymentAddressEntry::generate(DEMO_KEY_EPOCH);
    let mut note = [0_u8; CANDIDATE_PRIVATE_NOTE_PREIMAGE_LENGTH];
    note[..2].copy_from_slice(&1_u16.to_be_bytes());
    note[2..34].copy_from_slice(&[7; 32]);
    note[34..50].copy_from_slice(&42_u128.to_be_bytes());
    // The remaining candidate witness fields are deliberately not displayed.
    for (index, byte) in note[50..].iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(29).wrapping_add(11);
    }

    let output = encrypt_candidate_private_note(recipient.address(), &context, note)?;
    let commitment = output.commitment();
    let ciphertext_digest =
        output.candidate_ciphertext_digest(CandidatePrivateOutputSlotV1::First)?;
    let envelope_bytes = encode_hybrid_recipient_envelope(output.envelope())?;
    let decoded_envelope = decode_hybrid_recipient_envelope(&envelope_bytes)?;
    let received = decrypt_candidate_private_note(
        &recipient,
        &context,
        &CandidatePrivateNoteEnvelopeV1::from_parts(commitment, decoded_envelope),
    )?;

    if received.commitment() != commitment {
        return Err("the candidate private-note commitment changed after receive".into());
    }

    println!("Noxis encrypted candidate-note demo — EXPERIMENTAL / LOCAL ONLY");
    println!("sender computed H_NOTE and encrypted one 178-byte candidate note ... accepted");
    println!(
        "strict NXRE envelope round trip ... accepted ({} bytes)",
        envelope_bytes.len()
    );
    println!("recipient authenticated, decrypted and recomputed H_NOTE ... accepted");
    println!("public output commitment: {commitment}");
    println!("candidate envelope digest bound to slot 0 and commitment: {ciphertext_digest}");
    println!("No note bytes, asset, value, secret key, balance or envelope bytes are printed.");
    println!("This is not a wallet, spend flow, ledger transaction or privacy activation.");
    println!("This candidate digest is not yet accepted by an intent, proof or ledger.");
    Ok(())
}

fn run_demo() -> Result<(), Box<dyn std::error::Error>> {
    let context = RecipientEnvelopeContext::new(DEMO_CHAIN_ID, DEMO_KEY_EPOCH)?;
    let recipient = HybridPaymentAddressEntry::generate(DEMO_KEY_EPOCH);
    let address_bytes = encode_payment_address(recipient.address());
    let sender_address = decode_payment_address(&address_bytes)?;
    let envelope = sender_address.encrypt_incoming(&context, DEMO_PAYLOAD)?;
    let envelope_bytes = encode_hybrid_recipient_envelope(&envelope)?;
    let received_envelope = decode_hybrid_recipient_envelope(&envelope_bytes)?;
    let plaintext = recipient.decrypt_incoming(&context, &received_envelope)?;
    let unrelated_recipient = HybridPaymentAddressEntry::generate(DEMO_KEY_EPOCH);
    let unrelated_rejection = unrelated_recipient.decrypt_incoming(&context, &received_envelope);
    let identity = HybridIdentityKeypair::generate();
    let signature = identity.sign(IDENTITY_PAYLOAD);

    if plaintext != DEMO_PAYLOAD {
        return Err("the recipient decrypted a different local demo payload".into());
    }
    if !identity.public_key().verify(IDENTITY_PAYLOAD, &signature) {
        return Err("the local hybrid identity signature did not verify".into());
    }
    if !matches!(
        unrelated_rejection,
        Err(PaymentAddressError::RecipientEnvelope(_))
    ) {
        return Err("an unrelated local recipient accepted the envelope".into());
    }

    print_demo(
        recipient.address().address_id(),
        address_bytes.len(),
        envelope_bytes.len(),
    );
    Ok(())
}

fn print_demo(address_id: [u8; 32], address_bytes: usize, envelope_bytes: usize) {
    println!("Noxis hybrid wallet-crypto demo — EXPERIMENTAL / LOCAL ONLY");
    println!("No key is persisted, and this does not create a spend-capable wallet.");
    println!("Diversified public address ID: {}", hex(&address_id));
    println!("encoded payment address ... accepted ({address_bytes} bytes)");
    println!("sender encrypted with X25519 + ML-KEM-768 ... accepted");
    println!("encoded recipient envelope ... accepted ({envelope_bytes} bytes)");
    println!("owner decrypted authenticated payload ... accepted");
    println!("unrelated recipient ... rejected");
    println!("Ed25519 + ML-DSA-65 identity signature ... accepted");
    println!(
        "No ledger transaction, note proof, custody, anonymity, or network security is claimed."
    );
}

fn run_address_book_demo(directory: std::path::PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let entry = HybridPaymentAddressEntry::generate(DEMO_KEY_EPOCH);
    let address_id = entry.address().address_id();
    let book = PublicAddressBook::open(&directory)?;
    let stored = book.store(entry.address())?;
    drop(book);
    let reopened = PublicAddressBook::open(&directory)?;
    let loaded = reopened.load(address_id)?;

    if loaded.address_id() != address_id {
        return Err("reopened public address does not match the stored address".into());
    }
    println!("Noxis public address-book demo — EXPERIMENTAL / PUBLIC DATA ONLY");
    println!("Directory: {}", directory.display());
    println!("stored public NXPA address ... {stored:?}");
    println!("reopened public NXPA address ... accepted");
    println!("Address ID: {}", hex(&address_id));
    println!(
        "No private recipient key, seed, spend key, note, balance, or transaction was stored."
    );
    Ok(())
}

fn run_address_book_list(directory: std::path::PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let book = PublicAddressBook::open(&directory)?;
    let addresses = book.list()?;

    println!("Noxis public address-book listing — EXPERIMENTAL / PUBLIC DATA ONLY");
    println!("Directory: {}", directory.display());
    println!("Canonical public addresses: {}", addresses.len());
    for address in addresses {
        println!(
            "- {} (key epoch {})",
            hex(&address.address_id()),
            address.key_epoch()
        );
    }
    println!("No private recipient key, seed, spend key, note, balance, or transaction was read.");
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{DemoMode, parse_mode};

    #[test]
    fn defaults_to_and_accepts_the_explicit_demo_command() {
        assert_eq!(parse_mode([]).unwrap(), DemoMode::Run);
        assert_eq!(parse_mode([String::from("demo")]).unwrap(), DemoMode::Run);
        assert_eq!(
            parse_mode([String::from("private-note")]).unwrap(),
            DemoMode::PrivateNote
        );
        assert_eq!(
            parse_mode([
                String::from("address-book"),
                String::from("--data-dir"),
                String::from("wallet-public"),
            ])
            .unwrap(),
            DemoMode::AddressBook {
                directory: std::path::PathBuf::from("wallet-public"),
            }
        );
        assert_eq!(
            parse_mode([
                String::from("address-book"),
                String::from("list"),
                String::from("--data-dir"),
                String::from("wallet-public"),
            ])
            .unwrap(),
            DemoMode::AddressBookList {
                directory: std::path::PathBuf::from("wallet-public"),
            }
        );
    }

    #[test]
    fn rejects_unknown_or_extra_demo_arguments() {
        assert!(parse_mode([String::from("other")]).is_err());
        assert!(parse_mode([String::from("demo"), String::from("extra")]).is_err());
        assert!(parse_mode([String::from("address-book")]).is_err());
        assert!(
            parse_mode([
                String::from("address-book"),
                String::from("list"),
                String::from("--data-dir"),
            ])
            .is_err()
        );
    }
}
