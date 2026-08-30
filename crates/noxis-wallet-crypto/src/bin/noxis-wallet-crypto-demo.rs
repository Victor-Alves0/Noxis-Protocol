//! Local, non-persistent demonstration of the experimental hybrid wallet
//! recipient components.

use noxis_wallet_crypto::{
    HybridIdentityKeypair, HybridPaymentAddressEntry, PaymentAddressError, PublicAddressBook,
    RecipientEnvelopeContext, decode_hybrid_recipient_envelope, decode_payment_address,
    encode_hybrid_recipient_envelope, encode_payment_address,
};

const DEMO_CHAIN_ID: &[u8] = b"noxis-local-wallet-research";
const DEMO_KEY_EPOCH: u64 = 1;
const DEMO_PAYLOAD: &[u8] = b"noxis local recipient payload v1";
const IDENTITY_PAYLOAD: &[u8] = b"noxis local hybrid identity check v1";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match parse_mode(std::env::args().skip(1))? {
        DemoMode::Run => run_demo(),
        DemoMode::AddressBook { directory } => run_address_book_demo(directory),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DemoMode {
    Run,
    AddressBook { directory: std::path::PathBuf },
}

fn parse_mode(arguments: impl IntoIterator<Item = String>) -> Result<DemoMode, std::io::Error> {
    let arguments: Vec<String> = arguments.into_iter().collect();
    match arguments.as_slice() {
        [] => Ok(DemoMode::Run),
        [command] if command == "demo" => Ok(DemoMode::Run),
        [command, flag, directory] if command == "address-book" && flag == "--data-dir" => {
            Ok(DemoMode::AddressBook {
                directory: std::path::PathBuf::from(directory),
            })
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "usage:\n  noxis-wallet-crypto-demo [demo]\n  noxis-wallet-crypto-demo address-book --data-dir PATH",
        )),
    }
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
    }

    #[test]
    fn rejects_unknown_or_extra_demo_arguments() {
        assert!(parse_mode([String::from("other")]).is_err());
        assert!(parse_mode([String::from("demo"), String::from("extra")]).is_err());
        assert!(parse_mode([String::from("address-book")]).is_err());
    }
}
