# Local hybrid wallet-crypto demo v0.1

## Status

**Executable research evidence.** This demo exercises the local hybrid
recipient components. It does not create a persistent or spend-capable wallet,
authorize a transaction, prove ownership of a note, activate privacy, or
connect to a Noxis node.

## Run it

```powershell
cargo run -p noxis-wallet-crypto --bin noxis-wallet-crypto-demo
```

To create and reopen an explicit directory containing only one public address:

```powershell
cargo run -p noxis-wallet-crypto --bin noxis-wallet-crypto-demo -- address-book --data-dir .\target\noxis-public-addresses
```

To run the separate local receipt check for one encrypted 178-byte candidate
private note:

```powershell
cargo run -p noxis-wallet-crypto --bin noxis-wallet-crypto-demo -- private-note
```

That command derives recipient index zero from a fresh local wallet root,
converts the complete local recipient keyset into an incoming view key, then
recovers the note only after recomputing `H_NOTE` and matching its public output
commitment and `H_ADDR`. Its precise boundaries are documented in
[`WALLET_PRIVATE_NOTE_RECEIPT_LOCAL_V0_1.md`](WALLET_PRIVATE_NOTE_RECEIPT_LOCAL_V0_1.md),
[`WALLET_ROOT_SESSION_LOCAL_CANDIDATE_V0_1.md`](WALLET_ROOT_SESSION_LOCAL_CANDIDATE_V0_1.md)
and [`INCOMING_VIEW_KEY_LOCAL_CANDIDATE_V0_1.md`](INCOMING_VIEW_KEY_LOCAL_CANDIDATE_V0_1.md).

List and revalidate every managed public address in that directory with:

```powershell
cargo run -p noxis-wallet-crypto --bin noxis-wallet-crypto-demo -- address-book list --data-dir .\target\noxis-public-addresses
```

The command creates fresh process-local keys and performs this sequence:

1. create one diversified payment address at key epoch 1;
2. encode and strictly decode its public `NXPA v1` address bytes;
3. have a sender use only those decoded public bytes to encrypt a payload with
   X25519 + ML-KEM-768;
4. encode and strictly decode the bounded `NXRE v1` recipient envelope;
5. let the address owner authenticate and decrypt the payload;
6. show that an unrelated recipient is rejected; and
7. verify one Ed25519 + ML-DSA-65 identity signature over a domain-bound
   payload.

The program prints only a public address identifier and byte lengths. It never
prints or writes a private key, shared secret, plaintext, or envelope bytes.

## Public address book

`PublicAddressBook` stores each public `NXPA v1` encoding under an address-ID
derived filename. It holds an exclusive process-lifetime lock, writes a fresh
file through a synchronized temporary file and then reopens and decodes it
strictly. Storing the same address again is idempotent; altered or oversized
address bytes are rejected on load. Listing is deterministic by address ID and
revalidates every managed `address-<id>.nxpa` file before displaying its public
ID and key epoch.

This catalog intentionally has no private-key slot. Reopening it lets a sender
reuse public addresses, but cannot decrypt an envelope or spend a note. A
process crash can leave an ignored temporary public file, while any visible
entry has first been synchronized and then renamed. It is not a keystore,
backup format or wallet-recovery mechanism.

## What this establishes

The experimental crate has a concrete, runnable recipient flow with strict
address/envelope decoding and both classical and post-quantum key-agreement
components contributing to the encrypted payload. The identity check requires
both signature algorithms.

## What it does not establish

- It is not a wallet keystore, seed backup or key-rotation implementation.
- It is not a stealth-address or anonymous-payment protocol.
- It is not a persisted/exportable view key, block scanner, transaction
  construction or private settlement. A separate packet-bound local scanner
  exists in `noxis-private-packet-validation`, but it has no admission or
  chain-finality evidence.
- It does not bind `NXRE` bytes to an `NXPU` `CiphertextDigestV2`; the local
  candidate-note receipt is intentionally below that protocol gate.
- It does not make CometBFT transport, consensus, the node, or the protocol
  post-quantum secure.
- It is not approved for custody, public networks or production use.

The selected protocol profile still requires formal specification, independent
cryptographic review, vectors, adversarial testing and a genesis activation
decision. The crypto service remains fail-closed.
