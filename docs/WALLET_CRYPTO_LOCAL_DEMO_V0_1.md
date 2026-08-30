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

## What this establishes

The experimental crate has a concrete, runnable recipient flow with strict
address/envelope decoding and both classical and post-quantum key-agreement
components contributing to the encrypted payload. The identity check requires
both signature algorithms.

## What it does not establish

- It is not a wallet keystore, seed backup or key-rotation implementation.
- It is not a stealth-address or anonymous-payment protocol.
- It is not proof generation, note scanning, transaction construction or
  private settlement.
- It does not make CometBFT transport, consensus, the node, or the protocol
  post-quantum secure.
- It is not approved for custody, public networks or production use.

The selected protocol profile still requires formal specification, independent
cryptographic review, vectors, adversarial testing and a genesis activation
decision. The crypto service remains fail-closed.
