# Architecture

## Dependency direction

```text
noxis-node ──> noxis-comet-abci ──> noxis-storage ──> noxis-execution ──> noxis-record-chain ──> noxis-codec
     │                │                     │                 │
     ├────────────> noxis-ledger ───────> noxis-crypto ──> noxis-types
     ├────────────> noxis-checkpoint ───> noxis-ledger / record-chain / types
     └────────────> noxis-runtime ──────> noxis-config ────> noxis-consensus

noxis-consensus ────────────────────────> noxis-record-chain / noxis-types

noxis-private-packet-validation ───────> noxis-codec + noxis-wallet-crypto
noxis-private-proof-contract ──────────> noxis-private-state ──> noxis-nullifier-tree-state
```

Dependencies point inward. Domain types never depend on storage, transport, cryptographic providers or application wiring.

## Responsibilities

| Module | Owns | Must not own |
| --- | --- | --- |
| `noxis-types` | stable IDs, amounts, asset taxonomy | state, I/O, cryptography |
| `noxis-crypto` | suite versioning, proof-verifier contract | ledger mutation, keys, network clients |
| `noxis-private-packet-validation` | candidate local `NXPT` → strict `NXRE` → `H_ENVELOPE` integrity boundary | proof verification, decryption, wallet storage, ledger mutation, mempool/network service |
| `noxis-nullifier-tree-state` | isolated mutable state and immutable proof paths for the unselected `NXSM` candidate | ledger mutation, persistence, proof packets, network or settlement |
| `noxis-private-proof-contract` | candidate `NXPU` statement, retained local proof bundle and fail-closed private-ledger authorizer adapter | portable proof format, persistence, ABCI or consensus activation |
| `noxis-private-state` | candidate note/nullifier state, typed anchor, transparent transition and atomic in-memory private-ledger admission | proof implementation, durable storage, packet availability, network or consensus |
| `noxis-ledger` | transaction shape, transition validation, state | concrete cryptography, databases, P2P |
| `noxis-record-chain` | canonical record encoding, sequence and state-link validation | ledger mutation, filesystem I/O, consensus |
| `noxis-checkpoint` | canonical `NXCP` encoding and snapshot integrity validation | filesystem I/O, replay policy, consensus |
| `noxis-consensus` | canonical BFT validator sets, block commitments, quorum and finality-certificate verification boundary | sockets, peer discovery, key storage, a homegrown consensus state machine |
| `noxis-execution` | deterministic no-I/O execution of an ordered block and `AppHash` calculation | filesystem I/O, network engine, finality claim |
| `noxis-config` | validated genesis, validation context and consensus configuration binding | filesystem, environment parsing, networking |
| `noxis-storage` | atomic `NXCB` block append, sync, replay coordination and tail recovery; legacy per-record storage; candidate `NXPR` private-state snapshot publication/reopen | protocol rules, network transport, genesis policy |
| `noxis-comet-abci` | Comet height mapping, strict v0.38 TCP/protobuf framing, volatile mempool/proposal/finalization lifecycle and the sole durable `Commit` boundary | validator private keys, Comet finality proof, P2P/network claims |
| `noxis-node` | dependency composition and future service startup | protocol rules |

## Incremental roadmap

1. The engine identity, parameter commitment and exact Comet v0.38 validator
   mapping are bound to genesis, the `NXMF` v7 manifest, every `NXCB` v2
   decision and `AppHash`. The core requires `InitChain` to present the same
   parameters and validators. The TCP ABCI v0.38 server and one
   checksum-pinned CometBFT v0.38.17 CI scenario now cover handshake, empty
   block/`Commit` and restart. Next, expand this evidence to coordinated
   recovery and adversarial multi-validator scenarios, then establish engine
   finality separately from the generic Noxis certificate.
2. Implement a consensus block-tip checkpoint containing height, `BlockId`,
   `AppHash`, and a future finality proof. This is distinct from the existing
   local `NXCP` snapshot artifact.
3. Replace the abstract proof boundary with an audited, independently reviewed
   backend and canonical state-root construction.
4. Add property and fuzz tests plus operating-system write-fault injection to
   persistence.
5. Add a wallet and chain adapters only after their threat models, failure
   modes, and recovery paths are specified.
6. Require an external cryptography and security audit before any testnet can
   carry transferable value.
