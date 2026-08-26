# Protocol Specification v0.1

## Status and scope

This document defines the initial safety boundary. Version 0.1 models the settlement core only; it intentionally excludes real custody, bridges, fiat settlement, price-oracle operation, liquidity-provider execution, networking, consensus, wallets, and production zero-knowledge cryptography.

## Design principles

1. The core never creates value from an off-chain claim.
2. A note is represented in consensus by a commitment; spending reveals a nullifier, not an account balance.
3. A nullifier is accepted at most once for the lifetime of a ledger state.
4. New commitments are immutable once accepted.
5. Minting is an explicit privileged transition, separated from ordinary transfer validation.
6. Cryptographic primitives are versioned configuration, never hard-coded protocol assumptions.

## State

```text
LedgerState
  assets: AssetId -> AssetDefinition
  commitments: set<Commitment>
  spent_nullifiers: set<Nullifier>
  issued_supply: AssetId -> Amount
  accepted_transactions: set<TransactionId>
```

`issued_supply` is the public accounting for authorized issuance. It is not a proof of external backing. Any asset-specific backing proof belongs in the authorization policy for that asset.

## Transaction transitions

### Transfer

```text
Transfer {
  asset_id,
  input_nullifiers,
  output_commitments,
  proof
}
```

The ledger verifies that the asset exists, every list is non-empty, output commitments are new, and every nullifier is new. It delegates ownership, membership, value conservation and privacy to `ProofVerifier`. The verifier receives a `TransferStatement` bound to the current Merkle root, the deployment `GenesisId`, the `ValidationContextId`, and the non-self-referential transaction-intent ID.

### Mint

```text
Mint {
  asset_id,
  amount,
  output_commitments,
  authorization
}
```

Minting requires a registered asset, positive amount, new commitments and a successful `MintPolicy` decision. The policy receives a `MintStatement` bound to the deployment `GenesisId`, `ValidationContextId`, transaction-intent ID, complete pre-transition `StateId`, current Merkle root, prior issued supply, asset, amount and output commitments. Its opaque authorization bytes are supplied separately. A future policy must authenticate that complete statement; it must never authorize an issuance based on an unbound amount, output list or external claim. The policy is where a future native-backed asset can demand an adapter proof, and a synthetic asset can demand collateral and oracle rules.

## Non-goals of v0.1

- No representation that a synthetic unit is redeemable for fiat.
- No mechanism intended to evade KYC/AML or other legal controls.
- No home-grown cryptographic primitive or claim of post-quantum security.
- No cross-chain adapter or external settlement confirmation.
