# Cryptography Guide

Noxis treats cryptographic selection as a deployment decision, not branding.
Every selected primitive needs an exact statement, domain separation,
canonical encoding, versioned parameters, reproducible vectors, negative
tests and independent review.

## Current position

- The legacy ledger state uses its current research implementation boundaries;
  it is not a private-transfer construction.
- Poseidon2-P24 is a frozen **candidate** for private-note and tree work. A
  dense reference evaluator, external vectors and a STARK experiment for its
  permutation, candidate leaf hash, ordered candidate node hash and one
  private ordered Merkle step exist; the candidate is not selected for
  production.
- The proof direction is transparent STARK/AIR. A complete private-transfer
  statement and production verifier do not yet exist.
- The hybrid wallet profile is experimental. It does not enable active
  post-quantum protection or establish a sound combiner by itself.

Read [CRYPTOGRAPHY_DECISION_V0_1.md](CRYPTOGRAPHY_DECISION_V0_1.md) for the
decision record and [CRYPTO_SERVICE_GATE_V0_1.md](CRYPTO_SERVICE_GATE_V0_1.md)
for the fail-closed service boundary.
