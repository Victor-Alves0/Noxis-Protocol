# Wallet keystore security gate v0.1

## Status

**Decision gate — no user secret persistence is implemented or approved.**

`noxis-wallet-crypto` currently keeps recipient and identity secrets only in
process memory. Its persistent `PublicAddressBook` deliberately accepts only
canonical public `NXPA` address bytes. It cannot store a seed, private key,
shared secret, note, balance or proof.

This boundary is intentional. Encrypting an arbitrary byte blob with a
password is not, on its own, a safe wallet keystore. The isolated
`noxis-wallet-keystore` crate now parses and atomically stores only public
candidate `NXKS` headers, and exercises a synthetic root in unit tests; it does
not accept a real wallet root. See
[`WALLET_KEYSTORE_CONTAINER_CANDIDATE_V0_1.md`](WALLET_KEYSTORE_CONTAINER_CANDIDATE_V0_1.md).

## Security objective and attacker model

The first keystore iteration must protect local wallet secrets at rest against
an attacker who obtains a copied data directory or an old backup and can make
offline password guesses. It must reject corrupted, substituted, truncated,
oversized, rolled-back or algorithm-downgraded files before exposing secrets.

It does **not** by itself protect against a compromised running host, malware
with the user's privileges while the wallet is unlocked, screen/keylogging,
memory disclosure, a malicious backup destination, coercion, or forgotten
passwords. Those threats need separate platform, UX and operational controls.

## Direction under review, not a selected construction

The password-derived wrapping-key candidate is Argon2id. RFC 9106 describes
Argon2 as a memory-hard function and requires Argon2id support; it recommends
an independent 16-byte salt for each password. See
[RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html). Password-based
protection of stored keys must also retain its salt and work-factor metadata,
as reflected by [NIST SP 800-132](https://csrc.nist.gov/pubs/sp/800/132/final).

The existing XChaCha20-Poly1305 dependency is a candidate AEAD only because it
is already used for the experimental recipient envelope. Reusing a primitive
does not select it for a keystore. Parameters, associated-data layout,
container format, password UX, platform support and backup model remain open.

The public header candidate fixes Argon2id / XChaCha20-Poly1305 and a 64 MiB,
3-pass, 4-lane profile only for bounded parser and synthetic-fixture review.
It does not select a user keystore construction, key hierarchy, recovery phrase
or hardware-backed integration. Consequently, no secret-bearing file must be
written yet.

## Required secret inventory before implementation

A concrete keystore proposal must enumerate and separately version every
secret it can contain:

1. Ed25519 identity signing secret;
2. ML-DSA-65 identity signing secret;
3. X25519 recipient secret;
4. ML-KEM-768 recipient decapsulation secret;
5. future viewing, note-opening, nullifier and spend material; and
6. any recovery-only secret or wrapped backup key.

The current types intentionally expose no private-key serialization. A new
keystore must not bypass that boundary by adding ad-hoc byte extraction in a
CLI or public-address module.

## Non-negotiable implementation conditions

Before code may persist any secret, all of the following must exist:

1. A reviewable threat model with an explicit rollback and backup policy.
2. A selected KDF and calibrated bounds for each supported platform, including
   safe rejection of attacker-controlled cost parameters.
3. A versioned, bounded canonical secret-container specification entered in
   the wire/storage registry, with associated data binding profile, wallet
   identity, key epoch and intended secret inventory.
4. A dedicated keystore crate with no dependency on ledger admission,
   consensus or public-address storage.
5. Zeroization and error behavior reviewed so wrong passwords, corruption and
   parser failures reveal no secret material and do not create an oracle beyond
   authenticated-decryption failure.
6. Deterministic vectors, negative tests, fuzzing, interruption/recovery tests
   and cross-process unlock evidence.
7. A user-visible export/backup/recovery procedure with explicit confirmation
   that Noxis cannot recover a forgotten password or lost self-custodied
   secret.
8. Independent cryptographic and platform-security review before enabling any
   spend-capable workflow.

NIST's key-management guidance explicitly includes backup, compromise,
confidentiality, inventory and key recovery among the management concerns; see
[NIST SP 800-57 Part 1 Rev. 5](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final).

## Next implementation sequence

1. Choose the supported operating systems and password/unlock UX.
2. Publish a narrow keystore-container candidate and its parser limits for
   review; do not put private-key bytes in it initially. **Completed for the
   public `NXKS v1` header only.**
3. Define private-key export/import ownership inside a dedicated secret-type
   boundary.
4. Add a test-only encrypted fixture with no real user wallet, then test
   unlock, wrong-password, tampering, rollback and interruption behavior.
   **The synthetic unlock, wrong-password and header-substitution portions are
   complete. The public-header lifecycle also covers exclusive locking,
   synchronized temporary publication and fail-closed temporary recovery;
   rollback and secret-payload interruption still require a file lifecycle
   design.**
5. Only after review, make a persistent private recipient entry available to a
   non-spending local wallet session.

This order preserves the current fail-closed settlement boundary and avoids
turning an experimental public-address catalog into accidental custody.
