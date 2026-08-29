# Post-Quantum Hybrid Design Guide

Noxis explores a hybrid wallet-recipient design so that classical and
post-quantum key establishment can be composed before a recipient payload is
encrypted. This work is experimental and deliberately separated from the
ledger and consensus crates.

The important distinction is simple: carrying a post-quantum algorithm name
does not make a wallet, proof, node or protocol post-quantum secure. Security
depends on the exact combiner, key binding, downgrade handling, recipient
descriptor privacy, encoding and operational key lifecycle.

Read [HYBRID_CRYPTO_PROFILE_DRAFT_V0_1.md](HYBRID_CRYPTO_PROFILE_DRAFT_V0_1.md)
for the current candidate profile. Review questions are tracked in
[OPEN_QUESTIONS.md](OPEN_QUESTIONS.md).
