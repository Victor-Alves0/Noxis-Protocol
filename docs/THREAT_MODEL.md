# Threat Model Guide

The current threat model is deliberately conservative: code can enforce only
the properties it implements and tests. Privacy, post-quantum resistance,
network finality, custody safety and production readiness are not inferred
from names, interfaces or research experiments.

Read the normative document: [THREAT_MODEL_V0_1.md](THREAT_MODEL_V0_1.md).

Reviewers should concentrate on four boundaries:

1. **Untrusted input:** canonical parsing, bounded allocation and invalid
   transaction rejection.
2. **State transition:** commitment uniqueness, nullifier single-use, asset
   policy and atomic state changes.
3. **Proof boundary:** which public statement is verified, which witness
   properties are delegated, and whether failure is fail-closed.
4. **Operational boundary:** recovery, durability, consensus configuration,
   operator control and network exposure.

If an assumption is missing or a claim is too broad, open a research
discussion or add it to [OPEN_QUESTIONS.md](OPEN_QUESTIONS.md). Suspected
exploitable defects belong in [SECURITY.md](../SECURITY.md), not a public
issue.
