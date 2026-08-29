# Contributing to Noxis

Noxis welcomes careful contributions from systems engineers, Rust developers,
cryptographers, protocol researchers, reviewers, and documentation writers.
The project is research-stage: a precise objection, a better test, or a
well-scoped question is as useful as a code patch.

## Start here

1. Read the [documentation map](docs/README.md) and the
   [project plan](docs/PROJECT_PLAN.md).
2. Read [SECURITY.md](SECURITY.md). Do not disclose vulnerabilities in public
   issues.
3. Browse [open research questions](docs/OPEN_QUESTIONS.md), the
   `help wanted` issues, and repository discussions.
4. For a change larger than a small bug fix, open a discussion or issue first
   so the design boundary is clear before code is written.

## Contribution expectations

- Preserve the distinction between **implemented**, **candidate**, and
  **production-approved**. Do not upgrade a claim merely because an interface
  or test exists.
- Keep responsibility boundaries narrow. Ledger representation, invariants and
  mutation are intentionally separated for auditability.
- Add negative tests for a security-relevant acceptance path. A test that only
  proves success is usually insufficient.
- Update the relevant specification, threat model, or open question whenever
  a security assumption changes.
- Keep public APIs, wire formats, and cryptographic encodings canonical and
  bounded.

## Local checks

```powershell
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Use a focused test while iterating, then run the full suite before opening a
pull request. The repository's CI uses Rust 1.85.

## Pull requests

Explain the problem, the security boundary affected, the tests added, and
anything deliberately left for a later milestone. Keep unrelated refactors
out of the same pull request. A reviewer must be able to answer: “what changed
in the protocol claim, and what evidence supports it?”

## Community conduct

Be constructive, specific, and respectful. Discuss designs and evidence, not
people. Harassment, doxxing, or publication of unapproved vulnerability
details is not acceptable.
