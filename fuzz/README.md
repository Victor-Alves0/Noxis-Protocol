# Noxis parser fuzzing

This directory deliberately sits outside the normal Cargo workspace. It uses
[`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) and libFuzzer to attack
bounded, untrusted byte boundaries without running the expensive private STARK
backend.

## `nxpp_framing`

The target calls only
`CandidatePrivateProofBundleEnvelopeV1::validate_framing`. It exercises raw
arbitrary input and a small structurally valid frame derived from every input,
so the campaign reaches `NXPP v1` magic/version/flag checks, pinned deployment
binding, canonical BabyBear commitments, three declared proof lengths, total
envelope budget, exact EOF and checksum. It never deserializes a Plonky3 proof,
changes ledger state or writes private material.

Install the runner once:

```sh
cargo install cargo-fuzz --locked
```

On a platform with Rust's libFuzzer sanitizer support, run a bounded local
campaign:

```sh
cd fuzz
cargo +nightly fuzz run nxpp-framing -- -runs=100000 -max_len=65536
```

`cargo-fuzz` targets require a compatible sanitizer-capable Rust toolchain;
the normal workspace test gate remains portable. The instrumented target is
built and run in Linux CI. On Windows, the target can be built with nightly,
but execution also requires the matching AddressSanitizer runtime DLL; use WSL
or CI when that runtime is unavailable. Any crash artifact under
`fuzz/artifacts/` is security-sensitive input and must be handled under
[`SECURITY.md`](../SECURITY.md), not published in a public issue.
