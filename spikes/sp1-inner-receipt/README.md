# SP1 inner-receipt spike

This is an isolated research spike. It proves a tiny Noxis-compatible claim:
the prover supplied a private statement ID and relation tags whose SHA-256
derivation equals the single 32-byte public receipt ID.

The program's derivation exactly uses the domain of
`candidate_inner_relation_receipt_id_from_statement_id` in
`noxis-private-proof-contract`. The host independently invokes that Noxis
helper and rejects a mismatch before it accepts execution or proof output.

## What this establishes

- SP1 can compile a Noxis-shaped Rust guest in the supported Linux environment.
- A local execution and a local core proof can expose a public value that is
  checked against Noxis's production helper.
- The experiment is outside the production Cargo workspace and does not select
  SP1 as Noxis's recursive backend.

## What it does not establish

- no private-transfer proof, nullifier proof, Merkle ownership proof, or
  transaction acceptance;
- no recursive composition, network verification, or proof wire format;
- no production security claim or backend decision.

## Run locally (WSL/Linux/macOS)

Install the exact SP1 6.5.0 toolchain, then run from this directory:

```sh
cd script
cargo run --release -- --execute
cargo run --release -- --prove
```

From Windows, run the reproducible host-side compilation through WSL2:

```sh
bash scripts/check-wsl.sh
bash scripts/run-wsl.sh --execute
bash scripts/run-wsl.sh --prove
```

The proof command is intentionally local: it does not use a hosted prover or a
wallet key. Its success criterion is `core proof accepted and locally verified`.

## Verified result

On the maintained WSL2 environment, the following commands completed locally:

```text
bash scripts/check-wsl.sh
bash scripts/run-wsl.sh --execute
bash scripts/run-wsl.sh --prove
```

The guest consumed 13,501 cycles and committed this checked receipt ID:

```text
8704d226ef30c24d88390a49e9c549a3bee03444e5c48e1ba864c045fe119c18
```

The execution reported `public receipt id matches Noxis derivation`; the proof
reported `core proof accepted and locally verified`.

## Reproducibility note

SP1 6.5.0 calls `TempDir::keep`, while its published dependency range permits
older `tempfile` releases that do not provide that method. This spike's
`Cargo.lock` deliberately pins `tempfile` 3.20.0, the first compatible release
validated here. Do not replace the lockfile with an unconstrained update without
re-running the compilation and proof commands above.
