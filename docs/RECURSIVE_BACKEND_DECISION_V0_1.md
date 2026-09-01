# Recursive backend decision — v0.1

## Current decision

Noxis does not select a production recursive prover yet. Plonky3 remains the
executable AIR research environment. The decision is deliberate: changing to a
VM-oriented recursive system would change the proving model, verifier profile,
proof format and audit surface, not merely improve performance.

## Evidence

The first single-table ownership composition verified locally but took
1,178.05 seconds. Recursive aggregation is the correct architectural direction
for retaining independent relations while presenting one outer claim. Existing
STARK systems use recursive aggregation for this purpose, but their services
and programming models are not drop-in replacements for the current Rust AIR.

## Candidate path

Evaluate a Rust-friendly recursive backend such as SP1 only through a bounded
spike that proves a frozen Noxis inner-relation receipt. Acceptance requires:

1. fixed verifier/proof serialization profile;
2. independent security review plan;
3. canonical binding of `NXPU`, relation kind and input index;
4. reproducible local prover/verifier benchmark;
5. no dependence on a hosted proving service for correctness.

Until all gates pass, no `CircuitId`, wire proof format, consensus admission or
privacy claim may name that backend.

## Current bounded experiments

The first SP1 smoke spike proves only a locally derived inner-receipt ID. The
follow-on [P24 membership spike](SP1_P24_MEMBERSHIP_SPIKE_V0_1.md) isolates the
more meaningful tree subrelation: a private note commitment and a private
depth-32 path yield one public candidate root. Both are evaluation artifacts.
Neither supplies the statement, parameter-ID, key/address, note-opening or
nullifier bindings required by acceptance gate 3.

The P24 guest has passed local execution against the independent reference, but
its direct core-proof attempt exceeds the available 21 GiB WSL memory budget.
It therefore does not satisfy acceptance gate 4. Any next experiment must use
a cryptographically bound segmented or recursive construction, rather than
calling host-side stitching a proof.
