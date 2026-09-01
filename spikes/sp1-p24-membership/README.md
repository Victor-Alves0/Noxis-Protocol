# SP1 P24 depth-32 membership spike

This isolated workspace tests one narrow candidate relation: a private
16-element note commitment and private ordered 32-level sibling path derive a
public Poseidon2-BabyBear-P24 candidate root.

The guest uses `noxis-poseidon2-core`, an allocation-free `no_std` evaluator
generated from the same frozen candidate fixture used by Noxis's auditable
reference implementation. The host creates the fixture with that independent
reference and asserts the core produces the identical root before calling SP1.

Run inside the supported WSL SP1 environment:

```bash
bash scripts/check-wsl.sh
bash scripts/run-wsl.sh --execute
bash scripts/run-wsl.sh --prove
```

The local runner uses 500,000 cycles per internal SP1 shard by default. This
is a prover-resource setting: SP1 still receives one guest program and one
proof request, rather than relying on any host-side statement stitching.

This is research evidence, not a production proof backend or a private
transfer. It does not yet bind an address/key, nullifier, note-opening cipher,
transaction statement, parameter candidate ID, or Noxis proof-envelope ID.
Those bindings must be added and independently reviewed before any recursive
or consensus-facing use.
