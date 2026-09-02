# Candidate private-state journal design — v0.1

## Problem

`PrivateStateStoreV1` safely retains one complete `NXPR v1` snapshot. It can
recover the latest locally acknowledged candidate state, but it intentionally
does not explain how a node audits a sequence of private transitions or
distinguishes a stale snapshot from an ordered local history.

The public `NXRF → NXRC` chain cannot be reused: it embeds public `NOXT`
transactions and relies on the public verifier interface. The current private
proof bundle is an opaque in-memory value with no canonical proof bytes, so a
future journal must not pretend it can replay or independently reauthorize it.

## Candidate `NXPL v1` implementation boundary

The implemented local private journal is append-only. Each frame contains exactly
one complete canonical **post-transition `NXPR` snapshot**, plus only public
chain metadata:

```text
"NXPL" | frame version | payload length | payload | CRC-32

payload = sequence u64be | previous StateId | resulting StateId
        | NXPR length u32be | complete canonical NXPR bytes
```

The record has no note opening, secret key, recipient plaintext, proof witness
or ciphertext. Its `resulting StateId` must equal the decoded `NXPR` state ID.
For genesis, the configured initial state is the predecessor; every subsequent
record requires its `previous StateId` to equal the prior resulting ID and a
strictly contiguous sequence.

## What recovery proves

On reopen, the journal scanner must reject bad magic/version/length/checksum,
trailing bytes, a malformed `NXPR`, a mismatched resulting ID, a sequence gap
or a broken predecessor link. A structurally incomplete final frame may be
truncated only after every prior complete frame validates. The final validated
snapshot becomes the candidate state.

This gives durable, ordered state-history recovery and preserves every spent
nullifier present in every retained post-state. It does **not** prove that a
historic private proof was sound: the proof is not serializable yet. Therefore
the journal remains local research history and cannot activate ABCI/consensus.

## Commit order

For one accepted private transfer:

1. validate proof and construct the candidate state in memory;
2. construct one complete `NXPL` frame over its canonical post-state `NXPR`;
3. append, synchronize and (on supported platforms) make the journal entry
   durable before acknowledging success;
4. atomically publish the latest `NXPR` cache; and
5. expose the successor state to callers.

If the cache publication fails after a durable journal entry, reopening must
rebuild from the journal instead of treating the old cache as authority.

## Implementation status and remaining gates

`NXPL` now has a registry row, source-version guard and tests for a recovered
two-entry chain ending in a real private transition, predecessor/base mismatch, checksum corruption and a
verified incomplete-tail truncation. It remains deliberately separate from
`PrivateStateStoreV1`: joining a replaceable cache and an append-only journal
needs one crash-recovery authority and one shared writer lock, which is the
next integration step rather than a silent coupling.

The remaining tests/design are post-restart replay rejection, every-byte
final-tail truncation, mid-history corruption, cache/journal divergence and
writer exclusion. The private proof bundle also needs a portable-proof design
before journal recovery can reverify authorization.
