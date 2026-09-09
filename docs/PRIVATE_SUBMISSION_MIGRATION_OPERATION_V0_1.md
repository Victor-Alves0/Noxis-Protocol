# Private-store v1-to-v2 migration operation — candidate v0.1

## Purpose and boundary

This is the operator procedure for copying one recovered local `NXPL v1`
private-state store into a new `NXPL v2` receipt/state store. It is a local
research-storage operation, not wallet recovery, a consensus upgrade, network
replay or proof migration.

The v1 source never contained authoritative envelope IDs or transition receipt
facts. The v2 destination therefore begins with the recovered source state as
an authenticated base and **zero** receipt/state frames. Any command that
claims to reconstruct older v2 receipts from a v1 journal is incorrect.

## Preconditions

1. Stop every process using the source state directory.
2. Keep a copy of the complete source directory according to the operator's
   retention policy.
3. Choose a new, nonexistent target `state.nxpr` path in a separate target
   directory. Do not point the target at the source or at an old failed target.
4. Run the command from a build that contains the exact candidate formats being
   migrated. It rejects a v2 journal passed as v1 source.

## Command

```powershell
cargo run --release -p noxis-storage --bin noxis-private-state-migrate -- `
  --source .\old\private-state.nxpr `
  --target .\new\private-state.nxpr
```

On success it prints both final state IDs and reports zero target receipt/state
frames. Equal IDs are the required result. The target has a separate immutable
base snapshot so its first future v2 admission can be checked against it.

Validate the resulting target at any later time with the local status command:

```powershell
cargo run --release -p noxis-storage --bin noxis-private-state-status -- `
  --state .\new\private-state.nxpr
```

It reopens and validates the whole v2 journal before printing the state ID,
commitment count, spent-nullifier count and durable local receipt/state-frame
count. It is not a public RPC, wallet balance or consensus query.

## What the command does

```text
open/recover v1 source under its writer lock
→ copy its final canonical NXPR state into a distinct v2 target
→ synchronize target cache and authenticated base
→ reopen target and compare final StateId
→ confirm target history is empty
```

It does not delete, rename or append to the source. The existing v1 recovery
rule may truncate only a structurally verified incomplete final source frame.
That is a v1 recovery action, not a conversion of historic data.

## Failure and recovery

| Observation | Required action |
| --- | --- |
| Command rejects the source | Keep it unchanged; investigate its v1 recovery error. |
| Command rejects the target | Do not reuse that target. Preserve it for investigation or create a new empty target after identifying the failure. |
| Target already exists or contains only an interrupted cache | The command refuses it before copying state. Keep the complete source authoritative and select a fresh target after investigating the partial directory. |
| Source v1 journal is corrupt | No target is created. Preserve the source bytes and investigate the v1 recovery failure. |
| Source and target paths match | Choose a new target. In-place migration is forbidden. |
| State IDs differ after reopen | Treat the target as invalid and retain the source as authority. |

The command intentionally does not switch application configuration, delete
the source, or decide retention. Those actions require a separately reviewed
deployment runbook.

## Evidence

Release tests prove the source v1 journal remains byte-for-byte unchanged for a
complete source, the destination reopens at the same final state and contains
no fabricated history. The corpus also rejects a preexisting partial target
without changing a complete source, rejects a corrupt source before it can
create a target, and injects a target cache-publication failure while confirming
the complete v1 source remains byte-for-byte unchanged. The injection is a
test-only seam, not an operating-system fault claim. See the [atomicity
decision](PRIVATE_SUBMISSION_HISTORY_ATOMICITY_DECISION_V0_1.md).
