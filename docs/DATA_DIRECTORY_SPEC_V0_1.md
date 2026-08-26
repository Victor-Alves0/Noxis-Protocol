# Noxis Protocol — Data Directory Specification v0.1

## Status and purpose

This document specifies the filesystem boundary for a Noxis local node. It
covers deployment identity, genesis material, initialization, exclusive writer
ownership, opening, shutdown, permissions, and failure handling.

The current runtime persists a canonical `NXMF` v7 manifest plus a genesis
copy, holds a cooperative OS file lock, and makes `LocalNodeRuntime` derive
the record-log path as `<data-dir>/ledger.nxrf`; the separate Comet service
derives `<data-dir>/blocks.nxcb`. It does not use an embedding API's arbitrary
path. This is not a complete crash-safe ownership mechanism: ACL/symlink
checks, storage-class validation, multi-process fault injection and several
lifecycle requirements below remain unimplemented.

The authoritative transaction-history and recovery rules are specified in
`docs/DURABILITY_SPEC_V0_1.md`. This specification does not introduce network
replication, consensus, remote access, or distributed leader election.

## Directory identity and contents

A node operates on one explicit operator-selected directory. In normal mode it
must not silently select a temporary, current-working-directory, or shared
default location. The implementation may use different filenames, but must
keep these logical roles separate:

```text
<data-dir>/
  manifest.*        deployment identity and immutable compatibility metadata
  genesis.*         exact verified genesis artifact or immutable equivalent
  blocks.nxcb       authoritative append-only consensus-block history
  ledger.*          legacy per-record history or migration input; not consensus authority
  checkpoints/      optional verified state copies (not yet replay accelerators)
  audit/            non-authoritative operator events
  runtime/          replaceable process-local artifacts
```

For consensus execution, only `blocks.nxcb` reconstructs the authoritative
tip. The legacy ledger history and verified checkpoints may support migration
or diagnostics but must not be used to infer a committed consensus block.
Audit and runtime data must never be used to infer a committed transaction.

### Manifest

The manifest is created once during initialization and thereafter treated as
immutable. It must use a canonical, versioned encoding and contain at least:

| Field | Requirement |
| --- | --- |
| Manifest format version | Allows an implementation to reject unsupported layouts. |
| Canonical consensus configuration | Binds validator IDs, public keys, weights, fault budget and block limits to this deployment identity. |
| Protocol version/rule set | Identifies the ledger rules expected by this directory. |
| Local deployment identifier | Binds files to this configured local deployment; it does not represent network consensus. |
| Genesis identifier | Commits to the exact genesis state that initialized the directory. |
| Genesis artifact identifier | Binds the stored genesis bytes to the manifest. |
| Ledger codec/version identifiers | State which record and checkpoint formats may be opened. |
| Cryptographic-suite identifier | Binds the selected concrete verifier configuration once one exists. |
| Mint-policy configuration identifier | Binds non-secret policy configuration and its version. |
| Creation metadata | Informational provenance, clearly separated from security-critical fields. |

The manifest must not contain private keys, credentials, proof witnesses, or
other secrets. It must be atomically created before a directory is considered
initialized. If a manifest is present but invalid, incomplete, or incompatible,
the directory is not openable for writes.

`NXMF` v7 additionally records one immutable storage mode. It is one of
`LocalRecordLogV1` (only `ledger.nxrf` is authoritative) or
`CometBlockJournalV1` (only `blocks.nxcb` is authoritative). Reopening with a
different mode fails before replay. There is no automatic v6-to-v7 migration:
an operator must preserve the old directory, create a separately reviewed
export/migration procedure and then initialize a new v7 directory. This
fail-closed rule prevents a record log and a consensus journal from silently
becoming competing sources of history.

### Genesis artifact

The stored genesis artifact must be the exact artifact that produced the
manifest's genesis identifier, or a canonical equivalent whose identity rule is
specified. It must define initial asset definitions, initial issuance rules,
and the genesis state identifier. A node must validate the artifact before
writing it and must revalidate its identity whenever opening the directory.

Replacing genesis, its asset registry, or its identifier creates a distinct
ledger. It must never be handled as an ordinary configuration update in an
existing data directory.

### Mutable data

The `blocks.nxcb` journal, legacy ledger log and checkpoints are mutable only
through their respective append/create procedures. No component may rewrite an
accepted block or ledger record in place. Runtime files (for example an endpoint
descriptor or PID hint) are explicitly non-authoritative and may be recreated.
Audit records are useful for operators but cannot authorize a state change.

## Permissions and filesystem boundary

The node must create the data directory and security-critical entries with the
most restrictive permissions supported by the platform. At minimum:

- only the configured service identity may write the manifest, genesis, ledger,
  checkpoints, and ownership metadata;
- untrusted users must not be able to replace these entries through writable
  parent directories, symlinks/reparse points, hard links, or inherited ACLs;
- parent directories must be verified as suitable before initialization;
- opening must validate expected object types and refuse unexpected symbolic
  links/reparse points where platform-safe handling is not explicitly defined;
- temporary files used for atomic replacement must be created in the same
  protected filesystem boundary and with restrictive permissions;
- diagnostic exports, backups, and audit readers receive only the minimum
  read access their role needs.

Platform-specific permission behavior must be documented and tested. Running a
service as an overly privileged identity does not satisfy least privilege, and
filesystem permissions do not protect against an administrator, compromised
host, or malicious storage layer.

## Writer ownership and exclusion

There must be at most one active writer for one data directory. This prevents
two processes from validating conflicting transactions against the same prior
state and then independently appending both outcomes.

Writer exclusion requires all of the following:

1. An **operating-system-enforced exclusive ownership primitive** held for the
   full writable lifetime where supported (for example, an advisory/mandatory
   file lock with documented semantics, or an equivalent handle-based lock).
2. A **durable ownership record** that identifies the intended deployment,
   process instance generation, acquisition time, and implementation version
   for operator diagnosis. This record is not by itself proof that the process
   is alive.
3. A **startup validation protocol** that acquires exclusive ownership before
   replaying or appending history, and releases it only after writable service
   shutdown is complete.
4. A **single in-process write serialization mechanism** so individual threads
   cannot race after process-level ownership has been acquired.

A pathname named `lock`, a PID stored in a file, a timestamp/lease, or merely
checking whether a PID exists is insufficient on its own. PIDs can be reused,
clocks can be wrong, files can survive crashes, networked filesystems may have
different semantics, and a process can pause without exiting. These mechanisms
may improve diagnostics but must not be treated as proof of exclusive ownership.

The first supported implementation should restrict writable directories to
local filesystems with documented locking and force-to-media behavior. A
network filesystem, removable drive, or filesystem with unknown lock semantics
must be rejected for write mode until it has a dedicated compatibility and
failure-model specification.

### Crash and stale ownership handling

After a crash, the runtime ownership record may remain. A new process must not
delete it solely because it appears old or its recorded PID is absent. Instead,
it must attempt the actual operating-system ownership acquisition and, after
acquisition, run normal manifest/genesis/log recovery validation before serving
writes.

If the ownership primitive cannot establish that writing is exclusive, startup
must fail closed. An operator override is allowed only if separately designed
as an explicit recovery procedure with a clear warning, audit trail, backup
recommendation, and safeguards against concurrent writers. It must never be
an automatic "remove stale lock and continue" path.

## Lifecycle

### `init`

`init` creates a new directory; it must not convert an existing ledger into a
new genesis. It proceeds as follows:

1. Canonicalize and inspect the requested path and parent permissions without
   following unsafe links.
2. Refuse if a valid initialized manifest, ledger data, or an active writer
   already exists, unless a separate explicit destructive-reset operation is
   specified and authorized.
3. Validate the supplied genesis and non-secret configuration.
4. Acquire initialization ownership/exclusion before publishing any state.
5. Create the protected directory entries and atomically publish a complete
   manifest and genesis artifact.
6. Create an empty ledger history that is explicitly bound to the genesis
   state, force all required creation records according to the selected
   durability mode, then verify them by reopening read-only.
7. Mark initialization complete only after verification; otherwise leave the
   directory unavailable for normal open until an operator diagnoses it.

Init must be safe to retry: repeated invocation either reports the same
completed identity without changing it, or fails with an explicit incomplete/
conflicting-initialization status. It must not create a second genesis beside
or over the first.

### `open`

`open` prepares an initialized directory for service use:

1. acquire process-level exclusive writer ownership for writable mode, or
   explicitly enter a separate read-only diagnostic mode;
2. validate types, permissions, manifest format, manifest contents, and the
   exact genesis identity;
3. validate compatibility of the executable, ledger codec, verifier suite, and
   mint-policy configuration;
4. run log/checkpoint recovery according to the durability specification;
5. establish in-process serialization and publish `Ready` only after recovery
   succeeds.

Any failure in these steps leaves the directory closed for writes. The service
must return a categorized diagnostic status rather than silently creating new
history, repairing files, or accepting a different genesis.

### `shutdown`

Shutdown first prevents new write operations. It then finishes or reports the
known status of the active write, completes required storage flushes, writes a
non-authoritative shutdown audit event if possible, releases the
operating-system ownership primitive, and removes/replaces runtime hints only
after release. Failure to remove a runtime file must not imply that the next
start can ignore exclusive-ownership checks.

An unclean shutdown is recovered through `open`; it has no special shortcut.

## Failure behavior

| Condition | Required behavior |
| --- | --- |
| Missing directory | `open` reports not initialized; it must not silently initialize. |
| Empty new directory | `init` may proceed after exclusion and permission checks. |
| Incomplete initialization | Refuse normal write open; provide diagnosis/recovery guidance only. |
| Manifest/genesis mismatch | Fail closed; never select one artifact as authoritative by guesswork. |
| Incompatible binary or configuration | Fail closed before log replay/appending; require an explicit migration path. |
| Cannot acquire ownership | Fail closed in write mode; another writer or uncertain lock semantics are treated as unavailable. |
| Stale runtime/lock hint | Preserve it for diagnosis; attempt real OS ownership acquisition, never blindly delete-and-continue. |
| Partial final log record | Delegate to the durability specification's bounded tail-recovery rule. |
| Corruption before final incomplete tail | Fail closed and refuse writes. |
| Permission/type/link anomaly | Refuse to open or initialize until the operator fixes the filesystem boundary. |
| Disk-full, force-to-media, or I/O error | Do not acknowledge the affected transition; transition service to unavailable/draining when safe operation cannot continue. |

## Required tests and acceptance criteria

A data-directory implementation conforms to this specification only when
automated tests demonstrate all of the following on every supported operating
system/filesystem combination:

1. **Initialization identity:** successful `init` writes a valid manifest and
   genesis pair; reopening verifies the same identifiers.
2. **Idempotence:** retrying `init` after success does not change genesis,
   manifest, or history; interrupted init is detected rather than guessed at.
3. **Mismatch rejection:** modified genesis bytes, manifest fields, version
   identifiers, or asset registry prevent write open without changing files.
4. **Concurrent starts:** two processes race to open writable mode; exactly one
   obtains writer ownership and the other performs no replay/appends as writer.
5. **Writer crash:** terminate the owner at multiple lifecycle points; a later
   process obtains true OS-level exclusion or safely remains unavailable, then
   recovers the correct ledger state before writes.
6. **Stale metadata:** leave stale PID/timestamp/runtime records after a crash;
   startup must not rely on them as evidence and must not automatically delete
   them before attempting real ownership acquisition.
7. **In-process races:** concurrent submissions under one opened process retain
   a single transition order and cannot commit two uses of a shared nullifier.
8. **Filesystem attacks:** permissions, symlink/reparse-point substitution,
   unexpected object types, non-writable parent, and insecure temporary-file
   conditions are rejected safely on supported platforms.
9. **Shutdown ordering:** tests show that new writes are refused during
   draining and that no new writer proceeds before the old ownership primitive
   has been released.
10. **Storage failures:** injected create, rename, append, flush, and reopen
    failures do not leave the service reporting a writable ready state with
    unverified history.

Passing these tests provides a well-defined local filesystem boundary only. It
does not guarantee physical media durability beyond documented platform
assumptions, resist a malicious administrator, or establish distributed
consensus/finality.
