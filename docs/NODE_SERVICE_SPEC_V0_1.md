# Noxis Protocol — Local Node Service Specification v0.1

## Status and scope

This document defines the behavior of the Noxis **local node service**.
It is the process that composes the ledger, cryptographic verifier, mint
policy, configuration, and persistent repository for one operator.

The current v0.1 code implements a typed, embedded local API that composes
validated genesis configuration with durable transaction replay, plus a
genesis-bound data directory and cooperative writer lock. It does not yet
implement the audit files, lifecycle manager, stale-lock recovery procedure,
or transport adapter described here. This specification keeps those remaining
service responsibilities explicit before the node is presented as an
operator-ready service.

This is intentionally not a network-node specification. It provides no peer
discovery, remote API, consensus, block production, finality, replication,
data availability, or protection from an operator who runs different local
states for different users.

## Service purpose

The service has one responsibility: safely apply validated transactions to one
operator-controlled ledger history, preserve that history across restarts once
the durability component exists, and expose clear local operational status.

It must not create assets implicitly, bypass the `ProofVerifier` or
`MintPolicy`, alter accepted history in place, or report a transaction as
accepted before the configured repository has committed it.

## Genesis

Genesis defines the one initial state from which a data directory is allowed to
start. It must be a versioned, canonical artifact with at least:

| Field | Requirement |
| --- | --- |
| Protocol version | Identifies the rules and file formats expected by the node. |
| Chain/local-network identifier | A unique configured identifier that binds data to one intended local deployment. It is not a consensus network identifier in v0.1. |
| Genesis state identifier | Canonical identifier of the empty/initial state and asset registry. |
| Asset definitions | The full initial set of permitted asset identifiers and their declared taxonomy. |
| Initial supply rules | Explicitly states whether an asset begins with zero supply or with a separately authorized initial issuance. |
| Cryptographic-suite configuration | Exact verifier-suite version and any public parameters required by the configured implementation. |
| Mint-policy configuration reference | Identifies the authorized policy implementation and its non-secret configuration. |
| Creation metadata | Creation time and human-readable provenance, treated as informational rather than consensus-critical. |

The node must verify the genesis artifact before creating or opening a data
directory. Once data exists, the node must reject startup when the supplied
genesis state identifier, protocol version, suite configuration, or asset
registry is incompatible with the initialized directory.

Changing genesis creates a different local ledger. It is never an in-place
upgrade and must use a new data directory or an explicitly specified migration
procedure.

## Data-directory layout

The service owns one explicit data directory selected by the operator. It must
not silently use a temporary directory in normal operation. A compliant future
implementation should use a structure equivalent to:

```text
<data-dir>/
  manifest.json             immutable deployment identity and format metadata
  genesis.bin               exact verified genesis artifact or immutable copy
  ledger.log                append-only transition history
  checkpoints/              optional verified state checkpoints
  lock                      exclusive-writer process lock
  audit/                    append-only operator events, separate from ledger
  runtime/                  replaceable sockets/PID files only; never state
```

Names and encoding may change, but the separation of roles may not:

- **Manifest:** records local deployment identity, accepted file-format
  versions, and the genesis identifier. It must be created atomically and then
  treated as immutable. Secrets must not be placed here.
- **Genesis:** is sufficient to rebuild the initial state and is verified
  against the manifest before use.
- **Ledger log:** is governed by
  `docs/DURABILITY_SPEC_V0_1.md`; it is the sole authoritative sequence of
  accepted transitions between checkpoints.
- **Checkpoints:** are checked state copies, never an unverified replacement
  for history.
- **Lock:** prevents two service instances from independently appending to the
  same local history. Stale-lock handling must verify that no live writer owns
  the lock before removal.
- **Audit:** contains structured operational events, but must not be required
  to reconstruct ledger state and must not store transaction secrets.
- **Runtime:** contains ephemeral operating-system artifacts. Its loss must not
  change ledger state or prevent safe recovery.

Permissions must follow least privilege: the service identity needs write
access to its data directory, while untrusted local users must not be able to
modify the manifest, genesis, log, checkpoints, or lock. Key material, if a
future mint policy uses it, must live outside this layout or in a separately
specified protected-keystore boundary.

## Lifecycle

### Initialize

Initialization creates a new local ledger only when the chosen directory is
empty or explicitly prepared for initialization. The service must:

1. load and validate the requested genesis artifact and configuration;
2. create the data directory with restrictive permissions;
3. atomically write the immutable manifest and genesis copy;
4. acquire the exclusive writer lock; and
5. create an empty durable history representing the declared genesis state.

If initialization fails at any point, a subsequent run must either complete
from a verified atomic artifact or reject the directory as incomplete. It must
not guess at a genesis identity or continue with partially initialized state.

### Start

On normal start, the service must:

1. acquire the exclusive writer lock before exposing write operations;
2. validate the manifest, genesis, configured verifier suite, and mint policy
   compatibility;
3. recover the ledger according to the durability specification;
4. verify that the recovered state binds to the initialized genesis; and
5. enter `Ready` only after all checks succeed.

If configuration differs in a security-relevant way, if recovery detects
corruption, or if a second active writer owns the lock, startup must fail
closed. Read-only diagnostic tooling may be provided separately but must state
that it is not serving the ledger.

### Ready and draining

In `Ready`, the service accepts local operations. On a controlled stop, it
first enters `Draining`: it rejects new state-changing requests, completes or
clearly aborts any operation whose durability outcome is known, flushes
required telemetry/audit buffers without making them part of ledger safety,
then releases the lock and exits.

An unclean process termination is expected to be handled by log recovery on a
later start. It is not permission to reuse a nullifier, replay a partially
committed change, or silently remove a corrupted record.

### Upgrade

An executable upgrade must first prove compatibility with the existing
manifest, log, checkpoint, proof-suite, and mint-policy versions. Any format
or rule change requires a versioned migration specification, a backup plan,
and rollback behavior. A binary must refuse to open incompatible state rather
than perform an implicit rewrite.

## Local application operations

The initial interface may be an embedded Rust API or a local-only command-line
interface. Its transport is deliberately unspecified; it must not bind a TCP
port, expose a remote HTTP/RPC endpoint, or advertise peer connectivity under
this specification.

| Operation | Behavior | Required result |
| --- | --- | --- |
| `initialize(genesis, configuration)` | Creates a new data directory as described above. | Genesis identifier and local deployment status; never secret configuration. |
| `start()` / `stop()` | Transitions through the lifecycle safely. | Current lifecycle state or an actionable failure reason. |
| `submit(transaction)` | Serializes access, validates the transaction, performs the durable transition, then returns. | Accepted transaction ID and resulting state identifier only after commit; otherwise a typed rejection or indeterminate-outcome status. |
| `transaction_status(id)` | Looks up the committed outcome by canonical transaction ID once that rule exists. | `accepted`, `not_found`, or explicitly `indeterminate`; does not infer acceptance from caller retries. |
| `state_status()` | Returns non-sensitive ledger and health metadata. | Genesis ID, recovered state ID, log sequence, configured versions, and lifecycle/health state. |
| `verify_storage()` | Runs an offline or read-only integrity/recovery verification without changing accepted history. | A bounded report of valid range, partial tail, or fail-closed corruption. |
| `export_diagnostics()` | Produces operator diagnostics with sensitive fields redacted. | Version, health, error category, and correlation IDs; never proof witnesses, private keys, or raw secrets. |

`submit` is not an API for issuing money on its own. A mint transaction still
depends on the configured `MintPolicy`, and a transfer still depends on the
configured `ProofVerifier`. The node service coordinates these existing
boundaries; it does not replace them.

## Result and error semantics

State-changing operations must use explicit outcomes rather than ambiguous
success messages:

| Outcome | Meaning |
| --- | --- |
| `Accepted` | The complete transition is durably committed under the configured durability mode and may be recovered after restart. |
| `Rejected` | Validation failed before commit. The result includes a stable public error category but no sensitive verifier internals. |
| `Unavailable` | The service is not ready, is draining, is locked by another writer, or has fail-closed storage/configuration trouble. |
| `Indeterminate` | The caller cannot know whether a request committed, usually because its connection ended after submission. The caller must use transaction status rather than blindly resubmit. |

Error messages must be safe for local operators but must avoid leaking proof
witnesses, secret keys, credentials, complete private transaction payloads, or
filesystem paths outside an operator-authorized diagnostic context.

## Observability and auditability

Observability supports operation; it does not prove protocol correctness.
Every event must include a timestamp, component/version, lifecycle state, and
correlation ID. Where a transaction ID is available, it may be included if it
does not reveal private material under the eventual transaction-ID design.

The service must emit structured local events for:

- initialization, start, recovery start/completion/failure, and shutdown;
- lock acquisition/release failure;
- accepted, rejected, unavailable, and indeterminate submissions (with public
  category, not raw transaction/proof data);
- checkpoint creation/verification and partial-tail recovery;
- integrity failures, incompatible configuration, and fail-closed transitions;
- storage latency/failure and resource-limit rejection.

At minimum, local metrics must make visible: lifecycle state, recovered log
sequence, accepted/rejected submission counts by category, recovery duration,
checkpoint age, storage errors, and queue depth. Metrics and logs must be
bounded and rotate according to operator policy; their loss must never alter
ledger state.

## Local trust boundary

The service is trusted only within the host and operating-system identity that
run it. A local user with permission to alter the data directory, executable,
configuration, or mint-policy secrets can undermine the service. File
permissions, signed/reviewed releases, protected configuration, backups, and
host monitoring are therefore operational requirements, not optional polish.

The service does not authenticate remote users, protect network privacy, offer
Byzantine fault tolerance, or make a local accepted transaction globally final.
Those properties require separate network, consensus, wallet, and operational
specifications.

## Acceptance criteria

The local node service may be described as functional only when all of the
following are implemented and demonstrated in automated tests:

1. Fresh initialization creates a manifest and genesis-bound directory; a
   changed or incompatible genesis is rejected without altering existing data.
2. A second writer cannot start against the same directory, including under
   concurrent-start tests.
3. Start reconstructs state through the durability recovery procedure before
   accepting submissions; a recovered spent nullifier remains rejected.
4. `submit` returns `Accepted` only after the complete transition is durable;
   invalid transactions leave recovered state unchanged.
5. Crash and restart tests cover each write phase and distinguish rejected,
   accepted, and indeterminate client outcomes.
6. Incomplete tails are handled only as specified; mid-history corruption
   results in `Unavailable`/fail-closed status and no new writes.
7. State and diagnostic operations expose useful versioned health information
   without writing ledger state or leaking configured secrets.
8. All operations remain local-only; tests confirm the service does not expose
   an unauthenticated network listener as part of this v0.1 scope.
9. Upgrade tests reject unsupported data/configuration combinations without
   implicit mutation, and supported migrations have documented recovery paths.

Meeting these criteria creates a durable local component, not a production
payment system or distributed protocol. Network operation, independent
security review, concrete cryptography, and external-asset claims remain gated
by their own specifications and acceptance criteria.
