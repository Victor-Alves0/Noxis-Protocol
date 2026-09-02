# Noxis Wire and Storage Formats v0.1

## Status and purpose

This is the normative registry for Noxis binary-format identities, acceptance
boundaries and evolution rules. It makes the format surface auditable from one
place without suggesting that every registered artifact is an active protocol
message.

An entry is identified by **(artifact class, magic, version)**. `magic` alone
is never an identifier: `NXTM`, `NXTV` and `NXPS` deliberately reuse a magic
across incompatible versions. A decoder must select the exact entry or reject
the bytes.

The registry is normative for status, magic, supported version, resource bound,
byte-order convention, canonicality and upgrade rule. The linked owner
specification and codec define field-level layout. A change to either must
update both in one review; disagreement fails closed and never authorizes
compatibility by guesswork.

## Normative format descriptor

Each row below is a complete format descriptor. The table deliberately keeps
the following audit questions separate, even when a short row groups them in
one cell to remain readable:

| Audit field | Where it is stated in each registry row | Meaning |
| --- | --- | --- |
| **Magic** | `Key` | The exact four ASCII bytes, or the named external encoding when no Noxis magic exists. |
| **Version** | `Key` | The exact accepted layout version. It is part of the format identity, never an advisory field. |
| **Maximum size** | `Maximum accepted size / count` or `Maximum / exact size` | The allocation and nesting limit enforced before variable-size decoding. “Exact” means no other length is accepted. |
| **Endianness** | `Canonical bytes and domain boundary` or `Canonicality and parser / upgrade rule` | The order of structural integers. Any BabyBear `u32le` exception is named explicitly. |
| **Domain** | The same canonical-bytes column | The hash, checksum, candidate-ID or integrity boundary. `None` means that the artifact has no cryptographic domain claim. |
| **Canonical encoding** | The same canonical-bytes column | Required tags, order, length framing, reserved values, nested exact encodings and EOF behavior. |
| **Parser behavior** | `Parser / upgrade rule` | The fail-closed response to malformed, oversized, trailing or unsupported bytes. Encoder-only rows say so explicitly. |
| **Upgrade rule** | `Parser / upgrade rule` | Whether old bytes are rejected, read only for migration, or require a separately approved activation/migration. |

`magic + version` is still insufficient on its own when a magic is reused.
The artifact class in `Key` is part of the identity. For example, `NXTM v1`
and `NXTM v2`, and the two `NXPS` anchors, have deliberately incompatible
meanings.

## Registry-wide rules

| Rule | Requirement |
| --- | --- |
| Header order | Check magic, version, declared lengths and configured bounds before allocating variable-size fields. |
| Integer order | Structural integers are big-endian unless an entry says otherwise. Candidate BabyBear field elements are `u32le`; this exception applies only to those named payloads. |
| Canonical bytes | A decoder rejects truncation, unsupported versions, non-canonical reserved/tag/order values and trailing bytes. Re-encoding equality is required where the owner defines it. |
| Nesting | The outer parser owns framing limits; each nested artifact gets its own exact decoder. `NXCB → NXBP → NXBH + NXRC` and `NXRF → NXRC` are distinct layers. |
| Integrity is not authority | CRC-32 detects accidental corruption. A checksum or ID does not become a signature, Comet finality proof or settlement authorization. |
| Unknown versions | Reject. There is no generic forward-compatible decoder or silent migration. |
| Upgrade | A changed interpretation, layout, bound, cryptographic domain or security meaning requires a new exact version and an explicit migration/activation decision. Old bytes must never be reinterpreted informally. |
| Candidate activation | A candidate cannot enter `NOXT`, `NXRC`, `NXCB`, genesis allowlists or public transport until selected-parameter, proof, threat-model and migration reviews authorize it. |

## Operational formats

“Active” means that a workspace component can parse or persist the artifact at
its stated local boundary. It does **not** mean public-network, wallet,
privacy or finality readiness.

| Key | Role and status | Maximum accepted size / count | Canonical bytes and domain boundary | Parser / upgrade rule | Owner |
| --- | --- | --- | --- | --- | --- |
| `wire / NOXT / v1` | Current ledger transaction. | Collections ≤ 65,536; each opaque field ≤ 16 MiB. | BE structure, exact variant/tag order and EOF. **Frame domain: none**; its separately encoded `NXTI` intent is SHA-256 `NOXIS/TX-INTENT-ID/V1\\0`. | Strict structural revalidation; only v1 accepted. | [`PROTOCOL_SPEC_V0_1.md`](PROTOCOL_SPEC_V0_1.md); `noxis-codec`. |
| `internal / NXTI / v1` | `TransactionIntentId` preimage; not standalone wire or storage. | Bounded by committed transaction fields. | BE deterministic construction; `NOXIS/TX-INTENT-ID/V1\\0`. | No public decoder. External use requires one and a security review. | `noxis-codec`. |
| `record / NXRC / v1` | State-transition record embedded in legacy and Comet storage. | Transaction ≤ 32 MiB. | BE; exact sequence, state links, transaction and record hash; `NOXIS/RECORD-CHAIN/V1/RECORD\\0`. | Re-decodes transaction, rejects trailing/unknown data; only v1. | [`STATE_CHAIN_SPEC_V0_1.md`](STATE_CHAIN_SPEC_V0_1.md); `noxis-record-chain`. |
| `legacy storage / NXRF / v1` | Local frame for one `NXRC`; never Comet `Commit` authority. | Payload ≤ 32 MiB + 146 bytes. | BE frame/length and exact nested `NXRC`; CRC-32 only. | Bad complete frame fails closed; documented recovery applies only to a structural incomplete final tail. | [`DURABILITY_SPEC_V0_1.md`](DURABILITY_SPEC_V0_1.md); `noxis-storage/record_log`. |
| `legacy storage / NXLG / v1` | Superseded transaction-only frame. | Payload ≤ 32 MiB. | BE frame/length; CRC-32 only. | Read/detection/migration only; `NXRF` recovery rejects it as a state record. | [`DURABILITY_SPEC_V0_1.md`](DURABILITY_SPEC_V0_1.md); `noxis-storage`. |
| `consensus component / NXCG / v3` | Canonical BFT configuration; not a running finality certificate. | ≤ 10,000 validators; key ≤ 8 KiB; block transaction budget ≤ 64 MiB. | BE, ordered unique validators and EOF. SHA-256 identifiers: `NOXIS/CONSENSUS/V1/CONFIG` and `NOXIS/CONSENSUS/V1/VALIDATOR-SET`. | Reject old/unknown versions, invalid tags/order and oversize fields. | [`CONSENSUS_DATA_SPEC_V0_1.md`](CONSENSUS_DATA_SPEC_V0_1.md); `noxis-consensus`. |
| `consensus component / NXBH / v3` | Canonical Noxis block header inside `NXBP`. | ≤ 1,000,000 records, under configured 64 MiB aggregate transaction budget. | BE fixed canonical header. SHA-256 `BlockId`: `NOXIS/CONSENSUS/V1/BLOCK`; record commitment: `NOXIS/CONSENSUS/V1/RECORDS`. | Exact decode and EOF; only v3. | [`CONSENSUS_DATA_SPEC_V0_1.md`](CONSENSUS_DATA_SPEC_V0_1.md); `noxis-consensus`. |
| `consensus component / NXFC / v3` | Generic finality-certificate interface, not a Comet vote proof or client-finality API. | ≤ 10,000 votes; signature ≤ 16 KiB. | BE, canonical vote order and EOF. Vote preimage: `NOXIS/CONSENSUS/V1/PRECOMMIT`; certificate ID: `NOXIS/CONSENSUS/V1/FINALITY-CERTIFICATE`. | Exact decode plus quorum/weight checks; only v3. | [`CONSENSUS_DATA_SPEC_V0_1.md`](CONSENSUS_DATA_SPEC_V0_1.md); `noxis-consensus`. |
| `consensus storage / NXCB / v2` | Authoritative outer frame for one committed Comet-mode block. | 64 MiB aggregate transaction budget plus bounded header/record envelopes. | BE outer frame containing exact `NXBP v2`; CRC-32 only. | Reject bad magic/version/length/CRC. A validated incomplete final tail is the sole removable case. | [`DURABILITY_SPEC_V0_1.md`](DURABILITY_SPEC_V0_1.md); `noxis-storage/block_journal`. |
| `consensus storage / NXBP / v2` | Payload in `NXCB`: `NXBH`, Comet decision context, `AppHash`, ordered `NXRC`. | Enclosing `NXCB` bound; header ≤ 4 KiB. | BE structure and exact nested codecs. | Revalidates state links, record commitment, zero-record semantics and EOF; only v2. | [`DURABILITY_SPEC_V0_1.md`](DURABILITY_SPEC_V0_1.md); `noxis-storage/block_journal`. |
| `node storage / NXMF / v7` | Immutable data-directory manifest and selected storage mode. It is authoritative configuration only; `NXCB` alone reconstructs committed Comet state. | `MAX_MANIFEST_BYTES`; consensus bytes ≤ 1 MiB; assets ≤ 4,096. | BE, canonical tagged mode/identities and EOF. **Frame domain: none**; its embedded `GenesisId` is SHA-256 `NOXIS/GENESIS-ID/V1\\0` over the canonical genesis configuration. | Reject unsupported layout/mode/context. No automatic prior-version migration. | [`DATA_DIRECTORY_SPEC_V0_1.md`](DATA_DIRECTORY_SPEC_V0_1.md); `noxis-runtime`. |
| `legacy checkpoint / NXCP / v1` | Snapshot artifact for strict legacy `NXRF` replay; never `NXCB` authority or accelerator. | Snapshot ≤ 128 MiB; assets ≤ 4,096; identifier collections ≤ 1,048,576. | BE ordered snapshot and EOF; `NOXIS/CHECKPOINT/V1/SNAPSHOT\\0`, `NOXIS/CHECKPOINT/V1\\0`. | Reject bad magic/version/hash/order/trailing bytes; compare only in complete legacy replay. | [`CHECKPOINT_SPEC_V0_1.md`](CHECKPOINT_SPEC_V0_1.md); `noxis-checkpoint`. |
| `local experimental wire / NXPT / v1` | Private-transfer research packet, not a `NOXT` transaction. | Intent = 640 bytes; two envelopes = 1..4 KiB each; proof = 1..2 MiB. | BE framing/lengths and EOF. **Frame domain: none**; no selected proof/KEM/AEAD binding. | Strict bounded parser; promotion requires candidate activation. | [`PRIVATE_TRANSFER_ARCHITECTURE_DRAFT_V0_1.md`](PRIVATE_TRANSFER_ARCHITECTURE_DRAFT_V0_1.md); `noxis-codec`. |
| `wallet experimental wire / NXPA / v1` | Diversified hybrid payment address; not ledger/network accepted. | Fixed v1 profile/ML-KEM-768 public-key length. | BE structure and EOF; recomputes the SHA-256 address ID under `NOXIS/PAYMENT-ADDRESS/V1\\0` and validates ML-KEM key. | Strict v1 parser; activation separately gated. | `noxis-wallet-crypto/wire`. |
| `wallet experimental wire / NXRE / v1` | Hybrid recipient envelope; not a private-payment protocol. | Ciphertext payload 16..2,048 bytes. | BE structure and EOF. **Frame hash domain: none**; the inner AEAD is checked only during decryption and the decoder does not claim authenticity. | Strict v1 parser; `NXPT` owns outer arity/resource limits. | `noxis-wallet-crypto/wire`. |
| `wallet keystore candidate header / NXKS / v2` | Public 76-byte header for a future encrypted wallet-root container; no secret payload exists. | Exact 76 bytes. | BE fields; fixed Argon2id/XChaCha candidate profile, salt, public wallet ID and key epoch. Each future encrypted payload must carry its own unique XChaCha nonce; the exact header is associated data only in a test-only synthetic-root fixture. | Strict exact decoder rejects every different magic/version/algorithm/cost/zero wallet ID/trailing byte; `NXKS v1` is explicitly revoked because its nonce lifecycle was unsafe. Promotion requires secret-payload lifecycle, recovery and independent-review gates. | [`WALLET_KEYSTORE_CONTAINER_CANDIDATE_V0_1.md`](WALLET_KEYSTORE_CONTAINER_CANDIDATE_V0_1.md); `noxis-wallet-keystore`. |
| `wallet keystore candidate payload / NXKP / v1` | Opaque 150-byte ciphertext fixture bound to one `NXKS v2`; it is not a real secret file. | Exact 150 bytes. | BE magic/version/header ID/generation, then a nonzero 24-byte nonce and fixed 80-byte synthetic ciphertext. `NXKA` ID is SHA-256 `NOXIS/KEYSTORE-PAYLOAD-CIPHERTEXT-ID/V1\0` over exact bytes; test-only AEAD AAD binds `NXKS` and the 70-byte prefix. | Strict exact parser; immutable, bounded generation-file store recovers only canonical synchronized temporaries, rejects nonce reuse and compares exact metadata with a supplied external receipt. Release builds cannot unlock. Promotion requires real-secret inventory, operational backup/recovery and independent review. | [`WALLET_KEYSTORE_PAYLOAD_SYNTHETIC_CANDIDATE_V0_1.md`](WALLET_KEYSTORE_PAYLOAD_SYNTHETIC_CANDIDATE_V0_1.md); `noxis-wallet-keystore`. |
| `wallet synthetic recovery bundle / NXKB / v1` | Portable pairing of exact `NXKS v2` and opaque `NXKP v1`; it is not a secret backup. | Exact 232 bytes. | BE magic/version then fixed child encodings, each strictly parsed; payload header ID must equal the decoded header ID. `NXKA` is deliberately absent. | Exact decoder rejects child/parser/binding failure and trailing bytes. Capture and restore require a separately supplied `NXKA`, checked before target mutation. Promotion requires interruptible multi-file recovery, real-secret inventory and independent review. | [`WALLET_SYNTHETIC_RECOVERY_BUNDLE_CANDIDATE_V0_1.md`](WALLET_SYNTHETIC_RECOVERY_BUNDLE_CANDIDATE_V0_1.md); `noxis-wallet-keystore`. |
| `wallet external rollback anchor / NXKA / v1` | User-retained public receipt for a future encrypted-payload generation; it must live independently of the wallet directory. | Exact 78 bytes. | BE magic/version, `KeystoreHeaderId`, nonzero generation and nonzero opaque ciphertext ID; no secret or plaintext bytes. | Strict exact decoder rejects every different magic/version/zero generation/zero ciphertext ID/trailing byte. It detects only differences against a separately retained receipt; it does not by itself establish external storage or protect a current wallet. | [`WALLET_BACKUP_ROLLBACK_POLICY_CANDIDATE_V0_1.md`](WALLET_BACKUP_ROLLBACK_POLICY_CANDIDATE_V0_1.md); `noxis-wallet-keystore`. |
| `external transport / Comet ABCI protobuf / v0.38` | Loopback TCP transport owned by CometBFT, not an `NX..` format. | Frame ≤ 80 MiB; Comet block ≤ 64 MiB. | Length-delimited Comet protobuf; no Noxis magic/domain. | Bounded framing and exact conversion; upgrades need pinned-Comet compatibility review. | [`COMETBFT_CI_V0_1.md`](COMETBFT_CI_V0_1.md); `noxis-comet-abci`. |

## Candidate and evidence formats

These are canonical research artifacts, but none is selected protocol
cryptography, a network message, a ledger mutation or a privacy claim. “Exact”
means every different length is rejected.

| Key | Purpose and status | Maximum / exact size | Canonicality and parser / upgrade rule | Owner evidence |
| --- | --- | --- | --- | --- |
| `candidate manifest / NXTM / v1` | Empty draft tree manifest. | Exact 24 bytes. | BE; candidate-ID domain; exact parser. Cannot be reinterpreted as v2. | [`TREE_PARAMETER_FRAMING_V0_1.md`](TREE_PARAMETER_FRAMING_V0_1.md); `noxis-tree-params`. |
| `candidate manifest / NXTM / v2` | Frozen Poseidon2-P24 tree candidate. | Exact 7,660 bytes. | BE structure, BabyBear `u32le`, domain-separated candidate ID; exact parser/re-encoding. | [`POSEIDON2_P24_CANDIDATE_MANIFEST_V0_1.md`](POSEIDON2_P24_CANDIDATE_MANIFEST_V0_1.md); `noxis-tree-params`. |
| `candidate corpus / NXTV / v1` | Draft tree-vector evidence. | ≤ 1 MiB; ≤ 4,096 records. | BE framing, BabyBear `u32le`, canonical order; strict parser; evidence only. | [`TREE_VECTOR_CORPUS_FRAMING_V0_1.md`](TREE_VECTOR_CORPUS_FRAMING_V0_1.md); `noxis-tree-params`. |
| `candidate corpus / NXTV / v2` | Frozen P24 tree-vector evidence. | ≤ 1 MiB; ≤ 4,096 records. | BE framing, BabyBear `u32le`, exact manifest/coverage; strict parser; incompatible with v1. | [`TREE_VECTOR_CORPUS_P24_V2.md`](TREE_VECTOR_CORPUS_P24_V2.md); `noxis-tree-params`. |
| `candidate manifest / NXPH / v1` | P24 private-note domain candidate. | Exact 7,980 bytes. | BE plus BabyBear `u32le`; checksum/candidate-ID domains; exact parser. | [`POSEIDON2_P24_NOTE_DOMAINS_CANDIDATE_V0_1.md`](POSEIDON2_P24_NOTE_DOMAINS_CANDIDATE_V0_1.md); `noxis-tree-params`. |
| `candidate corpus / NXNV / v1` | External KAT evidence for `NXPH`. | ≤ 16 KiB; 6 frozen records. | BE, BabyBear `u32le`, exact parent manifest/ID/order; strict parser; evidence only. | [`NOTE_DOMAIN_VECTOR_CORPUS_V0_1.md`](NOTE_DOMAIN_VECTOR_CORPUS_V0_1.md); `noxis-tree-params`. |
| `candidate manifest / NXIC / v1` | P24 intent-commitment candidate. | Exact 8,162 bytes. | BE plus BabyBear `u32le`; checksum/candidate-ID domains; exact parser. | [`INTENT_COMMITMENT_MANIFEST_CANDIDATE_V0_1.md`](INTENT_COMMITMENT_MANIFEST_CANDIDATE_V0_1.md); `noxis-tree-params`. |
| `candidate corpus / NXIV / v1` | External KAT evidence for `NXIC`. | Exact 11,340 bytes; 2 frozen records. | BE, BabyBear `u32le`, exact parent manifest/ID; strict parser; evidence only. | [`INTENT_VECTOR_CORPUS_CANDIDATE_V0_1.md`](INTENT_VECTOR_CORPUS_CANDIDATE_V0_1.md); `noxis-tree-params`. |
| `candidate manifest / NXSM / v1` | Sparse-nullifier-tree manifest, not serialized mutable state. | Exact 8,347 bytes. | BE plus BabyBear `u32le`; checksum/candidate-ID domains; exact parser. | [`NULLIFIER_SPARSE_MANIFEST_CANDIDATE_V0_1.md`](NULLIFIER_SPARSE_MANIFEST_CANDIDATE_V0_1.md); `noxis-tree-params`. |
| `candidate corpus / NXSV / v1` | External KAT evidence for `NXSM`. | ≤ 1 MiB; ≤ 128 records. | BE, BabyBear `u32le`, exact `NXSM` parent; strict parser; evidence only. | [`NULLIFIER_SPARSE_EXTERNAL_KATS_V0_1.md`](NULLIFIER_SPARSE_EXTERNAL_KATS_V0_1.md); `noxis-tree-params`. |
| `candidate anchor / NXPS / v1` | First private-state anchor. | Exact 220 bytes. | BE plus BabyBear `u32le`; SHA-256 state ID `NOXIS/PRIVATE-STATE-ID/V1\\0` and nullifier-set commitment `NOXIS/PRIVATE-NULLIFIER-SET/V1\\0`; encoder-only local artifact, not received wire. | [`PRIVATE_STATE_ANCHOR_CANDIDATE_V0_1.md`](PRIVATE_STATE_ANCHOR_CANDIDATE_V0_1.md); `noxis-private-state`. |
| `candidate anchor / NXPS / v2` | Typed private-state anchor including `NXSM`. | Exact 288 bytes. | BE plus BabyBear `u32le`; SHA-256 state ID `NOXIS/PRIVATE-STATE-ID/V2\\0`; encoder-only and incompatible with v1. | [`PRIVATE_STATE_NXSM_ANCHOR_CANDIDATE_V0_1.md`](PRIVATE_STATE_NXSM_ANCHOR_CANDIDATE_V0_1.md); `noxis-private-state`. |
| `candidate state record / NXPR / v1` | Complete local private-ledger snapshot. | Commitments ≤ 1,024; nullifiers ≤ 2,048; assets ≤ 4,096; ticker ≤ 16 bytes. | BE counts and fields; SHA-256 checksum under `NOXIS/PRIVATE-STATE-RECORD/V1\\0`; commitments retain append order, nullifiers and assets have strict canonical order. | Exact fail-closed decoder rebuilds snapshot, `NXSM` and `NXPS v2`, checks encoded state ID and re-encoding equality; candidate single-snapshot storage only. | [`PRIVATE_STATE_RECORD_CANDIDATE_V0_1.md`](PRIVATE_STATE_RECORD_CANDIDATE_V0_1.md); `noxis-private-state`. |
| `candidate relation / NXNT / v1` | Public two-nullifier `NXSM` transition. | Exact 408 bytes. | BE plus BabyBear `u32le`, domain-separated ID; encoder-only. Promotion needs decoder/fuzz review. | [`PRIVATE_TRANSFER_NXSM_TRANSITION_CANDIDATE_V0_1.md`](PRIVATE_TRANSFER_NXSM_TRANSITION_CANDIDATE_V0_1.md); `noxis-private-proof-contract`. |
| `candidate statement / NXPU / v1` | Unified public private-transfer statement. | Exact 1,440 bytes. | BE plus nested candidate frames/BabyBear `u32le`; SHA-256 statement ID `NOXIS/PRIVATE-TRANSFER-PROOF-PUBLIC-STATEMENT-ID/V1\\0`; encoder-only, not proof or transaction. | [`PRIVATE_TRANSFER_PUBLIC_STATEMENT_CANDIDATE_V0_1.md`](PRIVATE_TRANSFER_PUBLIC_STATEMENT_CANDIDATE_V0_1.md); `noxis-private-proof-contract`. |
| `candidate AIR profile / NXAR / v1` | AIR constraint-profile candidate. | Exact 152 bytes. | BE fixed checksum/ID construction; exact fail-closed parser; no executable AIR follows. | [`PRIVATE_TRANSFER_AIR_PROFILE_CANDIDATE_V0_1.md`](PRIVATE_TRANSFER_AIR_PROFILE_CANDIDATE_V0_1.md); `noxis-private-proof-contract`. |
| `candidate deployment / NXPD / v1` | Unselected proof-deployment prerequisite manifest. | Exact 19,598 bytes. | BE checksummed chain `NXPD → NXIC → NXPH → NXTM`; exact parser; not a verifier/proof format. | [`PRIVATE_TRANSFER_PROOF_DEPLOYMENT_CANDIDATE_V0_1.md`](PRIVATE_TRANSFER_PROOF_DEPLOYMENT_CANDIDATE_V0_1.md); `noxis-private-proof-contract`. |

## What is deliberately absent

The registry does not turn an in-memory type, hash preimage, CometBFT schema,
fixture or filename into a protocol format. There is no selected private proof
packet, wallet transaction, public P2P envelope, finality-proof API,
authenticated checkpoint or durable private transition log. `NXPR v1` has a
single-snapshot local store that rebuilds mutable `NXSM` state; it is not
consensus durability.

Before adding a format, the change needs:

1. one owner crate and short owner specification;
2. this registry row, including exact artifact class;
3. a bounded fail-closed decoder, or explicit encoder-only status;
4. malformed/truncation/trailing-byte tests and fuzz/property plan;
5. domain-separation/canonical-ID review for hashed bytes; and
6. explicit migration, rejection or legacy-read policy.

## Mechanical inventory guard

The registry has a deliberately small CI guard:

```text
pwsh -File scripts/audit/check-format-registry.ps1
```

It collects every literal `NX..` or `NOXT` magic declared by Rust source under
`crates/` and requires a corresponding registry row. It also checks every
supported **(artifact class, magic, version)** row against an explicit
source-level version assertion, so changing (for example) `NXTM v2` to `v3`
without updating the registry fails CI. It rejects a registry magic that has no
implementation declaration and a registry identity without a supported-source
assertion.

The assertions are intentionally explicit rather than a naming heuristic:
format-version constants use several legitimate Rust names. This cannot prove
that a row's semantic limits are correct; owner-codec tests and review remain
the authority for that. It prevents a new magic, a stale registry row, or a
changed registered-version assertion from silently losing its audit-home.

Read [`DURABILITY_SPEC_V0_1.md`](DURABILITY_SPEC_V0_1.md) next for durable
authority. For candidates, use the [private-transfer research trail](README.md#private-transfer-research-trail): their registry presence is an audit index, not activation.
