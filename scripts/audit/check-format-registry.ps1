Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# This is an inventory guard, not a parser or a substitute for per-format
# codec tests. It intentionally checks only explicit four-byte Noxis magics;
# version semantics stay subject to normal specification review.
$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$registryPath = Join-Path $repositoryRoot 'docs/WIRE_STORAGE_FORMATS_V0_1.md'
$sourceMagicPattern = 'b"(NX[A-Z0-9]{2}|NOXT)"'
$registryMagicPattern = '\| `[^`]* / (NX[A-Z0-9]{2}|NOXT) / v[0-9][^`]*`'
$registryIdentityPattern = '\| `([^`]* / (?:NX[A-Z0-9]{2}|NOXT) / v[0-9][^`]*)`'

# One source-level version assertion for every supported registry identity.
# Rust does not use a single universal name for format-version constants, so
# this explicit list makes a version change fail CI instead of being inferred
# from an unreliable naming heuristic.
$formatVersionEvidence = @(
    @{ Identity = 'wire / NOXT / v1'; Source = 'crates/noxis-codec/src/lib.rs'; Pattern = 'TRANSACTION_FORMAT_VERSION:\s*u16\s*=\s*1' }
    @{ Identity = 'internal / NXTI / v1'; Source = 'crates/noxis-codec/src/lib.rs'; Pattern = 'TRANSACTION_FORMAT_VERSION:\s*u16\s*=\s*1' }
    @{ Identity = 'local experimental wire / NXPT / v1'; Source = 'crates/noxis-codec/src/lib.rs'; Pattern = 'PRIVATE_TRANSFER_FORMAT_VERSION:\s*u16\s*=\s*1' }
    @{ Identity = 'record / NXRC / v1'; Source = 'crates/noxis-record-chain/src/lib.rs'; Pattern = 'RECORD_FORMAT_VERSION:\s*u16\s*=\s*1' }
    @{ Identity = 'legacy storage / NXRF / v1'; Source = 'crates/noxis-storage/src/record_log.rs'; Pattern = 'RECORD_FRAME_VERSION:\s*u16\s*=\s*1' }
    @{ Identity = 'legacy storage / NXLG / v1'; Source = 'crates/noxis-storage/src/lib.rs'; Pattern = 'FRAME_VERSION:\s*u16\s*=\s*1' }
    @{ Identity = 'consensus component / NXCG / v3'; Source = 'crates/noxis-consensus/src/hash.rs'; Pattern = 'CONSENSUS_FORMAT_VERSION:\s*u16\s*=\s*3' }
    @{ Identity = 'consensus component / NXBH / v3'; Source = 'crates/noxis-consensus/src/hash.rs'; Pattern = 'CONSENSUS_FORMAT_VERSION:\s*u16\s*=\s*3' }
    @{ Identity = 'consensus component / NXFC / v3'; Source = 'crates/noxis-consensus/src/hash.rs'; Pattern = 'CONSENSUS_FORMAT_VERSION:\s*u16\s*=\s*3' }
    @{ Identity = 'consensus storage / NXCB / v2'; Source = 'crates/noxis-storage/src/block_journal.rs'; Pattern = 'BLOCK_FRAME_VERSION:\s*u16\s*=\s*2' }
    @{ Identity = 'consensus storage / NXBP / v2'; Source = 'crates/noxis-storage/src/block_journal.rs'; Pattern = 'BLOCK_PAYLOAD_VERSION:\s*u16\s*=\s*2' }
    @{ Identity = 'node storage / NXMF / v7'; Source = 'crates/noxis-runtime/src/lib.rs'; Pattern = 'MANIFEST_FORMAT_VERSION:\s*u16\s*=\s*7' }
    @{ Identity = 'legacy checkpoint / NXCP / v1'; Source = 'crates/noxis-checkpoint/src/lib.rs'; Pattern = 'CHECKPOINT_FORMAT_VERSION:\s*u16\s*=\s*1' }
    @{ Identity = 'wallet experimental wire / NXPA / v1'; Source = 'crates/noxis-wallet-crypto/src/wire.rs'; Pattern = 'PAYMENT_ADDRESS_FORMAT_VERSION:\s*u16\s*=\s*1' }
    @{ Identity = 'wallet experimental wire / NXRE / v1'; Source = 'crates/noxis-wallet-crypto/src/wire.rs'; Pattern = 'HYBRID_RECIPIENT_ENVELOPE_FORMAT_VERSION:\s*u16\s*=\s*1' }
    @{ Identity = 'wallet keystore candidate header / NXKS / v2'; Source = 'crates/noxis-wallet-keystore/src/lib.rs'; Pattern = 'KEYSTORE_HEADER_VERSION:\s*u16\s*=\s*2' }
    @{ Identity = 'wallet keystore candidate payload / NXKP / v1'; Source = 'crates/noxis-wallet-keystore/src/candidate_payload.rs'; Pattern = 'KEYSTORE_PAYLOAD_VERSION:\s*u16\s*=\s*1' }
    @{ Identity = 'wallet synthetic recovery bundle / NXKB / v1'; Source = 'crates/noxis-wallet-keystore/src/recovery_bundle.rs'; Pattern = 'SYNTHETIC_RECOVERY_BUNDLE_VERSION:\s*u16\s*=\s*1' }
    @{ Identity = 'wallet external rollback anchor / NXKA / v1'; Source = 'crates/noxis-wallet-keystore/src/external_anchor.rs'; Pattern = 'EXTERNAL_ROLLBACK_ANCHOR_VERSION:\s*u16\s*=\s*1' }
    @{ Identity = 'candidate manifest / NXTM / v1'; Source = 'crates/noxis-tree-params/src/lib.rs'; Pattern = 'DRAFT_TREE_MANIFEST_VERSION:\s*u16\s*=\s*1' }
    @{ Identity = 'candidate manifest / NXTM / v2'; Source = 'crates/noxis-tree-params/src/p24.rs'; Pattern = 'P24_CANDIDATE_MANIFEST_VERSION:\s*u16\s*=\s*2' }
    @{ Identity = 'candidate corpus / NXTV / v1'; Source = 'crates/noxis-tree-params/src/corpus.rs'; Pattern = 'DRAFT_TREE_VECTOR_VERSION:\s*u16\s*=\s*1' }
    @{ Identity = 'candidate corpus / NXTV / v2'; Source = 'crates/noxis-tree-params/src/corpus_v2.rs'; Pattern = 'P24_TREE_VECTOR_VERSION:\s*u16\s*=\s*2' }
    @{ Identity = 'candidate manifest / NXPH / v1'; Source = 'crates/noxis-tree-params/src/p24_note_domains.rs'; Pattern = 'MANIFEST_VERSION:\s*u16\s*=\s*1' }
    @{ Identity = 'candidate corpus / NXNV / v1'; Source = 'crates/noxis-tree-params/src/note_corpus_v1.rs'; Pattern = 'P24_NOTE_VECTOR_VERSION:\s*u16\s*=\s*1' }
    @{ Identity = 'candidate manifest / NXIC / v1'; Source = 'crates/noxis-tree-params/src/p24_intent_commitment.rs'; Pattern = 'MANIFEST_VERSION:\s*u16\s*=\s*1' }
    @{ Identity = 'candidate corpus / NXIV / v1'; Source = 'crates/noxis-tree-params/src/intent_corpus_v1.rs'; Pattern = 'P24_INTENT_VECTOR_VERSION:\s*u16\s*=\s*1' }
    @{ Identity = 'candidate manifest / NXSM / v1'; Source = 'crates/noxis-tree-params/src/p24_nullifier_sparse.rs'; Pattern = 'MANIFEST_VERSION:\s*u16\s*=\s*1' }
    @{ Identity = 'candidate corpus / NXSV / v1'; Source = 'crates/noxis-tree-params/src/nullifier_sparse_corpus_v1.rs'; Pattern = 'P24_NULLIFIER_SPARSE_VECTOR_VERSION:\s*u16\s*=\s*1' }
    @{ Identity = 'candidate anchor / NXPS / v1'; Source = 'crates/noxis-private-state/src/state_anchor.rs'; Pattern = 'const VERSION:\s*u16\s*=\s*1' }
    @{ Identity = 'candidate anchor / NXPS / v2'; Source = 'crates/noxis-private-state/src/state_anchor_v2.rs'; Pattern = 'const VERSION:\s*u16\s*=\s*2' }
    @{ Identity = 'candidate state record / NXPR / v1'; Source = 'crates/noxis-private-state/src/private_state_record.rs'; Pattern = 'PRIVATE_STATE_RECORD_VERSION:\s*u16\s*=\s*1' }
    @{ Identity = 'candidate private-state journal / NXPL / v1'; Source = 'crates/noxis-storage/src/private_state_journal.rs'; Pattern = 'PRIVATE_STATE_JOURNAL_VERSION:\s*u16\s*=\s*1' }
    @{ Identity = 'candidate relation / NXNT / v1'; Source = 'crates/noxis-private-proof-contract/src/nxsm_transition.rs'; Pattern = 'const VERSION:\s*u16\s*=\s*1' }
    @{ Identity = 'candidate statement / NXPU / v1'; Source = 'crates/noxis-private-proof-contract/src/public_statement.rs'; Pattern = 'const VERSION:\s*u16\s*=\s*1' }
    @{ Identity = 'candidate AIR profile / NXAR / v1'; Source = 'crates/noxis-private-proof-contract/src/air_profile.rs'; Pattern = 'const VERSION:\s*u16\s*=\s*1' }
    @{ Identity = 'candidate deployment / NXPD / v1'; Source = 'crates/noxis-private-proof-contract/src/lib.rs'; Pattern = 'const VERSION:\s*u16\s*=\s*1' }
)

$sourceMagics = [System.Collections.Generic.HashSet[string]]::new()
Get-ChildItem -Path (Join-Path $repositoryRoot 'crates') -Filter '*.rs' -File -Recurse |
    ForEach-Object {
        $contents = [System.IO.File]::ReadAllText($_.FullName)
        [regex]::Matches($contents, $sourceMagicPattern) |
            ForEach-Object { [void]$sourceMagics.Add($_.Groups[1].Value) }
    }

$registryMagics = [System.Collections.Generic.HashSet[string]]::new()
$registryContents = [System.IO.File]::ReadAllText($registryPath)
[regex]::Matches($registryContents, $registryMagicPattern) |
    ForEach-Object { [void]$registryMagics.Add($_.Groups[1].Value) }

$registryIdentities = [System.Collections.Generic.HashSet[string]]::new()
[regex]::Matches($registryContents, $registryIdentityPattern) |
    ForEach-Object { [void]$registryIdentities.Add($_.Groups[1].Value) }

$expectedIdentities = [System.Collections.Generic.HashSet[string]]::new()
foreach ($entry in $formatVersionEvidence) {
    [void]$expectedIdentities.Add($entry.Identity)
}

$missing = @($sourceMagics | Where-Object { -not $registryMagics.Contains($_) } | Sort-Object)
$stale = @($registryMagics | Where-Object { -not $sourceMagics.Contains($_) } | Sort-Object)
$missingIdentity = @($expectedIdentities | Where-Object { -not $registryIdentities.Contains($_) } | Sort-Object)
$staleIdentity = @($registryIdentities | Where-Object { -not $expectedIdentities.Contains($_) } | Sort-Object)
$invalidVersionEvidence = @()
foreach ($entry in $formatVersionEvidence) {
    $sourcePath = Join-Path $repositoryRoot $entry.Source
    $sourceContents = [System.IO.File]::ReadAllText($sourcePath)
    if (-not [regex]::IsMatch($sourceContents, $entry.Pattern)) {
        $invalidVersionEvidence += "$($entry.Identity) expected $($entry.Source) to match /$($entry.Pattern)/"
    }
}

if ($missing.Count -gt 0 -or $stale.Count -gt 0 -or $missingIdentity.Count -gt 0 -or $staleIdentity.Count -gt 0 -or $invalidVersionEvidence.Count -gt 0) {
    if ($missing.Count -gt 0) {
        Write-Error "Format registry is missing Rust magic(s): $($missing -join ', ')"
    }
    if ($stale.Count -gt 0) {
        Write-Error "Format registry has no Rust declaration for: $($stale -join ', ')"
    }
    if ($missingIdentity.Count -gt 0) {
        Write-Error "Format registry is missing supported identity row(s): $($missingIdentity -join '; ')"
    }
    if ($staleIdentity.Count -gt 0) {
        Write-Error "Format registry has unsupported identity row(s): $($staleIdentity -join '; ')"
    }
    if ($invalidVersionEvidence.Count -gt 0) {
        Write-Error "Format-version source evidence failed: $($invalidVersionEvidence -join '; ')"
    }
    exit 1
}

$inventory = @($sourceMagics | Sort-Object)
Write-Output "Format registry covers $($inventory.Count) Rust magics and $($expectedIdentities.Count) supported (class, magic, version) identities."
