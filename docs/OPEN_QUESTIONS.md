# Open Research Questions

This is an invitation to review concrete assumptions, not a request to
“audit a blockchain.” Each question identifies a decision that needs evidence
before Noxis can make a stronger claim. Contributions are most useful when
they include a threat model, counterexample, construction, test strategy, or
primary reference.

Do not post exploitable vulnerabilities, private keys, or sensitive proofs of
breakage here; follow [SECURITY.md](../SECURITY.md).

## Hybrid and post-quantum recipient design

1. **Is the X25519 + ML-KEM combiner sound for the intended recipient envelope?**
   Define the adversary, failure behavior, KDF inputs, domain separation and
   downgrade resistance rather than assuming that concatenation is enough.
2. **Is `keyset_id` binding sufficient?**
   Determine whether every algorithm identifier, public key, version,
   recipient descriptor and context that affects decryption is bound in the
   correct place.
3. **Can diversified recipient descriptors be made unlinkable?**
   Assess scanning, address reuse, sender-side metadata and any relationship
   between a base recipient and its derived descriptors.
4. **What wallet backup, rotation and compromise model is compatible with a
   hybrid keyset?**
   A sound cryptographic envelope is not enough if recovery silently drops a
   key component or allows a downgrade.

## Private-note and STARK statement

5. **Is the nullifier construction safe?**
   Review key binding, note randomness, commitment binding, leaf position,
   domain separation, collision assumptions and cross-asset behavior.
6. **Does the exact private-transfer AIR prove all intended relations?**
   It must compose canonical intent binding, note membership, nullifier
   derivation, output commitments, range constraints, asset-specific value
   conservation, uniqueness and sequential NXSM absence/insertion.
7. **Are the Poseidon2-P24 candidate parameters and domain encodings suitable
   for the final construction?**
   Cross-check parameter provenance, byte packing, constants, rate/capacity,
   empty values and independent implementations.
8. **Does the STARK configuration provide the intended soundness and
   zero-knowledge properties?**
   Review trace hiding, FRI parameters, proof serialization, verifier failure
   behavior, side channels and resource limits. The current P3 experiment is
   a research primitive, not a selected proof system.

## State, encoding and operations

9. **Is state recovery crash-consistent for every supported platform and
   storage failure mode?**
   Examine file/directory durability, partial writes, replay, rollback,
   concurrent writers, checkpoints and operator recovery.
10. **Can canonical encoding admit ambiguity or denial of service?**
    Seek alternative byte strings, parsing differentials, integer edge cases,
    unbounded work/allocation and mismatches between code, proof and network
    framing.
11. **What consensus and governance assumptions are required before a
    multi-node deployment?**
    Review validator identity, CometBFT integration, finality semantics,
    configuration changes, upgrades, key rotation and incident response.
12. **What privacy leaks remain outside the proof?**
    Consider network metadata, timing, mempool behavior, logging, wallet
    scanning, data availability and operator telemetry.

## How to contribute an answer

Open a GitHub Discussion or use the **Research question** issue form, which
adds the `type: research question` and `status: needs triage` labels. State
which question you address, the assumptions you use, evidence or references,
expected impact, and whether a code experiment or specification change is
proposed. A negative result is valuable when it rules out an unsafe or
misleading direction.
