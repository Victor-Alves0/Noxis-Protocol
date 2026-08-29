# Private Notes Research Guide

The intended private-transfer model is note based: a note commitment enters a
Merkle state; later a holder proves membership and ownership, reveals a
nullifier exactly once, and creates new commitments while conserving value for
an asset. The verifier sees a canonical public statement, not the note
preimage or private witness.

This is a roadmap, not an active privacy guarantee. The current repository has
typed candidate note openings, public-intent framing, NXSM transition
references and local preflight checks. It does not yet have an audited proof
that composes those relations.

Suggested route:

1. [Private-transfer architecture draft](PRIVATE_TRANSFER_ARCHITECTURE_DRAFT_V0_1.md)
2. [Note-opening boundary](NOTE_OPENING_BOUNDARY_V0_1.md)
3. [AIR constraint profile](PRIVATE_TRANSFER_AIR_PROFILE_CANDIDATE_V0_1.md)
4. [NXSM transition candidate](PRIVATE_TRANSFER_NXSM_TRANSITION_CANDIDATE_V0_1.md)
5. [STARK deployment prerequisites](PRIVATE_TRANSFER_PROOF_DEPLOYMENT_CANDIDATE_V0_1.md)

The most valuable external review is usually a concrete counterexample to one
of the intended statement relations or a proposal for a simpler, testable
constraint design.
