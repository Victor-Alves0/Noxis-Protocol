# STARK composition resource decision — v0.1

## Decision

Do not extend the current single-table composed AIR from one to two depth-32
ownership paths by simple trace concatenation.

## Evidence

The locally verified release proof for one `H_INTENT` relation, four `H_NOTE`
openings, value conservation and one ownership/Merkle path used 8,192 rows and
completed in 1,178.05 seconds on 2026-08-31. The ordinary complete sequential
preflight was 499.12 seconds. Adding a second path would duplicate the largest
private component while keeping the same padded trace height.

## Consequence

The existing single-table AIR remains a correct executable research slice, but
the two-input transfer must move to a multi-table/recursive composition design:
separate ownership proofs retain their compact traces and a small outer proof
binds their committed public statement, input note commitments, intent, value
relation and nullifier transition. This is a performance and auditability gate,
not a relaxation of any protocol invariant.

## Next implementation gate

Specify a versioned inner-proof receipt and its exact public-input digest before
selecting recursion or a proof-carrying backend. No transaction acceptance or
privacy activation follows from this decision.
