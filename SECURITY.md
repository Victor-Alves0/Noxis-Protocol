# Security Policy

## Research status

Noxis is research software. It is not approved for custody, public-network
operation, private-value transfer, or protection of real assets. The current
security boundary is described in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Reporting a vulnerability

Please do **not** open a public issue for a suspected vulnerability,
exploitable parser behavior, key-material exposure, privacy failure, consensus
failure, or a way to bypass a declared safety boundary.

Use GitHub's private vulnerability-reporting flow from the repository's
**Security** tab when it is available. If it is unavailable, contact the
maintainer privately through their GitHub profile and include only enough
information to establish contact; do not publish an exploit or sensitive
details.

Include, where safe to do so:

- affected revision, crate, and platform;
- a minimal reproduction or precise conditions;
- impact and any assumptions needed to trigger it; and
- a proposed mitigation, if you have one.

## Coordinated disclosure

The maintainer will acknowledge a private report, assess reproducibility and
impact, work with the reporter on a remediation plan, and credit the reporter
when they consent. A public issue or advisory should be created only after a
fix or an agreed disclosure date.

## Out of scope for public security claims

The absence of a bug report does not imply cryptographic, privacy,
post-quantum, consensus, or operational security. In particular, the current
STARK and hybrid-wallet work is experimental and is not authorization to use
Noxis with transferable value.

For design-level review that is not a vulnerability report, use the
[open research questions](docs/OPEN_QUESTIONS.md) or the repository
discussions.
