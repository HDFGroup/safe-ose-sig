# Secure SDLC & Code Review Policy

**Policy intent:** Prevent introduction of SSP defects through disciplined engineering practices appropriate for a widely embedded, security-sensitive parsing library and ecosystem.

This aligns with known HDF5 SSP risk drivers (memory safety, plugins, supply chain, and “AI-generated code risk”).

## Controls

| Control ID | Control statement | Minimum evidence | Audit checklist (how to test) |
| ---------- | ----------------- | ---------------- | ----------------------------- |
| HDF5-SINS-SDLC‑01 | The default branches SHALL be protected with required reviews and CI status checks before merge. | Branch protection settings export/screenshots; required status checks list. | Verify branch rules; sample 10 merged PRs for compliance. |
| HDF5-SINS-SDLC‑02 | Security-sensitive changes (file parsing, metadata handling, plugin loader, cryptography, build scripts) SHALL receive at least one review from a designated “security reviewer” or SIG delegate. | PR labels + reviewer list; CODEOWNERS (or equivalent). | Sample PRs touching parsing/plugin areas; confirm reviewer role. |
| HDF5-SINS-SDLC‑03 | A secure coding standard SHALL be maintained for C/C++ (bounds checks, integer safety, safe alloc patterns, banned APIs, error handling). | `docs/security/secure-coding.md` (or equivalent); lint/static-analysis configuration. | Confirm existence; confirm it is referenced in CONTRIBUTING. |
| HDF5-SINS-SDLC‑04 | Changes SHALL be risk-ranked (Low/Med/High). High-risk changes SHALL include a security impact note and test plan updates. | PR template fields; security impact section in PR description. | Sample PRs; verify risk ranking + security notes. |
| HDF5-SINS-SDLC‑05 | CI SHALL run on every PR and SHALL include at least: build, unit/regression tests, and security checks configured by this manual (see TEST/BUILD policies). | `.github/workflows/*` and CI logs; badge/status pages. | Review workflow definitions; confirm required jobs are mandatory for merge. |
| HDF5-SINS-SDLC‑06 | Maintainer accounts SHALL use strong authentication (MFA) and privileged access SHALL be reviewed at least quarterly. | GitHub org security settings attestation; quarterly access review record. | Request most recent access review record; validate scope and signoff. |
