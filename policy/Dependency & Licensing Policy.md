# Dependency & Licensing Policy

**Policy intent:** Ensure downstream trust and legal clarity, and reduce supply-chain exposure from third-party libraries and transitive components (e.g., compression backends, build tooling).

## Controls

| Control ID | Control statement | Minimum evidence | Audit checklist (how to test) |
| ---------- | ----------------- | ---------------- | ----------------------------- |
| HDF5-SINS-DEP‑01 | The project SHALL maintain an inventory of direct runtime and build-time dependencies (including optional feature toggles). | Dependency inventory doc + build option matrix. | Confirm list covers common build configs; spot-check against build scripts. |
| HDF5-SINS-DEP‑02 | Each release SHALL publish a license manifest for bundled/linked third-party components (including notices). | `THIRD_PARTY_NOTICES*` or release bundle notice file. | Verify file exists in release artifacts; verify updates each release. |
| HDF5-SINS-DEP‑03 | Each release SHOULD produce an SBOM for core artifacts and (where feasible) official plugins. | SBOM files attached to releases (SPDX/CycloneDX). | Confirm SBOM presence for latest release + one prior release. |
| HDF5-SINS-DEP‑04 | Dependencies SHALL be monitored for known vulnerabilities; remediation timelines SHALL be defined (severity-based). | Vulnerability tracking issue labels; dependency scanning reports. | Sample recent dependency CVE; confirm triage + fix timeline. |
| HDF5-SINS-DEP‑05 | New third-party code adoption SHALL require: license review, provenance check, and security review (per SDLC‑02). | PR checklist completion; provenance note. | Sample 3 dependency-introducing PRs; confirm evidence. |
