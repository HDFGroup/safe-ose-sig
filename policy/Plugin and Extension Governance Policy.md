# Plugin and Extension Governance Policy

**Policy intent:** Treat extensions as a first-class security boundary. Dynamic loading enables flexibility but can enable arbitrary code execution and silent compromise if unmanaged.

The Safe‑OSE proposal specifically calls out current plugin manager weaknesses (no signature/version awareness, no constraints, no isolation) and proposes a policy-driven runtime enforcement framework (YAML/JSON).

## Controls

| Control ID | Control statement | Minimum evidence | Audit checklist (how to test) |
| ---------- | ----------------- | ---------------- | ----------------------------- |
| HDF5-SINS-PLUG‑01 | The project SHALL define plugin classes (Filter, VFD, VOL, Others) and a governance model for “Official”, “Registered”, and “Unregistered” plugins. | `docs/plugins/governance.md` | Confirm tiers and requirements are explicit. |
| HDF5-SINS-PLUG‑02 | Official plugins SHALL require cryptographic signatures and verification support in the loader, with enforceable modes (Off/Warn/Strict). | Loader design doc; config flags. The SC25 plugin signing design includes Off/Warn/Strict concepts. | Verify mode exists; confirm defaults per HARD policy. |
| HDF5-SINS-PLUG‑03 | Hardened builds SHALL support a “require signed plugins” configuration (build-time and/or runtime). | Build option docs. Example CMake option described in SC25 paper: `HDF5_REQUIRE_SIGNED_PLUGINS`. | Verify option is documented and testable; check hardened build artifacts. |
| HDF5-SINS-PLUG‑04 | A machine-readable plugin policy format (YAML/JSON) SHOULD be supported to restrict plugin paths, allowed plugin IDs, versions, and resource limits. | Policy schema + example policies. Safe‑OSE explicitly proposes YAML/JSON policy enforcement. | Verify schema; confirm example policies cover path allowlists and version pins. |
| HDF5-SINS-PLUG‑05 | Registered plugins SHOULD provide minimum metadata: version, license, supported HDF5 versions/APIs, and (preferred) SBOM/provenance. | Plugin manifest template; registry PR requirements. | Sample 3 registered plugins; verify metadata completeness. |
| HDF5-SINS-PLUG‑06 | Plugin documentation SHALL warn that plugin path settings and preload mechanisms are security-sensitive and must be controlled in high-assurance deployments. | Hardening guide section referencing environment variables. | Verify docs explicitly call out risk and mitigation steps. |
