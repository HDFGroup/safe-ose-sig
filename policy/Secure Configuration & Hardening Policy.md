# Secure Configuration & Hardening Policy

**Policy intent:** Provide secure-by-default options that do not unduly break existing applications, while enabling stronger enforcement for high-assurance deployments. 

Safe‑OSE proposes policy-driven runtime enforcement (YAML/JSON), including controlling minimum file format version and preventing DoS/resource exhaustion.
HDF5 plugin loading behavior can be controlled via APIs and environment variables such as `HDF5_PLUGIN_PRELOAD` and `HDF5_PLUGIN_PATH`, which are therefore security-relevant surfaces.

## Controls

| Control ID | Control statement | Minimum evidence | Audit checklist (how to test) |
| ---------- | ----------------- | ---------------- | ----------------------------- |
| HDF5-SINS-HARD‑01 | The project SHALL document a “baseline” and “hardened” configuration profile (including plugin behavior). | `docs/security/hardening.md` | Verify profiles exist; verify each maps to settings/options. |
| HDF5-SINS-HARD‑02 | Security-relevant environment variables and runtime knobs SHALL be enumerated with guidance for locking down in production. | Hardening guide section on env vars. | Confirm list completeness; confirm mitigations (allowlist paths, disable env overrides). |
| HDF5-SINS-HARD‑03 | Hardened profile SHOULD support: signed‑plugin enforcement, plugin allowlisting, and optional disabling of dynamic plugin loading. | Build/runtime options; examples. | Verify options are testable and documented with examples. |
| HDF5-SINS-HARD‑04 | The library SHOULD provide or recommend resource-limiting controls to reduce file‑based DoS (bounds on sizes, recursion, allocations). | Limits documentation; tests. | Review limits; confirm tests exist and defaults are safe. |
| HDF5-SINS-HARD‑05 | Debug and diagnostic logging SHALL avoid leaking sensitive metadata by default; sensitive logging MUST be explicitly enabled and documented. | Logging policy + redaction rules. | Sample logs in default mode; verify sensitive fields are absent. |
