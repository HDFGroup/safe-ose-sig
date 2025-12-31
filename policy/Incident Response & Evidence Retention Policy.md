# Incident Response & Evidence Retention Policy

**Policy intent:** Prepare for security incidents affecting code, build systems, releases, or plugin ecosystem; preserve evidence for remediation, audits, and downstream notifications. This aligns with the Safe‑OSE plan to maintain an SSP audit archive of artifacts and procedures.

## Controls

| Control ID | Control statement | Minimum evidence | Audit checklist (how to test) |
| ---------- | ----------------- | ---------------- | ----------------------------- |
| HDF5-SINS-IR‑01 | The project SHALL maintain an incident response runbook covering: repo compromise, signing key compromise, malicious release, malicious plugin, and vulnerability embargo failure. | `docs/security/ir-runbook.md` | Confirm scenarios covered; check last review date. |
| HDF5-SINS-IR‑02 | Evidence retention SHALL include CI logs, build inputs, SBOMs, provenance attestations, and release artifacts for a defined retention period (e.g., 2 years). | Retention policy + storage location list. | Verify retention settings; sample retrieval of prior evidence. |
| HDF5-SINS-IR‑03 | Security-relevant evidence SHALL be integrity-protected (access controls + tamper-evident storage, checksums/signatures). | Hash manifests; signed log bundles. | Verify at-rest integrity controls; sample hash verification. |
| HDF5-SINS-IR‑04 | Incident communications SHALL include coordinated messages to users and downstream packagers, with clear mitigations. | Comms templates; past incident comms. | Review template; confirm escalation path and approval. |
| HDF5-SINS-IR‑05 | A post-incident review SHALL be performed and SHALL result in tracked action items and policy updates where needed. | PIR report; action item tracker. | Sample PIR; verify closure of actions. |
