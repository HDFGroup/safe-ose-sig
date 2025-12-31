# Secure Build, Provenance, and Distribution Policy

**Policy intent:** Reduce supply-chain risk in released libraries/tools/plugins and ensure downstream users can verify authenticity and integrity.

Safe‑OSE explicitly calls for SBOMs and increased adoption of signed, reproducible build processes.

## Controls

| Control ID | Control statement | Minimum evidence | Audit checklist (how to test) |
| ---------- | ----------------- | ---------------- | ----------------------------- |
| HDF5-SINS-BUILD‑01 | Release builds SHALL be performed in controlled environments (documented toolchains, pinned dependencies where feasible). | Build recipes; CI workflow definitions. | Verify build definitions; confirm immutability/pinning approach. |
| HDF5-SINS-BUILD‑02 | Each release SHALL publish cryptographic checksums for all artifacts and SHALL retain them for the lifecycle of the release. | `SHA256SUMS` (or equivalent) and signatures. | Verify checksums for latest release; confirm archival. |
| HDF5-SINS-BUILD‑03 | Official release artifacts SHOULD be signed (code signing for installers; signature files for tarballs) and signature verification instructions SHALL be published. | Signed installer note (Windows) and signing docs. | Verify artifacts are signed; verify instructions are complete. |
| HDF5-SINS-BUILD‑04 | Each release SHOULD include provenance attestations (builder identity, source revision, build steps). | Provenance attestation files; CI run references. | Verify attestation links to exact git commit and workflow run. |
| HDF5-SINS-BUILD‑05 | Reproducibility SHOULD be measured (at least for a reference platform), and discrepancies SHALL be investigated. | Reproducibility report. | Review last report; verify follow-ups exist. |
| HDF5-SINS-BUILD‑06 | Distribution channels SHALL be enumerated and monitored for integrity risks (unofficial mirrors, trojanized packages). | “Official channels” page; monitoring notes. | Verify list is current; confirm response steps for discovered spoofing. |
