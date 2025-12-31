# Threat Modeling & SSP Architecture Policy

**Policy intent:** Create and maintain adequate threat models for HDF5 safety, security, and privacy vulnerabilities.

Data management libraries have unique attack surfaces (file structures, metadata graphs, plugin boundaries).
DML-focused security threat modeling approaches (e.g., CASSE) emphasize modeling file structures and library layers rather than only generic STRIDE categories.

## Controls

| Control ID | Control statement | Minimum evidence | Audit checklist (how to test) |
| ---------- | ----------------- | ---------------- | ----------------------------- |
| HDF5-SINS-TM‑01 | The project SHALL maintain a threat model covering core parsing paths, format structures, and plugin trust boundaries. | Threat model doc + update log. | Confirm threat model exists; check last update aligns with major changes. |
| HDF5-SINS-TM‑02 | Threat modeling SHALL explicitly include file structure elements (superblock/object headers/messages), plugin loader flows, and configuration entry points. | DFDs + structure diagrams. | Verify inclusion of file-structure modeling. |
| HDF5-SINS-TM‑03 | Threat models SHALL drive test planning (fuzz targets, regression suites) and hardening priorities. | Link from TM findings to TEST backlog. | Sample 3 TM findings → verify linked tests/backlog items. |
| HDF5-SINS-TM‑04 | The SIG SHOULD review threat model changes for high-risk features (new plugin types, integrity/encryption features). | SIG minutes noting TM reviews. | Verify review trail for a recent high-risk change. |
