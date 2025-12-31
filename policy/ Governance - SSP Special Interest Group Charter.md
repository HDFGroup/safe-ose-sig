# Governance / SSP Special Interest Group Charter

**Policy intent:** Provide durable governance for the SSP posture of HDF5 (core + ecosystem), consistent with Safe‑OSE deliverables recommending an HDF5 SSP SIG and continuous monitoring.

HDF5 also uses public channels (forum/discussions) for community engagement, which the SIG should leverage for transparency.

## SSP SIG Charter (template)

### Mission

* Maintain and continuously improve the HDF5 SSP posture across **core**, **file format**, and **extension ecosystem**.
* Own SSP policies and ensure they stay aligned with real-world operations, user expectations, and evolving threats.

### Scope

* Policies and controls
* Security roadmap inputs, audit planning, and remediation tracking
* PSIRT process oversight and post-incident reviews
* Plugin governance decisions (registration criteria, signing, trust tiers)

### Membership & roles

* **Chair** (rotating annually)
* **PSIRT Lead** (may be same org as maintainers)
* **Release Security Liaison** (coordinates REL/BUILD controls)
* **Plugin Governance Lead** (coordinates PLUG controls)
* **Community Representatives** (users, downstream packagers, HPC centers)

### Cadence & transparency

* Meet at least monthly; publish agendas and minutes (redacting sensitive security details).
* Maintain a public “Security Posture” page summarizing: current supported versions, hardening guidance, and how to report issues.

### Decision-making

* Consensus preferred; otherwise, simple majority vote of quorum (quorum = chair + 2 additional voting members).
* Any decision that impacts compatibility guarantees requires COMP review and a documented rationale.

### Deliverables

* Quarterly metrics (TEST‑06), annual policy review, annual audit plan, and maintained audit archive (IR‑02/IR‑03).

### Governance controls

| Control ID | Control statement | Minimum evidence | Audit checklist (how to test) |
| ---------- | ----------------- | ---------------- | ----------------------------- |
| HDF5-SINS-GOV‑01 | The SSP SIG SHALL review SSP policies at least annually and record approvals and changes. | Annual review minutes + version history. | Verify last annual review date and outcomes. |
| HDF5-SINS-GOV‑02 | The SIG SHALL maintain a security backlog and publish a high-level roadmap (redacted as needed). | Roadmap doc; backlog labels. | Confirm roadmap exists; confirm backlog is active. |
| HDF5-SINS-GOV‑03 | The SIG SHALL maintain an audit archive of evidence artifacts and prior audit results (as permitted). | Archive index + retention policy. | Confirm archive exists and is access controlled. |
