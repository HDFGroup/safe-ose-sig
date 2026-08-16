---
title: H5Policy Integration
nav_order: 90
---

# H5Policy × SSP SIG integration — goals and trajectory

This document describes why the [`hdf5-ssp-sig`](https://github.com/HDFGroup/hdf5-ssp-sig)
governance repository and the [`hdf5-pickles`](https://github.com/HDFGroup/hdf5-pickles)
H5Policy repository are connected, what that connection guarantees today, and where
it is headed. It is orientation for contributors and auditors; the authoritative
mechanics live in [`audit/policy/H5Policy Control Evidence Contract.md`](../audit/policy/H5Policy%20Control%20Evidence%20Contract.md)
and the two checked contracts it names.

Status legend: **[shipped]** exists and is gated by a checker; **[partial]** started
but not complete; **[planned]** proposed, not yet built. Nothing marked planned
should be cited as implemented evidence.

## 1. Two repositories, one division of labor

The integration rests on a deliberate separation of authority. Neither repository
is subordinate; each owns what it is best placed to own.

| | `hdf5-ssp-sig` | `hdf5-pickles` (H5Policy) |
| --- | --- | --- |
| Role | Policy, governance, threat models, audit judgment | Enforcement mechanism and technical-evidence producer |
| Owns | `HDF5-SHINES-*` control definitions, disclosure/review/ownership records, release approval | The bounded-decode oracle, the finding/invariant registry, regression fixtures, exact-build measurements |
| Question it answers | *What must be true, and has an auditor judged it true?* | *For a malformed input, does the library uphold the invariant — and can we prove it reproducibly?* |
| Authoritative artifact | `audit/registry/h5policy-control-evidence.json`, the policy manual | `registry/ssp-control-evidence.yml`, `registry/validation-coverage.yml`, `registry/libhdf5-evidence.yml` |

H5Policy is strongest exactly where the SSP threat model is most exposed: the
**FMT** (file-format) and **LIB** (core-library) categories in
[`models/Security Threats.md`](../models/Security%20Threats.md) — crafted metadata,
pointer/offset abuse, memory-safety and DoS in parsing hot paths. The integration
lets that machine-checked strength count as technical evidence for the relevant
policy controls, without pretending it settles the human parts of a control.

## 2. Design principles

1. **Separation of authority.** SSP defines controls and renders audit judgment;
   H5Policy measures. Neither edits the other's authoritative records.
2. **Evidence boundary.** The mapping is *supplementary technical evidence*, never a
   complete control attestation. Disclosure timing, review, ownership, release
   approval, and residual-risk decisions stay SSP-owned.
3. **Pinning and provenance.** Every import records the producer commit, the
   SHA-256 of the imported contract, and the measured `libhdf5_version`.
4. **Version alignment.** Evidence measured against one library release cannot be
   filed under another; the importer enforces this.
5. **Honesty over coverage.** A fixture that only crashes the library is recorded as
   `crashes`, not dressed up as clean enforcement; a control the mapping does not
   fully cover says so.
6. **Portability.** Records identify builds, specimens, and tools by role, hash, and
   soname — never by a workstation path.

## 3. What exists today

### The checked contract **[shipped]**
- Producer: `registry/ssp-control-evidence.yml` + `tools/check_ssp_control_evidence.py`
  (hdf5-pickles). Each row maps a control to a record family, invariant, finding,
  regression fixture, canary, oracle decision, and exact-build measurement — and the
  checker validates every field against the *live* H5Policy registry.
- Consumer: `audit/registry/h5policy-control-evidence.json` +
  `audit/scripts/check_h5policy_contract.py` (this repo), which confirms each imported
  control is defined by the policy manual.

### Cross-seam consistency **[shipped]**
Each repository also compares its control set against the other's, so a control added
to one contract alone cannot drift silently. The check skips with a notice — never a
failure — when the sibling repository is not checked out, so either repository still
gates on its own.

### Evidence model that fits real defects **[shipped]**
- A control is evidenced by **many** fixtures (rows are keyed by `(control, fixture)`),
  because a control such as TEST-05 covers *every* fixed vulnerability class.
- Fixture outcomes are `enforced`, `diverges`, `crashes`, or `not_applicable`. The
  `crashes` outcome makes a memory-safety/DoS fixture — a divide-by-zero, an
  amplification — first-class evidence instead of unrepresentable.

### Release import **[shipped]**
`audit/scripts/import_h5policy_evidence.py <component> <version>` copies the checked
contract into `proofs/<component>/<version>/control-evidence/`, asserts the contract's
measured version equals the release, refuses to import unless the producer checker
passes, and records provenance. `control-evidence` is a standard proof category in the
scaffold. The first real import is
[`proofs/hdf5-core/2.2.0/control-evidence/`](../audit/proofs/hdf5-core/2.2.0/control-evidence/README.md).

### Controls covered today **[shipped]**
Five controls, six evidence rows, measured against **libhdf5 2.2.0**:
VULN-04 (dataspace element overflow), TEST-01 (chunk-index cycle),
TEST-05 (compound-member bounds **and** the v2 B-tree `record_size == 0` SIGFPE),
HARD-04 (external-link no-traverse), TM-03 (VDS source-path classification).

## 4. Trajectory

The near-term aim is breadth and automation; the long-term aim is a living, mostly
self-maintaining map from policy intent to reproducible technical proof.

### Bidirectional traceability **[planned]**
Today the control→evidence map lives only in the contract. Tagging each H5Policy
invariant or registry case with the `HDF5-SHINES-*` control(s) it serves would make
the contract *derivable* rather than hand-maintained, and let coverage be queried both
ways ("which invariants serve HARD-04?" and "which control does this fixture serve?").

### Broader control coverage **[partial]**
Prioritize the FMT/LIB/DoS cluster where H5Policy is the natural producer, driven by
the `PARTIAL`/`GAP` rows in
[`policy/OSPS  -> SHINES Coverage Matrix.md`](../policy/OSPS%20%20-%3E%20SHINES%20Coverage%20Matrix.md).
Concrete candidates: a HARD-04 row for the v2 B-tree `node_size` amplification; TM-02
from the H5Policy profile boundary as a machine-readable trust-boundary model; TEST-04
(triage) from the `h5cve` case workflow.

### Per-release measurement **[planned]**
The contract measures one library version at a time (2.2.0 today). Supported releases
should each carry their own measured contract and import bundle, so an audit of any
release cites evidence from that release.

### Release automation **[partial]**
The importer is a manual command. Wiring it into a per-release job — build the
selected libhdf5, regenerate `registry/libhdf5-evidence.yml`, run the checkers, import
with pinning — would make control evidence a routine release gate rather than a manual
step.

### Corpus / fuzz feedback loop **[partial]**
Findings from `h5policy-fuzz` and OSS-Fuzz already become tracked registry cases and
fixtures via the `h5cve` workflow. Closing the loop so each new fixed vulnerability
class automatically proposes a new TEST-05/VULN evidence row would keep the map current
by construction.

## 5. Where things live

| Concern | Location |
| --- | --- |
| Import ritual and boundary | `audit/policy/H5Policy Control Evidence Contract.md` |
| Consumer contract / checker | `audit/registry/h5policy-control-evidence.json`, `audit/scripts/check_h5policy_contract.py` |
| Importer | `audit/scripts/import_h5policy_evidence.py` |
| Imported bundles | `audit/proofs/<component>/<version>/control-evidence/` |
| Producer contract / checker | `registry/ssp-control-evidence.yml`, `tools/check_ssp_control_evidence.py` (hdf5-pickles) |
| Control catalog | `policy/README.md`, `policy/OSPS  -> SHINES Coverage Matrix.md` |

## 6. Open questions

- Should the contract's per-family `family_verdict` be decoupled from individual
  fixture outcomes, so growing the corpus does not perturb an unrelated control's row?
- How should evidence for a control the H5Policy mapping only *partly* covers be
  combined with the human evidence, so a reader never mistakes partial technical proof
  for a full attestation?
- What is the right cadence for re-measuring supported releases, and who owns it?
