# hdf5-core 2.2.0 — control-evidence (H5Policy)

**Owner:** `<fill>`  **Reviewers:** `<fill>`
**Status:** ☑ draft ☐ in review ☐ final

Machine-checked technical evidence imported from the
[`hdf5-pickles`](https://github.com/HDFGroup/hdf5-pickles) H5Policy control-evidence
contract, measured against **libhdf5 2.2.0**. Supplementary technical evidence for
selected controls — **not** a complete SSP-control attestation.

## 1) Scope

- Producer contract: `registry/ssp-control-evidence.yml` (hdf5-pickles).
- Measured libhdf5 version: **2.2.0** (must equal this release; enforced by the importer).
- Controls contributed: **VULN-04, TEST-01, TEST-05, HARD-04, TM-03** (5 controls, 6 evidence rows).

## 2) Method

Imported with `audit/scripts/import_h5policy_evidence.py hdf5-core 2.2.0`, which:

1. asserts the contract's measured `libhdf5_version` equals `2.2.0`;
2. runs the producer checker `tools/check_ssp_control_evidence.py` and requires it to pass;
3. records the producer commit, the SHA-256 of the imported contract, and the checker output.

See [`provenance.json`](./provenance.json), [`imported-contract.yml`](./imported-contract.yml),
and [`checker-output.txt`](./checker-output.txt).

## 3) Disposition

- The mapping and its native measurement check out (`checker-output.txt`).
- Per the [contract](../../../../policy/H5Policy%20Control%20Evidence%20Contract.md),
  this contributes technical evidence only. Disclosure timing, review records,
  ownership, release approval, and residual-risk decisions remain SSP-owned.
- **Residual control evidence not covered by the mapping** (SSP reviewer to
  complete): `<fill: for each of VULN-04/TEST-01/TEST-05/HARD-04/TM-03, what the
  H5Policy fixture does NOT establish, and where the rest of that control's
  evidence lives>`.

See [`EVIDENCE-TABLE.md`](./EVIDENCE-TABLE.md) for the per-control disposition.
