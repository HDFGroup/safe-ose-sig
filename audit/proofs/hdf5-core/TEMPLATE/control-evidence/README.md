# hdf5-core — control-evidence

Machine-checked technical evidence imported from the
[`hdf5-pickles`](https://github.com/HDFGroup/hdf5-pickles) H5Policy control-evidence
contract. It is supplementary technical evidence for selected VULN/TEST/HARD/TM
controls — not a complete SSP-control attestation.

## What to put here

Populate with `audit/scripts/import_h5policy_evidence.py`, which enforces the
import ritual in
[`../../../../policy/H5Policy Control Evidence Contract.md`](../../../policy/H5Policy%20Control%20Evidence%20Contract.md):

- `imported-contract.yml` — the producer contract, copied verbatim.
- `provenance.json` — producer commit, SHA-256 of the imported contract, the
  contract's measured `libhdf5_version`, and the import timestamp.
- `checker-output.txt` — the captured `check_ssp_control_evidence.py` output from
  the same producer revision.
- `README.md` / `EVIDENCE-TABLE.md` — the control→evidence disposition and the
  SSP reviewer's note on residual control evidence the mapping does not cover.

The importer asserts the contract's measured `libhdf5_version` equals this
release's version, so evidence measured against one release cannot be filed under
another.

## Placeholder

Replace `PLACEHOLDER.md` with real artifacts for this release.
