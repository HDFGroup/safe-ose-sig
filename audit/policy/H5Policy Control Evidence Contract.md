# H5Policy control-evidence contract

`h5policy` produces machine-checked evidence about HDF5 metadata validation.
The producer contract maps an SSP control to an HDF5 record family, invariant,
finding, regression fixture, canary exercise, and exact-build measurement.

The contract is maintained in the
[`hdf5-pickles`](https://github.com/HDFGroup/hdf5-pickles) repository at
`registry/ssp-control-evidence.yml` and checked by
`tools/check_ssp_control_evidence.py`. This repository records the consumer
requirements in
[`audit/registry/h5policy-control-evidence.json`](../registry/h5policy-control-evidence.json).

## Evidence boundary

The mapping is technical evidence, not an attestation that the complete SSP
control is satisfied. It currently contributes to VULN-04, TEST-01, TEST-05,
HARD-04, and TM-03. Disclosure timing, review records, ownership, release
approval, and any residual-risk decision remain evidence owned by the SSP
audit.

## Importing evidence for a release

For a release audit, copy the checked producer contract into the relevant
`proofs/<component>/<version>/` evidence bundle and record:

1. The producer commit and SHA-256 of the copied contract.
2. The `libhdf5_version` in its generated measurement.
3. The output of `python3 tools/check_ssp_control_evidence.py` from the same
   producer revision.
4. The SSP reviewer’s disposition of any control evidence the mapping does not
   cover.

Do not use an unpinned branch, a hand-edited contract copy, or an oracle result
as a substitute for release-level audit evidence.
