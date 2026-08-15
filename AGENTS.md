# AGENTS instructions

## Purpose and scope

This repository holds HDF5 Safety, Security, and Privacy (SSP) governance,
policy, threat-model, and audit-evidence material. Treat its Markdown and
registry files as policy and audit records, not as source-code documentation.

- Read `CHARTER.md`, `GOVERNANCE.md`, `CONTRIBUTING.md`, and `SECURITY.md`
  before making a material governance or disclosure change.
- Keep public policy material free of embargoed vulnerability details, secrets,
  credentials, private reporter information, and unredacted incident evidence.
- Do not represent a template, placeholder, proposed control, or incomplete
  proof as implemented, approved, measured, or release-ready.

## Companion repository: hdf5-pickles

[`HDFGroup/hdf5-pickles`](https://github.com/HDFGroup/hdf5-pickles) produces
the machine-checked H5Policy technical evidence that this repository can use in
SSP audits. Do not assume it is checked out at any particular local path.

- Producer contract: `registry/ssp-control-evidence.yml`
- Producer validator: `tools/check_ssp_control_evidence.py`
- SSP consumer contract: `audit/registry/h5policy-control-evidence.json`

When changing either contract, inspect and validate both repositories when they
are available. Do not copy unpinned evidence into a release bundle; follow
`audit/policy/H5Policy Control Evidence Contract.md`.

## Evidence integrity

- Preserve the distinction between a policy requirement, an implementation
  claim, measured technical evidence, and an auditor's conclusion.
- Evidence added under `audit/proofs/<component>/<version>/` must identify the
  component/version, source or locator, and any relevant revision or digest.
  Record failures and residual risks; do not silently replace them with a
  passing statement.
- Use `audit/registry/exceptions.md` for deviations that need an owner,
  approver, expiry, and supporting evidence. Do not create permanent unnamed
  exceptions in prose.
- The `h5policy` control-evidence contract is supplementary technical evidence,
  not a complete SSP-control attestation. Follow
  `audit/policy/H5Policy Control Evidence Contract.md` when importing it into a
  release proof bundle: pin the producer revision and contract digest, keep the
  checker output, and record the SSP review of evidence it does not cover.

## Editing rules

- Maintain stable `HDF5-SHINES-<DOMAIN>-<NN>` control IDs. If a control is
  renamed, update its policy definition, crosswalk, evidence pointers, and any
  machine-readable reference together.
- Keep Markdown headings and tables readable in GitHub and preserve working
  relative links.
- Add a focused test or checker whenever a new policy contract is structured
  enough to drift. Prefer checks that validate concrete IDs, links, schema, and
  evidence boundaries over brittle prose matching.
- Do not edit release evidence, SBOMs, checksums, or other generated/downloaded
  artifacts by hand when their documented collection or generation workflow is
  available. Update the source workflow and regenerate instead.
- Ask before destructive rewrites of audit evidence, registry records, or
  release bundles, and before adding external dependencies or changing the
  repository's policy scope.

## Verification

Run checks relevant to the edited surface from the repository root:

| Changed surface | Required verification |
| --- | --- |
| Governance, policy, audit registry, or tests | `pytest -q` |
| Audit scaffold or proof templates | `python3 audit/scripts/check_scaffold.py` |
| H5Policy evidence contract or its SSP consumer | `python3 audit/scripts/check_h5policy_contract.py` and `pytest -q` |

Report commands run and any skipped check in the handoff.
