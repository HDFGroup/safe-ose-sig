# OSPS → SHINES Coverage Matrix

Assessed against [OSPS Baseline **v2026.08.28**](https://baseline.openssf.org/versions/2026.08.28)
(65 criteria). Original crosswalk 2026-01-16 against the then-development Baseline;
re-pinned to v2026.08.28 on 2026-09-01. All 62 originally assessed criterion IDs are
unchanged in v2026.08.28; the three criteria added since are assessed below.

## Legend

* **COVERED** = a SHINES control’s evidence pointer clearly aligns with the OSPS requirement
* **PARTIAL** = related SHINES evidence exists, but the OSPS requirement isn’t explicit in the evidence pointers
* **GAP** = no clear SHINES evidence pointer for that OSPS requirement

**Counts:** COVERED **24**, PARTIAL **26**, GAP **15** (of 65 criteria).

## Gaps at a glance (OSPS controls flagged GAP in the matrix)

These are the places where the evidence-pointer table doesn’t show an obvious SHINES control match (i.e., would be the most immediate candidates for SHINES-policy additions or for adding explicit evidence pointers):

* **CI/CD permissions least privilege**
  * OSPS-AC-04.01 (L2)
  * OSPS-AC-04.02 (L3)
* **CI/CD input sanitization**
  * OSPS-BR-01.01 (L1)
  * OSPS-BR-01.02 (L1)
* **User-facing documentation basics**
  * OSPS-DO-01.01 (L1) — user guides for basic functionality
  * OSPS-DO-02.01 (L1) — defect reporting guide
* **Project governance documentation**
  * OSPS-GV-01.02 (L2) — roles & responsibilities
* **Contributor legal attestation**
  * OSPS-LE-01.01 (L2) — per-commit legal authorization assertion (e.g., DCO/CLA patterns)
* **Repository hygiene / transparency items not evidenced**
  * OSPS-QA-01.01 (L1) — public repo at static URL
  * OSPS-QA-01.02 (L1) — public change record
  * OSPS-QA-04.01 (L1) — list of subprojects
  * OSPS-QA-05.01 (L1) — no generated executables in VCS
  * OSPS-QA-05.02 (L1) — no unreviewable binaries in VCS
  * OSPS-QA-04.02 (L3) — subprojects enforce ≥ same security requirements
* **VEX**
  * OSPS-VM-04.02 (L3) — VEX for non-affecting vulnerabilities

## Assessment notes — criteria added in v2026.08.28 (assessed 2026-09-01)

v2026.08.28 adds three criteria that were not present when the original crosswalk was
made on 2026-01-16. All 62 previously assessed criterion IDs are unchanged in this
version, so only the three below required new assessment. Evidence is from
`HDFGroup/hdf5@develop`.

* **OSPS-BR-01.03 (L1) — COVERED.** `.github/workflows/review-checklist.yml` is the only
  workflow in the repository using a privileged trigger (`pull_request_target`,
  `workflow_run`). It sets no `ref:` override, so the checkout always resolves to the base
  branch and fork code is never checked out or executed; it also sets
  `persist-credentials: false`, scopes `permissions:` to
  `pull-requests: write / issues: write / contents: read`, guards on
  `github.repository == 'HDFGroup/hdf5'`, and pins actions to full commit SHAs. The
  companion `review-checklist-gather.yml` runs on `pull_request_review` with
  `permissions: {}`. Repository settings require approval for first-time-contributor fork
  workflows.

* **OSPS-BR-01.04 (L3) — PARTIAL.** `.github/workflows/zizmor.yml` (added 2026-06-09) runs
  zizmor static analysis over all user-facing workflows and uploads SARIF to the Security
  tab, which covers template injection from `workflow_dispatch` inputs. A sweep of the
  workflow set found no raw `${{ inputs.* }}` interpolation into `run:` shell strings.
  Rated PARTIAL rather than COVERED because the zizmor step is `continue-on-error: true`,
  so findings do not gate merges, and detection is not the same as the sanitization and
  validation the criterion requires.

* **OSPS-DO-07.01 (L2) — COVERED.** `docs/INSTALL_CMake.md` contains a Prerequisites
  section (CMake 3.26+, supported compilers) and a versioned dependency list with sources
  (ZLIB, ZLIB-NG, libaec/szip), linked from `README.md` alongside `INSTALL_Windows.md`,
  `INSTALL_Cygwin.md`, and `README_HPC.md`.

### Flagged for SIG decision — not changed here

`OSPS-BR-01.01` and `OSPS-BR-01.02` (CI/CD input and branch-name sanitization) are both
rated **GAP**. Those ratings date from 2026-01-16, but `zizmor.yml` landed on 2026-06-09
and provides the same static-analysis coverage cited above for `OSPS-BR-01.04`. On that
evidence both look stale and would arguably move to PARTIAL, which would make the counts
24 / 28 / 13. Re-rating existing controls is left to the SIG rather than folded into this
change.

## Access Control (AC)

| OSPS control  | Level | Requirement (from OSPS overview)                                                                               | SHINES control(s)  | Status  |
| ------------- | ----: | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------- | ------- |
| OSPS-AC-01.01 |     1 | When a user attempts to read or modify a sensitive resource in the project's authoritative repository, the system MUST require the user to complete a multi-factor authentication process. | HDF5-SHINES-SDLC-06                           | PARTIAL |
| OSPS-AC-02.01 |     1 | When a new collaborator is added, the version control system MUST require manual permission assignment, or restrict the collaborator permissions to the lowest available privileges by default. | HDF5-SHINES-SDLC-06                           | PARTIAL |
| OSPS-AC-03.01 |     1 | When a direct commit is attempted on the project's primary branch, an enforcement mechanism MUST prevent the change from being applied. | HDF5-SHINES-SDLC-01                           | COVERED |
| OSPS-AC-03.02 |     1 | When an attempt is made to delete the project's primary branch, the version control system MUST treat this as a sensitive activity and require explicit confirmation of intent. | HDF5-SHINES-SDLC-01                           | COVERED |
| OSPS-AC-04.01 |     2 | When a CI/CD task is executed with no permissions specified, the CI/CD system MUST default the task's permissions to the lowest permissions granted in the pipeline. | HDF5-SHINES-SDLC-05, HDF5-SHINES-BUILD-01     | GAP     |
| OSPS-AC-04.02 |     3 | When a job is assigned permissions in a CI/CD pipeline, the source code or configuration MUST only assign the minimum privileges necessary for the corresponding activity. | HDF5-SHINES-SDLC-05, HDF5-SHINES-BUILD-01     | GAP     |

## Build and Release (BR)

| OSPS control  | Level | Requirement (from OSPS overview)                                                                               | SHINES control(s)                                      | Status  |
| ------------- | ----: | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- | ------- |
| OSPS-BR-01.01 |     1 | When a CI/CD pipeline accepts an input parameter, that parameter MUST be sanitized and validated prior to use in the pipeline. | HDF5-SHINES-SDLC-05, HDF5-SHINES-BUILD-01                                         | GAP     |
| OSPS-BR-01.02 |     1 | When a CI/CD pipeline uses a branch name in its functionality, that name value MUST be sanitized and validated prior to use in the pipeline. | HDF5-SHINES-SDLC-05, HDF5-SHINES-BUILD-01                                         | GAP     |
| OSPS-BR-01.03 |     1 | When a CI/CD pipeline operates on untrusted code snapshots, it MUST prevent access to privileged CI/CD credentials and assets. | HDF5-SHINES-SDLC-05, HDF5-SHINES-BUILD-01                                         | COVERED |
| OSPS-BR-03.01 |     1 | When the project lists a URI as an official project channel, that URI MUST be exclusively delivered using encrypted channels. | HDF5-SHINES-BUILD-06                                                              | PARTIAL |
| OSPS-BR-03.02 |     1 | When the project lists a URI as an official distribution channel, that URI MUST be exclusively delivered using encrypted channels. | HDF5-SHINES-BUILD-06                                                              | PARTIAL |
| OSPS-BR-07.01 |     1 | The project MUST prevent the unintentional storage of unencrypted sensitive data, such as secrets and credentials, in the version control system. | HDF5-SHINES-SDLC-06                                                               | PARTIAL |
| OSPS-BR-02.01 |     2 | When an official release is created, that release MUST be assigned a unique version identifier. | HDF5-SHINES-REL-02                                                                | COVERED |
| OSPS-BR-04.01 |     2 | When an official release is created, that release MUST contain a descriptive log of functional and security modifications. | HDF5-SHINES-REL-02, HDF5-SHINES-REL-03                                            | COVERED |
| OSPS-BR-05.01 |     2 | When a build and release pipeline ingests dependencies, it MUST use standardized tooling where available. | HDF5-SHINES-BUILD-01, HDF5-SHINES-DEP-01                                          | PARTIAL |
| OSPS-BR-06.01 |     2 | When an official release is created, that release MUST be signed or accounted for in a signed manifest including each asset's cryptographic hashes. | HDF5-SHINES-BUILD-02, HDF5-SHINES-REL-06, HDF5-SHINES-IR-03, HDF5-SHINES-BUILD-03 | COVERED |
| OSPS-BR-01.04 |     3 | CI/CD pipelines which accept trusted collaborator input MUST sanitize and validate that input prior to use in the pipeline. | HDF5-SHINES-SDLC-05, HDF5-SHINES-BUILD-01                                         | PARTIAL |
| OSPS-BR-02.02 |     3 | When an official release is created, all assets within that release MUST be clearly associated with the release identifier or another unique identifier for the asset. | HDF5-SHINES-BUILD-02, HDF5-SHINES-REL-02                                          | PARTIAL |
| OSPS-BR-07.02 |     3 | The project MUST define a policy for managing secrets and credentials used by the project. The policy should include guidelines for storing, accessing, and rotating secrets and credentials. | HDF5-SHINES-CRYPTO-02                                                             | PARTIAL |

## Documentation (DO)

| OSPS control  | Level | Requirement (from OSPS overview)                                                                               | SHINES control(s)                   | Status  |
| ------------- | ----: | -------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- | ------- |
| OSPS-DO-01.01 |     1 | When the project has made a release, the project documentation MUST include user guides for all basic functionality. | —                                                              | GAP     |
| OSPS-DO-02.01 |     1 | When the project has made a release, the project documentation MUST include a guide for reporting defects. | —                                                              | GAP     |
| OSPS-DO-06.01 |     2 | When the project has made a release, the project documentation MUST include a description of how the project selects, obtains, and tracks its dependencies. | HDF5-SHINES-DEP-01                                             | COVERED |
| OSPS-DO-07.01 |     2 | The project documentation MUST include instructions on how to build the software, including required libraries, frameworks, SDKs, and dependencies. | HDF5-SHINES-BUILD-01, HDF5-SHINES-DEP-01                       | COVERED |
| OSPS-DO-03.01 |     3 | When the project has made a release, the project documentation MUST contain instructions to verify the integrity and authenticity of the release assets. | HDF5-SHINES-BUILD-02, HDF5-SHINES-BUILD-03, HDF5-SHINES-REL-06 | COVERED |
| OSPS-DO-03.02 |     3 | When the project has made a release, the project documentation MUST contain instructions to verify the expected identity of the person or process authoring the software release. | HDF5-SHINES-BUILD-04, HDF5-SHINES-CRYPTO-02                    | PARTIAL |
| OSPS-DO-04.01 |     3 | When the project has made a release, the project documentation MUST include a descriptive statement about the scope and duration of support for each release. | HDF5-SHINES-COMP-02                                            | COVERED |
| OSPS-DO-05.01 |     3 | When the project has made a release, the project documentation MUST provide a descriptive statement when releases or versions will no longer receive security updates. | HDF5-SHINES-COMP-02, HDF5-SHINES-COMP-03                       | COVERED |

## Governance (GV)

| OSPS control  | Level | Requirement (from OSPS overview)                                                                               | SHINES control(s)  | Status  |
| ------------- | ----: | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------- | ------- |
| OSPS-GV-02.01 |     1 | While active, the project MUST have one or more mechanisms for public discussions about proposed changes and usage obstacles. | HDF5-SHINES-GOV-02, HDF5-SHINES-SDLC-04       | PARTIAL |
| OSPS-GV-03.01 |     1 | While active, the project documentation MUST include an explanation of the contribution process. | HDF5-SHINES-SDLC-03                           | COVERED |
| OSPS-GV-01.01 |     2 | While active, the project documentation MUST include a list of project members with access to sensitive resources. | HDF5-SHINES-SDLC-06                           | PARTIAL |
| OSPS-GV-01.02 |     2 | While active, the project documentation MUST include descriptions of the roles and responsibilities for members of the project. | —                                             | GAP     |
| OSPS-GV-03.02 |     2 | While active, the project documentation MUST include a guide for code contributors that includes requirements for acceptable contributions. | HDF5-SHINES-SDLC-03, HDF5-SHINES-SDLC-04      | COVERED |
| OSPS-GV-04.01 |     3 | While active, the project documentation MUST have a policy that code collaborators are reviewed prior to granting escalated permissions to sensitive resources. | HDF5-SHINES-SDLC-06                           | PARTIAL |

## Legal (LE)

| OSPS control  | Level | Requirement (from OSPS overview)                                                                               | SHINES control(s)  | Status  |
| ------------- | ----: | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------- | ------- |
| OSPS-LE-02.01 |     1 | While active, the license for the source code MUST meet the OSI Open Source Definition or the FSF Free Software Definition. | HDF5-SHINES-DEP-02                            | PARTIAL |
| OSPS-LE-02.02 |     1 | While active, the license for the released software assets MUST meet the OSI Open Source Definition or the FSF Free Software Definition. | HDF5-SHINES-DEP-02                            | PARTIAL |
| OSPS-LE-03.01 |     1 | While active, the license for the source code MUST be maintained in the corresponding repository's LICENSE file, COPYING file, or LICENSE/ directory. | HDF5-SHINES-DEP-02                            | COVERED |
| OSPS-LE-03.02 |     1 | While active, the license for the released software assets MUST be included in the released source code, or in a LICENSE file, COPYING file, or LICENSE/ directory alongside the corresponding release assets. | HDF5-SHINES-DEP-02                            | COVERED |
| OSPS-LE-01.01 |     2 | While active, the version control system MUST require all code contributors to assert that they are legally authorized to make the associated contributions on every commit. | —                                             | GAP     |

## Quality (QA)

| OSPS control  | Level | Requirement (from OSPS overview)                                                                               | SHINES control(s)  | Status  |
| ------------- | ----: | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------- | ------- |
| OSPS-QA-01.01 |     1 | While active, the project's source code repository MUST be publicly readable at a static URL. | —                                             | GAP     |
| OSPS-QA-01.02 |     1 | The version control system MUST contain a publicly readable record of all changes made, who made the changes, and when the changes were made. | —                                             | GAP     |
| OSPS-QA-02.01 |     1 | When the package management system supports it, the source code repository MUST contain a dependency list that accounts for the direct language dependencies. | HDF5-SHINES-DEP-01                            | COVERED |
| OSPS-QA-04.01 |     1 | While active, the project documentation MUST contain a list of any codebases that are considered subprojects. | —                                             | GAP     |
| OSPS-QA-05.01 |     1 | While active, the version control system MUST NOT contain generated executable artifacts. | —                                             | GAP     |
| OSPS-QA-05.02 |     1 | While active, the version control system MUST NOT contain unreviewable binary artifacts. | —                                             | GAP     |
| OSPS-QA-03.01 |     2 | When a commit is made to the primary branch, any automated status checks for commits MUST pass or be manually bypassed. | HDF5-SHINES-SDLC-01                           | COVERED |
| OSPS-QA-06.01 |     2 | Prior to a commit being accepted, the project's CI/CD pipelines MUST run at least one automated test suite to ensure the changes meet expectations. | HDF5-SHINES-SDLC-05                           | COVERED |
| OSPS-QA-02.02 |     3 | When the project has made a release, all compiled released software assets MUST be delivered with a software bill of materials. | HDF5-SHINES-DEP-03                            | COVERED |
| OSPS-QA-04.02 |     3 | When the project has made a release comprising multiple source code repositories, all subprojects MUST enforce security requirements that are as strict or stricter than the primary codebase. | —                                             | GAP     |
| OSPS-QA-06.02 |     3 | While active, project's documentation MUST clearly document when and how tests are run. | HDF5-SHINES-TEST-02, HDF5-SHINES-SDLC-05      | PARTIAL |
| OSPS-QA-06.03 |     3 | While active, the project's documentation MUST include a policy that all major changes to the software produced by the project should add or update tests of the functionality in an automated test suite. | HDF5-SHINES-SDLC-04                           | PARTIAL |
| OSPS-QA-07.01 |     3 | When a commit is made to the primary branch, the project's version control system MUST require at least one non-author human approval of the changes before merging. | HDF5-SHINES-SDLC-01, HDF5-SHINES-SDLC-02      | COVERED |

## Security Assessment (SA)

| OSPS control  | Level | Requirement (from OSPS overview)                                                                               | SHINES control(s)                               | Status  |
| ------------- | ----: | -------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- | ------- |
| OSPS-SA-01.01 |     2 | When the project has made a release, the project documentation MUST include design documentation demonstrating all actions and actors within the system. | HDF5-SHINES-TM-02                                                          | PARTIAL |
| OSPS-SA-02.01 |     2 | When the project has made a release, the project documentation MUST include descriptions of all external software interfaces of the released software assets. | HDF5-SHINES-TM-02                                                          | PARTIAL |
| OSPS-SA-03.01 |     2 | When the project has made a release, the project MUST perform a security assessment to understand the most likely and impactful potential security problems that could occur within the software. | HDF5-SHINES-TM-01, HDF5-SHINES-GOV-03                                      | PARTIAL |
| OSPS-SA-03.02 |     3 | When the project has made a release, the project MUST perform a threat modeling and attack surface analysis to understand and protect against attacks on critical code paths, functions, and interactions within the system. | HDF5-SHINES-TM-01, HDF5-SHINES-TM-02, HDF5-SHINES-TM-03, HDF5-SHINES-TM-04 | COVERED |

## Vulnerability Management (VM)

| OSPS control  | Level | Requirement (from OSPS overview)                                                                               | SHINES control(s)  | Status  |
| ------------- | ----: | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------- | ------- |
| OSPS-VM-02.01 |     1 | While active, the project documentation MUST contain security contacts. | HDF5-SHINES-VULN-01                           | COVERED |
| OSPS-VM-01.01 |     2 | While active, the project documentation MUST include a policy for coordinated vulnerability disclosure (CVD), with a clear timeframe for response. | HDF5-SHINES-VULN-01, HDF5-SHINES-VULN-02      | PARTIAL |
| OSPS-VM-03.01 |     2 | While active, the project documentation MUST provide a means for private vulnerability reporting directly to the security contacts within the project. | HDF5-SHINES-VULN-01, HDF5-SHINES-VULN-02      | COVERED |
| OSPS-VM-04.01 |     2 | While active, the project documentation MUST publicly publish data about discovered vulnerabilities. | HDF5-SHINES-VULN-05, HDF5-SHINES-VULN-03      | COVERED |
| OSPS-VM-04.02 |     3 | While active, any vulnerabilities in the software components not affecting the project MUST be accounted for in a VEX document, augmenting the vulnerability report with non-exploitability details. | —                                             | GAP     |
| OSPS-VM-05.01 |     3 | While active, the project documentation MUST include a policy that defines a threshold for remediation of SCA findings related to vulnerabilities and licenses. | HDF5-SHINES-DEP-04                            | PARTIAL |
| OSPS-VM-05.02 |     3 | While active, the project documentation MUST include a policy to address SCA violations prior to any release. | HDF5-SHINES-REL-01, HDF5-SHINES-DEP-04        | PARTIAL |
| OSPS-VM-05.03 |     3 | While active, all changes to the project's codebase MUST be automatically evaluated against a documented policy for malicious dependencies and known vulnerabilities in dependencies, then blocked in the event of violations, except when declared and suppressed as non-exploitable. | HDF5-SHINES-DEP-04, HDF5-SHINES-SDLC-05       | PARTIAL |
| OSPS-VM-06.01 |     3 | While active, the project documentation MUST include a policy that defines a threshold for remediation of SAST findings. | HDF5-SHINES-SDLC-03                           | PARTIAL |
| OSPS-VM-06.02 |     3 | While active, all changes to the project's codebase MUST be automatically evaluated against a documented policy for security weaknesses and blocked in the event of violations except when declared and suppressed as non-exploitable. | HDF5-SHINES-SDLC-03, HDF5-SHINES-SDLC-05      | PARTIAL |
