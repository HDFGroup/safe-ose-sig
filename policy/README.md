# Policy Manual for HDF5 Library & File Format

| Key | Value |
| --- | ------|
| **Document ID:** | HDF5-SINS-PM |
| **Version:** | 0.1 (Draft) |
| **Effective date:** | 2025‑12‑31 |
| **Applies to:** | HDF5 reference implementation (HDFGroup/hdf5), HDF5 file format specification, official release artifacts, and “official/registered” plugin & extension ecosystem. |

## Definitions

* **HDF5 Core**: The HDF5 C/C++/Fortran libraries and command-line tools in the official repository.
* **Plugin / Extension**: Dynamically loadable components (e.g., filter plugins, VFDs, VOL connectors) that run in-process and can affect I/O and behavior.
* **Official distribution channels**: The HDF Group support portal downloads and official project release pages/registries used by maintainers (plus any explicitly designated package repositories).
* **Evidence**: Artifacts demonstrating a control is implemented (repo settings, policy docs, CI logs, build attestations, SBOMs, advisories, meeting minutes, etc.).
* **PSIRT**: Product Security Incident Response Team function (may be a small team) responsible for intake/triage/coordination of vulnerabilities and security incidents.
* **Registered plugin**: A plugin listed in an approved registry/index maintained by the project or an affiliated org repository (even if maintained externally).
* **SBOM**:
* **SDLC**:
* **CVSS**:
* **EOS**:
* **DFD**:

## Document control

### Version history

| Version | Date | Summary of changes |
| ------: | -----| ------------------ |
| 0.1 | 2025‑12‑31 | Initial consolidated policy manual: 14 policies; added control catalog, control‑to‑artifact mapping, and auditor worksheet. |

### Normative language

* **SHALL** = mandatory control requirement.
* **SHOULD** = strongly recommended; deviations require documented rationale.
* **MAY** = optional, risk-based.

### Control ID scheme

Controls are uniquely identified as:
**HDF5-SINS-{DOMAIN}‑{NN}** 

Example: **HDF5-SINS-SDLC‑01**.

## Policy catalog

* [**SDLC** Secure SDLC & Code Review](./Secure%20SDLC%20&%20Code%20Review%20Policy.md)
* [**DEP** Dependency & Licensing](./Dependency%20&%20Licensing%20Policy.md)
* [**VULN** Vulnerability Mgmt & Disclosure (PSIRT)](./Vulnerability%20Management%20&%20Disclosure%20(PSIRT)%20Policy.md)
* [**REL** Release & Change Control](./Release%20&%20Change%20Control%20Policy.md)
* [**IR** Incident Response & Evidence Retention](./Incident%20Response%20&%20Evidence%20Retention%20Policy.md)
* [**PLUG** Plugin & Extension Governance](./Plugin%20and%20Extension%20Governance%20Policy.md)
* [**BUILD** Secure Build, Provenance & Distribution](./Secure%20Build,%20Provenance,%20&%20Distribution%20Policy.md)
* [**TEST** Security Testing & Fuzzing](./Security%20Testing%20&%20Fuzzing%20Policy.md)
* [**COMP** Compatibility & Lifecycle Support](./Compatibility%20&%20Lifecycle%20Support%20Policy.md)
* [**CRYPTO** Cryptography & Key Management](./Cryptography%20&%20Key%20Management%20Policy.md)
* [**HARD** Secure Configuration & Hardening](./Secure%20Configuration%20&%20Hardening%20Policy.md)
* [**GOV** Governance / SSP SIG Charter](./%20Governance%20-%20SSP%20Special%20Interest%20Group%20Charter.md)
* [**TM** Threat Modeling & Security Architecture](./Threat%20Modeling%20&%20Security%20Architecture%20Policy.md)
* [**PRIV** Data Handling & Privacy](./Data%20Handling%20&%20Privacy%20Policy.md)

## Control-to-artifact mapping table (one row per control)

> “Where to find evidence” pointers are intentionally concrete (repo paths, GitHub features, release artifacts, or governance records). Adjust paths to match your repository layout if you standardize a different `docs/` structure.

> **TODO:** Hyperlink into the documents

| Control ID | Where to find evidence (pointers) |
| ---------- | --------------------------------- |
| HDF5-SINS-SDLC‑01   | GitHub branch protection settings; required status checks; merge rules; PR history      |
| HDF5-SINS-SDLC‑02   | CODEOWNERS (if used); PR labels like `security-review`; SIG reviewer roster             |
| HDF5-SINS-SDLC‑03   | `docs/security/secure-coding.md`; CONTRIBUTING references; static analysis configs      |
| HDF5-SINS-SDLC‑04   | PR template (`.github/pull_request_template.md`); PR descriptions; risk label taxonomy  |
| HDF5-SINS-SDLC‑05   | `.github/workflows/*`; CI logs/artifacts; required checks list                          |
| HDF5-SINS-SDLC‑06   | GitHub org security settings attestation; quarterly access review minutes               |
| HDF5-SINS-DEP‑01    | `docs/build/dependencies.md`; build option matrix; `release_docs/` build notes          |
| HDF5-SINS-DEP‑02    | `LICENSE`; third-party notices files in source + release tarballs                       |
| HDF5-SINS-DEP‑03    | SBOM files attached to releases; `sbom/` directory (if created)                         |
| HDF5-SINS-DEP‑04    | Dependency scan outputs; issues labeled `dependency` + `security`; PSIRT tracker        |
| HDF5-SINS-DEP‑05    | PR checklist; provenance notes; license review approvals                                |
| HDF5-SINS-VULN‑01   | `SECURITY.md` and/or GitHub “Security” tab guidance                                     |
| HDF5-SINS-VULN‑02   | PSIRT intake tracker (private); acknowledgement timestamps; email alias logs (redacted) |
| HDF5-SINS-VULN‑03   | Advisory drafts; CVSS worksheets; affected-version matrices                             |
| HDF5-SINS-VULN‑04   | Regression tests under `test/`; advisory-to-commit links; “CVE regression” CI jobs      |
| HDF5-SINS-VULN‑05   | GitHub Security Advisories; release notes referencing fixed versions                    |
| HDF5-SINS-REL‑01    | Release checklist in repo; release manager signoff record                               |
| HDF5-SINS-REL‑02    | `release_docs/CHANGELOG.md`; GitHub release notes; issue/PR references                  |
| HDF5-SINS-REL‑03    | Release notes; advisory links; PSIRT disclosure record                                  |
| HDF5-SINS-REL‑04    | Compatibility test logs; signoff notes; CI job outputs                                  |
| HDF5-SINS-REL‑05    | `docs/migration/*`; deprecation policy; announcements (forum/discussions)               |
| HDF5-SINS-REL‑06    | Provenance attestations; reproducibility reports; checksum manifests                    |
| HDF5-SINS-IR‑01     | `docs/security/ir-runbook.md`; tabletop exercise notes                                  |
| HDF5-SINS-IR‑02     | CI retention settings; artifact storage bucket; release archive index                   |
| HDF5-SINS-IR‑03     | Signed hash manifests; WORM/tamper-evident storage settings; access logs                |
| HDF5-SINS-IR‑04     | Comms templates; past announcements (forum/newsletter); escalation roster               |
| HDF5-SINS-IR‑05     | Post-incident review docs; action item tracker                                          |
| HDF5-SINS-PLUG‑01   | `docs/plugins/governance.md`; registry/index repo references; plugin tier definitions   |
| HDF5-SINS-PLUG‑02   | Plugin verification design; loader docs; enforcement level docs (Off/Warn/Strict)       |
| HDF5-SINS-PLUG‑03   | Build options documentation (e.g., require signed plugins)                              |
| HDF5-SINS-PLUG‑04   | YAML/JSON policy schema + examples; policy parser implementation                        |
| HDF5-SINS-PLUG‑05   | Plugin manifests; registry PR requirements; metadata validation checks                  |
| HDF5-SINS-PLUG‑06   | Hardening guide sections on plugin env vars (`HDF5_PLUGIN_PATH`, preload)               |
| HDF5-SINS-BUILD‑01  | CI build workflows; pinned toolchain definitions; build scripts repository references   |
| HDF5-SINS-BUILD‑02  | `SHA256SUMS`/hash manifests; release attachments; archive storage                       |
| HDF5-SINS-BUILD‑03  | Signed installer notes (Windows); signature verification docs                           |
| HDF5-SINS-BUILD‑04  | Provenance attestations; CI run IDs tied to release tags                                |
| HDF5-SINS-BUILD‑05  | Reproducibility diff reports; independent rebuild notes                                 |
| HDF5-SINS-BUILD‑06  | “Official channels” documentation; monitoring/incident notes for spoofed artifacts      |
| HDF5-SINS-TEST‑01   | `tests/fuzz/` harnesses; corpus storage; documentation                                  |
| HDF5-SINS-TEST‑02   | CI scheduled workflows; sanitizer builds; OSS-Fuzz integration references               |
| HDF5-SINS-TEST‑03   | Plugin loader adversarial tests; fuzz targets for configuration surfaces                |
| HDF5-SINS-TEST‑04   | Triage tracker for findings; labels; SLA doc                                            |
| HDF5-SINS-TEST‑05   | CVE regression tests; mapping from advisory → test case                                 |
| HDF5-SINS-TEST‑06   | Quarterly metrics reports; SIG meeting minutes where reviewed                           |
| HDF5-SINS-COMP‑01   | `docs/compatibility.md`; references to official compatibility macros/docs               |
| HDF5-SINS-COMP‑02   | Support/EOS matrix page; release branch list                                            |
| HDF5-SINS-COMP‑03   | Backport decision records; advisory fixed-version lists                                 |
| HDF5-SINS-COMP‑04   | Migration guides; announcements; deprecation notices                                    |
| HDF5-SINS-CRYPTO‑01 | Crypto design doc; dependency list; code references                                     |
| HDF5-SINS-CRYPTO‑02 | Key management SOP; access logs; rotation schedule                                      |
| HDF5-SINS-CRYPTO‑03 | Plugin signature verification docs; enforcement mode behavior                           |
| HDF5-SINS-CRYPTO‑04 | Transparency log references; attestation metadata (if Sigstore used)                    |
| HDF5-SINS-CRYPTO‑05 | Compliance notes; hardening guide addendum                                              |
| HDF5-SINS-HARD‑01   | `docs/security/hardening.md`; baseline/hardened profiles                                |
| HDF5-SINS-HARD‑02   | Enumerated env vars and runtime knobs; lockdown recommendations                         |
| HDF5-SINS-HARD‑03   | Signed-plugin enforcement examples; allowlist configs                                   |
| HDF5-SINS-HARD‑04   | Resource limit docs; parsing limit tests; DoS mitigation guidance                       |
| HDF5-SINS-HARD‑05   | Logging policy; redaction rules; default log samples                                    |
| HDF5-SINS-GOV‑01    | Annual policy review minutes; version history table                                     |
| HDF5-SINS-GOV‑02    | Security roadmap; backlog labels; SIG deliverables tracker                              |
| HDF5-SINS-GOV‑03    | Audit archive index; retention/access controls                                          |
| HDF5-SINS-TM‑01     | Threat model doc; DFDs; update log                                                      |
| HDF5-SINS-TM‑02     | File-structure diagrams; plugin flow diagrams; trust boundary notes                     |
| HDF5-SINS-TM‑03     | Links from TM findings → TEST backlog items; fuzz target list                           |
| HDF5-SINS-TM‑04     | SIG minutes recording TM reviews for major features                                     |
| HDF5-SINS-PRIV‑01   | Security/privacy guidance doc; explicit statements about default protections            |
| HDF5-SINS-PRIV‑02   | Logging tests; default logging outputs; redaction verification                          |
| HDF5-SINS-PRIV‑03   | Integrity/encryption design docs; key mgmt expectations; TM updates                     |

## One-page auditor worksheet (reusable template)

### Safe‑OSE Auditor Worksheet — HDF5 SSP Policy Manual

#### Audit metadata

* Audit ID: __________________________
* Target: ☐ HDF5 core ☐ File format ☐ Official tools ☐ Plugin ecosystem ☐ Release pipeline
* Repo(s) in scope: ______________________________________________
* Baseline revision(s): Tag(s) ____________ Commit(s) ____________
* Audit period (start/end): __________________ / __________________
* Auditor(s): ______________________________________________
* Project contact(s): ______________________________________________

#### Scope notes / exclusions

* Out of scope components: ______________________________________________
* Assumed trust boundaries: ______________________________________________

#### Evidence collected (check all that apply)

* ☐ Branch protection & PR samples
* ☐ CI workflow definitions + logs
* ☐ SECURITY/PSIRT artifacts (redacted if needed)
* ☐ Release checklist + changelog
* ☐ Build provenance + checksums + signatures
* ☐ SBOMs (core / plugins)
* ☐ Fuzzing harnesses + results
* ☐ Compatibility support matrix
* ☐ Key management SOP (redacted)
* ☐ Hardening guide + default configs
* ☐ SIG minutes + roadmap + audit archive index

#### Controls sampling

* Sample size strategy: ☐ 100% ☐ risk-based ☐ random (n=___) ☐ targeted
* Highest-risk areas sampled (describe): ______________________________________________

#### Findings log (use one row per finding)

| Finding ID | Related control(s) | Severity (L/M/H/C) | Evidence pointer | Summary | Recommendation | Owner | Target date |
| ---------- | ------------------ | -----------------: | ---------------- | ------- | -------------- | ----- | ----------- |

#### Overall assessment

* Control implementation: ☐ Strong ☐ Adequate ☐ Needs improvement ☐ High risk
* Top 3 systemic risks observed:

  1. ---
  2. ---
  3. ---

 #### Sign-off

* Auditor signature: __________________________ Date: __________
* Project acknowledgement: ____________________ Date: __________