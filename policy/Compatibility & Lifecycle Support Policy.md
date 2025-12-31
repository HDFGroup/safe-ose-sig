# Compatibility & Lifecycle Support Policy

**Policy intent:** Balance HDF5’s strong interoperability expectations with security realities (vulnerable legacy deployments and upgrade inertia).

Broad compatibility can reduce upgrade incentives and keep vulnerable versions in long-term use.

HDF5 release process documentation states maintenance releases are backward- and forward-compatible for the file format and notes interface compatibility caveats and reporting.

## Controls

| Control ID | Control statement | Minimum evidence | Audit checklist (how to test) |
| ---------- | ----------------- | ---------------- | ----------------------------- |
| HDF5-SINS-COMP‑01 | The project SHALL publish a compatibility contract covering: file format, API, ABI, and plugin interfaces (what is guaranteed vs not). | `docs/compatibility.md` referencing official guidance. | Confirm contract exists; confirm it matches observed practices. |
| HDF5-SINS-COMP‑02 | Supported versions/branches and end-of-support (EOS) dates SHALL be published. | Support matrix page. | Verify it’s current; confirm old branches marked EOS. |
| HDF5-SINS-COMP‑03 | Security fixes SHALL be backported to supported branches according to severity and feasibility, with transparent disclosure of what is/not patched. | Backport policy; advisory notes. | Sample one high severity issue; verify backport decision record. |
| HDF5-SINS-COMP‑04 | Breaking changes SHALL require migration guidance and advance notice (forum/newsletter/discussions), unless urgent for security. | Migration doc; announcement references. | Verify one recent change followed this process. |
