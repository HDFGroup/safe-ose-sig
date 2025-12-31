# Data Handling & Privacy Policy

**Policy intent:** Ensure users are clear on how HDF5 handles user data, what HDF5 does/does not protect by default, and recommended options to implement added protection.

Safe‑OSE highlights operational/privacy risks such as metadata leakage and logging leaks, and notes the lack of built-in privacy mechanisms in current HDF5 usage patterns.

## Controls

| Control ID | Control statement | Minimum evidence | Audit checklist (how to test) |
| ---------- | ----------------- | ---------------- | ----------------------------- |
| HDF5-SINS-PRIV‑01 | Project documentation SHALL clearly state what HDF5 does/does not protect by default (data vs metadata, logs), and provide safe usage guidance. | Privacy/security guidance page. | Verify clarity and accuracy; check for misleading claims. |
| HDF5-SINS-PRIV‑02 | Logging and diagnostics SHALL be designed to avoid exposing user identifiers and sensitive metadata unless explicitly enabled. | Logging policy + tests. | Review default logs; confirm sensitive fields absent. |
| HDF5-SINS-PRIV‑03 | If integrity/encryption features are introduced, the project SHALL publish threat model assumptions and key management expectations (CRYPTO alignment). | Design docs + threat model updates. | Confirm alignment with CRYPTO and TM controls. |
