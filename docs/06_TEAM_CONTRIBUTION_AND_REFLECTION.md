# 06. Team Contribution Breakdown (5 Individuals) & Reflection

> **Note for GitHub Submission:** The repository is hosted under your primary GitHub account (`CipherBallot`), with the codebase, security tests, and documentation cleanly structured across **5 distinct engineering workstreams** so each team member can demonstrate clear ownership during the live demonstration and individual viva. Replace `[Member X Name / Roll No]` before final submission.

---

## 1. Five-Member Responsibility Matrix

| Member | Assigned Role & Focus | Owned Modules & Files | Key Concepts to Explain in Viva |
| :--- | :--- | :--- | :--- |
| **Member 1** `[Name / Roll No]` | **Authentication, ID Verification & Access Control** | `app/auth/forms.py`, `app/auth/routes.py`, `app/security/passwords.py`, `app/templates/auth/login.html`, `register.html`, `tests/test_auth.py`, `tests/test_registration.py` | Argon2id memory-hard parameters, Student ID + Secret PIN ownership proof, anti-Sybil 1:1 identity claim, 5-attempt account lockout, RBAC (`403` checks). |
| **Member 2** `[Name / Roll No]` | **Hybrid Cryptography, Keys & Digital Signatures** | `app/security/ballots.py`, `app/security/signatures.py`, `app/security/canonical.py`, `scripts/init_keys.py`, `tests/test_ballot_encryption.py`, `test_ballot_tampering.py`, `test_signatures.py` | Hybrid encryption (ephemeral AES-256-GCM key + RSA-2048 OAEP wrap), 96-bit random nonce safety, GHASH tag & AAD binding, Ed25519 deterministic signatures, canonical JSON. |
| **Member 3** `[Name / Roll No]` | **Database Design & Variant A/B/C Voting Engine** | `app/models.py`, `app/services/voting.py`, `app/services/elections.py`, `app/services/tally.py`, `app/services/receipts.py`, `tests/test_variants.py`, `test_duplicate_vote.py`, `test_eligibility.py`, `test_receipts.py` | Table separation (`participations` vs `encrypted_ballots` vs `anonymous_tokens`), atomic `UNIQUE` constraints, Variant A vs. B vs. C workflows, SHA-256 ballot digests. |
| **Member 4** `[Name / Roll No]` | **Audit Chain, TLS/Network Security & 5 Security Experiments** | `app/security/audit.py`, `run.py`, `app/config.py`, `app/admin/routes.py` (Security Demo & Audit), `app/templates/admin/security_demo.html`, `tests/test_audit_chain.py`, `docs/04_SECURITY_TESTING_AND_WIRESHARK_GUIDE.md` | Append-only SHA-256 hash chain, self-signed X.509 certificate & HTTPS/TLS flags, Wireshark HTTP vs. TLS comparison, all 5 controlled attack demonstrations. |
| **Member 5** `[Name / Roll No]` | **UI/UX, Public Transparency, Crypto Lab & Technical Docs** | `app/templates/base.html`, `app/templates/voter/*`, `app/templates/public/*`, `app/templates/admin/variant_comparison.html`, `users.html`, `app/api/routes.py`, `scripts/seed_demo.py`, `docs/` | Public Bulletin Board & receipt verifier, Interactive 6-panel Cryptography Lab, Dark/Light accessible UI, Threat Model, Architecture & Limitations analysis. |

---

## 2. Individual One-Page Reflection Templates

### Member 1 Reflection — Authentication & Identity Security
- **Contribution:** Built Argon2id credential hashing, institutional roster validation with Secret Verification PINs, and temporary account lockout after repeated login failures.
- **Key Challenge Solved:** Preventing identity pre-emption attacks where an adversary registers using another student's public Student ID and name, solved by binding each pre-approved record to an Argon2id-hashed one-time Verification PIN.
- **Takeaway:** Understood the distinction between *identification* (public Student ID), *authentication* (secret PIN/password), and *authorization* (RBAC + election eligibility).

### Member 2 Reflection — Hybrid Cryptography & Digital Signatures
- **Contribution:** Implemented RSA-2048 OAEP key encapsulation around unique ephemeral AES-256-GCM ballot keys and Ed25519 result certification.
- **Key Challenge Solved:** Guaranteeing backward-compatible decryption alongside AAD binding so tampering with ciphertext, GCM tag, or RSA-wrapped key is immediately rejected.
- **Takeaway:** Learned why symmetric AEAD handles bulk confidentiality/integrity efficiently while asymmetric RSA-OAEP solves key distribution, and why Ed25519 eliminates nonce reuse risks in signatures.

### Member 3 Reflection — Multi-Variant Voting Architecture
- **Contribution:** Designed the 11-table isolated relational schema and implemented all three Problem #28 variants (A, B, and C) inside one cohesive voting engine.
- **Key Challenge Solved:** Supporting two-phase anonymous token voting (Variant C) without storing `voter_id` alongside token hashes or ballots, while still enforcing one token per voter atomically.
- **Takeaway:** Appreciated the core electronic voting trade-off between identity-linked auditability (Variant B) and cryptographic unlinkability (Variant C).

### Member 4 Reflection — Network Security, Auditability & Attack Testing
- **Contribution:** Added X.509 local TLS support (`--https` / `--http` toggle), SHA-256 hash-chain verification, and expanded the Security Demo to 5 CSEG3040-aligned experiments.
- **Key Challenge Solved:** Configuring Flask-Limiter rate limits alongside 5-strike account lockout so brute-force tests and live classroom demos behave predictably without IP collisions.
- **Takeaway:** Verified firsthand via Wireshark how plaintext HTTP exposes credentials and session cookies while TLS protects all application data inside encrypted records.

### Member 5 Reflection — Transparency Interfaces, Crypto Lab & Documentation
- **Contribution:** Integrated the Public Bulletin Board, Receipt Verifier, Variant Comparison visualizations, Interactive Cryptography Lab, and complete threat model/architecture documentation.
- **Key Challenge Solved:** Presenting complex cryptographic steps (nonces, AAD, digests, hash chains, and Variant A/B/C differences) clearly to both voters and technical evaluators.
- **Takeaway:** Learned how clear threat modeling and honest limitation disclosure are as critical to security engineering as the cryptography itself.
