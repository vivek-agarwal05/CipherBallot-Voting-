# 01. Project Proposal & Approved Problem Statement

- **Course:** CSEG3040 — Cryptography and Network Security (Semester V)
- **Project Title:** CipherBallot — Secure Online Voting Prototype
- **Problem Statement #28:** Create an educational voting system that protects voter authentication, vote confidentiality, integrity, and duplicate-vote prevention.
- **Core Concepts:** Authentication, hybrid encryption, digital signatures, anonymity trade-offs, auditability, and transport-layer security.

---

## 1. Assigned Variants Integrated Into One Platform

| Variant | Problem #28 Description | How CipherBallot Implements It |
| :--- | :--- | :--- |
| **Variant A** | Single-class election with encrypted ballots | Any active voter account can cast 1 ballot without a manual roster; uses Hybrid **RSA-2048 OAEP + AES-256-GCM** encryption and atomic duplicate prevention (no public receipt code issued). |
| **Variant B** | Department poll with voter eligibility & verifiable receipts | Enforces explicit per-election eligibility rosters (`ElectionEligibility`), Hybrid encryption, **SHA-256** verifiable ballot receipts on the Public Bulletin Board, and **Ed25519** signed tallies. |
| **Variant C** | Privacy-focused design comparing anonymous tokens with identity-linked audit records | Two-phase protocol: **Phase 1** verifies identity & logs `token_issued` in `participations` while issuing a 256-bit random token (only `SHA-256(token)` stored in `anonymous_tokens`); **Phase 2** redeems the token anonymously with zero `voter_id` attached. |

---

## 2. Course Outcome (CO) & Syllabus Alignment (CSEG3040)

| Course Outcome / Unit | Cryptographic / Security Implementation in CipherBallot |
| :--- | :--- |
| **CO1 / Unit I** (Basics, Threats & Services) | Threat model covering confidentiality, integrity, authentication, authorization, and non-repudiation across 4 adversary profiles. |
| **CO2 / Unit II** (Symmetric Crypto & Block Modes) | Fresh per-ballot 256-bit **AES-256-GCM** encryption with unique 96-bit random nonces (`os.urandom(12)`), 128-bit GHASH MAC tags, and Additional Authenticated Data (AAD). |
| **CO2 & Unit III** (Public-Key Crypto, RSA, ECC, Signatures, Certs) | **RSA-2048 OAEP** (SHA-256) wraps each ballot's ephemeral AES key (Hybrid Encryption); **Ed25519** certifies election tallies; local **X.509** certificate enables TLS. |
| **CO3 / Unit IV** (Hash Functions & Integrity) | **SHA-256** verifiable ballot digests, **SHA-256** hashed Variant C tokens, append-only **SHA-256 hash-chained audit logs**, and memory-hard **Argon2id** credential & PIN hashing. |
| **CO4 & CO5 / Unit V** (Network Security, Auth, Access Control, TLS) | Registration **ID + Secret PIN verification**, RBAC (`admin` / `voter`), CSRF tokens, IP rate limiting + **5-attempt account lockout**, and **HTTPS/TLS** with Wireshark HTTP vs. TLS comparison. |

---

## 3. 8-Week Progress Alignment

| Week | Activity | Evidence in Repository |
| :--- | :--- | :--- |
| **1** | Team formation & problem selection | Problem #28 selected (`README.md`, `docs/01_PROJECT_PROPOSAL_AND_SCOPE.md`, `docs/06_TEAM_CONTRIBUTION_AND_REFLECTION.md`). |
| **2** | Threat analysis & security requirements | `SECURITY_NOTES.md`, `docs/02_THREAT_MODEL_AND_REQUIREMENTS.md`. |
| **3** | Architecture, DB, API & crypto design | `app/models.py`, `docs/03_ARCHITECTURE_DFD_DB_API.md`. |
| **4** | Authentication, authorization & basic voting | `app/auth/`, `app/voter/`, `app/admin/`, PIN-verified registration, RBAC. |
| **5** | Hybrid encryption, key management, hashing & signatures | `app/security/ballots.py`, `signatures.py`, `passwords.py`, `audit.py`, `scripts/init_keys.py`. |
| **6** | TLS, audit logging & Variant A/B/C integration | `run.py` (`--https`/`--http`), `app/services/voting.py`, `app/templates/admin/variant_comparison.html`. |
| **7** | Security testing & remediation | `/admin/security-demo` (5 experiments), `tests/` (37 passing pytest cases), `docs/04_SECURITY_TESTING_AND_WIRESHARK_GUIDE.md`. |
| **8** | Final presentation, live demo & individual viva | `docs/07_VIVA_AND_PRESENTATION_GUIDE.md`. |
