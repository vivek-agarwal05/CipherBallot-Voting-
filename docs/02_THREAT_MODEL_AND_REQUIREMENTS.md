# 02. Threat Model & Security Requirements

## 1. Protected Assets

| Asset | Security Property | Implemented Control |
| :--- | :--- | :--- |
| **Voter Passwords & Registration PINs** | Confidentiality (even if DB leaks) | Memory-hard **Argon2id** (`argon2-cffi`, $m=64\text{ MB}, t=2, p=2$). Never stored or logged in plaintext. |
| **Ballot Choices** | Confidentiality & Integrity | **Hybrid Encryption**: unique ephemeral 256-bit **AES-256-GCM** key per ballot, wrapped with **RSA-2048 OAEP (SHA-256)** public key; 128-bit GCM tag + AAD `(election_id, ballot_id)`. |
| **Voter Anonymity** | Unlinkability of voter to choice | `participations` has no `ballot_id` or `candidate_id`; `encrypted_ballots` has no `voter_id`; Variant C uses one-time `SHA-256(token)` in `anonymous_tokens`. |
| **One-Vote-Per-Voter Integrity** | Anti-ballot-stuffing | Atomic DB transaction with `UNIQUE(election_id, voter_id)` on `participations` and conditional single-spend update (`is_spent=False -> True`) in Variant C. |
| **Voter Registration Eligibility** | Anti-Sybil & Anti-Impersonation | Must match pre-approved `InstitutionalIdentity` (`student_id`, `department`, `full_name`) AND valid one-time secret `verification_pin` (Argon2id hashed); 1 account per Student ID. |
| **Published Election Tallies** | Origin Authenticity & Non-Repudiation | Canonical JSON signed with institutional **Ed25519** private key (`signing_private.pem`). |
| **Administrative Audit Trail** | Tamper-Evidence | Append-only SHA-256 hash chain: $H_i = \text{SHA-256}(H_{i-1} \parallel \text{canonical}(\text{payload}_i))$. |
| **Credentials & Ballots in Transit** | Network Confidentiality | **HTTPS / TLS** via local X.509 certificate (`instance/certs/cert.pem`), `HttpOnly`, `SameSite=Lax`, `Secure` session cookies, CSRF tokens. |

---

## 2. Adversary Profiles & Mitigations

### A. External Network Attacker (Eavesdropping / Brute-Force / CSRF)
- **Threat:** Sniffs Wi-Fi/LAN traffic for passwords/votes, runs dictionary attacks on `/auth/login`, or crafts cross-site POST requests.
- **Mitigations:**
  - TLS encryption (`python run.py` HTTPS mode) prevents plaintext credential or cookie capture.
  - IP rate limiting (`15/min`) via `Flask-Limiter` + **per-account temporary lockout** (5 minutes after 5 consecutive failed logins).
  - Constant-time dummy Argon2id check prevents username enumeration.
  - `Flask-WTF` CSRF tokens required on every state-changing POST request.

### B. Malicious Voter / Sybil Attacker
- **Threat:** Tries to create fake accounts, hijack a classmate's Student ID, vote twice, vote when ineligible, or replay a Variant C token.
- **Mitigations:**
  - Self-registration requires an unclaimed `InstitutionalIdentity` AND its secret **Verification PIN**.
  - Duplicate votes fail atomically via DB `IntegrityError` rollback (`UNIQUE(election_id, voter_id)`).
  - Variant C token redemption performs an atomic `UPDATE ... WHERE is_spent = False` check, blocking double-spends.

### C. Database Exfiltration / Tampering Attacker
- **Threat:** Obtains `instance/cipherballet.db` or flips bits in stored ciphertexts, receipts, tallies, or audit events.
- **Mitigations:**
  - Keys (`rsa_private.pem`, `signing_private.pem`) and TLS keys (`instance/certs/key.pem`) live outside the database (`0600` permissions, excluded by `.gitignore`).
  - Flipping 1 bit in ciphertext/tag triggers `InvalidTag`; flipping 1 bit in the wrapped AES key fails RSA-OAEP decryption.
  - Modifying stored ballot fields invalidates the receipt's `SHA-256` digest on the Public Bulletin Board.
  - Altering any audit event breaks `verify_audit_chain()` at the exact tampered row ID.

### D. Curious Server Administrator (Acknowledged Insider Boundary)
- **Threat:** Root access to the server filesystem gives access to `rsa_private.pem` and insertion timestamps.
- **Mitigation & Residual Risk:** Table isolation (`participations` vs. `encrypted_ballots`) and Variant C anonymous tokens raise the barrier against naive inspection. However, a single-authority server holding `rsa_private.pem` can decrypt ballots once collected—documented openly as an educational prototype limitation (production systems use threshold cryptography across multiple trustees).

---

## 3. Formal Security Requirements Checklist

- **SR-1 (Authentication):** Passwords and verification PINs stored exclusively via Argon2id; account locks after 5 consecutive failures.
- **SR-2 (Authorization / RBAC):** Strict separation of `admin` and `voter` blueprints (`_require_admin()`, `_require_voter()` returning HTTP `403`).
- **SR-3 (Hybrid Confidentiality):** Every ballot generates a fresh 256-bit AES-GCM key and 96-bit nonce, encapsulated under RSA-2048 OAEP.
- **SR-4 (Integrity & Non-Repudiation):** GCM tags authenticate ballots; SHA-256 verifies receipts and audit chains; Ed25519 signs published results.
- **SR-5 (Transport Security):** HTTPS/TLS active by default via local X.509 certificate; HTTP toggle available strictly for lab traffic comparison.
