# CipherBallot — Security & Threat Modeling Notes

> **Document Status:** Educational Security Reference  
> **Target Audience:** Cryptography Course Evaluators (CSEG3040), Security Engineers, Students  
> **Application:** CipherBallot — Multi-Variant Secure Online Voting Prototype (Variants A, B, and C)

---

## 1. Executive Summary & Scope

CipherBallot is an educational voting prototype designed to demonstrate foundational cryptographic mechanisms in web applications. It implements real, authenticated cryptography (**Hybrid RSA-2048 OAEP + AES-256-GCM**, **Argon2id**, **Ed25519**, **SHA-256**, and **local X.509 TLS**) alongside relational database isolation and two-phase anonymous tokens.

**Scope Boundary:** This system is built for classroom laboratory demonstrations and is **not certified for binding, political, union, or governmental elections**. It assumes an honest-but-curious host environment and exposes the security boundary trade-offs present in real-world electronic voting architectures.

---

## 2. Protected Assets

| Asset | Security Goal | Mechanism |
|-------|---------------|-----------|
| **Voter Credentials & Verification PINs** | Confidentiality against database leaks | Argon2id hashing ($m=64\text{MB}, t=2, p=2$). Never encrypted or logged. |
| **Ballot Content** | Confidentiality until tallying | **Hybrid Encryption:** fresh ephemeral 256-bit AES-256-GCM key per ballot, wrapped under RSA-2048 OAEP (SHA-256) public key. |
| **Ballot Authenticity** | Integrity & anti-tampering | 128-bit GHASH authentication tag; Additional Authenticated Data (AAD) binding; RSA-OAEP integrity. |
| **Voter Privacy** | Unlinkability of voter identity to choice | Strict separation of `participations` and `encrypted_ballots` (Variant B) + two-phase SHA-256 anonymous tokens in `anonymous_tokens` (Variant C). |
| **Vote Legitimacy** | Exactly one vote per eligible voter | DB `UNIQUE(election_id, voter_id)` on participation; atomic single-spend conditional update in Variant C; 1:1 PIN-verified registration. |
| **Receipt Integrity** | Individual verifiability | SHA-256 digest of $(election\_id \parallel ballot\_id \parallel nonce \parallel ciphertext \parallel tag \parallel wrapped\_key)$. |
| **Certified Results** | Origin authenticity & non-repudiation | Ed25519 digital signature over canonical RFC-compliant JSON result document. |
| **Administrative History** | Tamper-evident logging | Append-only hash chain: $H_i = \text{SHA-256}(H_{i-1} \parallel \text{canonical}(payload_i))$. |
| **Network Traffic** | Confidentiality & integrity in transit | HTTPS/TLS via local X.509 certificate (`instance/certs/cert.pem`) + `HttpOnly`/`Secure` cookies + CSRF tokens. |

---

## 3. Threat Model & Attacker Profiles

### 3.1 External Network Attacker (Adversary on Public Internet)
- **Capabilities:** Can send arbitrary HTTP requests, replay payloads, attempt credential stuffing, or submit forged votes.
- **Mitigations:**
  - Mandatory server-side session authentication on all protected endpoints.
  - Flask-WTF CSRF tokens on every state-changing POST request.
  - Rate limiting on authentication (`5/min`) via Flask-Limiter.
  - Constant-time dummy Argon2 verification to defeat user enumeration.
  - Cryptographically secure 256-bit token entropy (`secrets.token_urlsafe(32)`).

### 3.2 Malicious / Corrupted Voter
- **Capabilities:** Tries to vote multiple times, vote in elections they are not rostered for, submit tampered ciphertexts directly, or tamper with candidate options.
- **Mitigations:**
  - Eligibility roster cross-checked on every POST before ballot processing.
  - Atomic database constraint enforces strictly 1 vote per voter; rollbacks on race conditions.
  - Server generates fresh nonces and executes encryption server-side.
  - Candidate IDs validated against active candidates roster for that election.

### 3.3 Database Exfiltration / Offline Attacker
- **Capabilities:** Obtains a raw dump of `cipherballet.db`.
- **Mitigations:**
  - Passwords cannot be reversed (Argon2id resistant to GPU/ASIC cracking).
  - Ballots cannot be decrypted without `instance/keys/rsa_private.pem` (stored outside DB).
  - Encrypted ballot records contain no voter ID or student ID column.

### 3.4 Curious System Administrator (Insider Threat)
- **Capabilities:** Has server console or database root access.
- **Risks & Boundaries:**
  - *Acknowledged Limitation:* The administrator possesses the ballot encryption key and could decrypt ballots prior to tallying.
  - *Mitigation:* Participation records are stored separately from ballots without linking identifiers. However, metadata correlation (see Section 5) remains an insider risk in low-traffic polls.

---

## 4. Cryptographic Key Handling & Lifecycle

### 4.1 Key Storage:
- **RSA-2048 Keypair (`instance/keys/rsa_private.pem`, `rsa_public.pem`):** Used for hybrid RSA-OAEP (SHA-256) encapsulation of each ballot's unique ephemeral 256-bit AES-GCM key. Private key set to `0600` on POSIX systems and excluded by `.gitignore`.
- **Signing Keypair (`instance/keys/signing_private.pem`, `signing_public.pem`):** Ed25519 keypair serialized to PEM format. Private key is never exposed via web routes, templates, or APIs.
- **TLS Certificate (`instance/certs/cert.pem`, `key.pem`):** Self-signed local X.509 certificate for HTTPS transport encryption.
- **Flask Session Key (`SECRET_KEY` in `.env`):** 64-character hex string generated via `secrets.token_hex(32)`.

### 4.2 Nonce Management in AES-GCM:
- AES-GCM catastrophic failure occurs if a $(Key, Nonce)$ pair is ever reused.
- CipherBallot generates a fresh 12-byte (96-bit) cryptographically secure random nonce via `os.urandom(12)` on every ballot encryption call.
- The probability of collision under $2^{96}$ nonces is negligible ($< 10^{-14}$) for university-scale elections.
- AAD binds $(election\_id, ballot\_id)$ into the tag, preventing transplantation attacks.

---

## 5. Architectural Privacy & Residual Risks

While CipherBallot separates voter participation from encrypted ballots, realistic privacy analysis highlights several residual risks:

1. **Traffic & Timestamp Correlation:**
   - If voter Alice casts a ballot at 09:15:32 AM in an election with low activity, an observer with access to server network logs (or DB insert timestamps) can correlate her participation record with the ballot row created at the same millisecond.
   - *Production Solution:* Requires batched ingestion, randomized shuffling, or blind-token issuance (Variant C).

2. **Single-Authority Decryption:**
   - In Variant B, all ballots for an election are decrypted by the application server using the ballot key.
   - *Production Solution:* Threshold ElGamal or Paillier homomorphic encryption where $k$-of-$n$ trustees must supply partial decryption shares.

3. **Receipt-Based Coercion:**
   - While receipts only contain ciphertext digests and reveal no candidate name, if a coercer forces a voter to cast a ballot in front of them or pre-demands the receipt code, verification does not provide receipt-falsification (deniability).
   - *Production Solution:* JCJ / Civitas coercion-resistant protocols with fake credentials or revoting capabilities.

---

## 6. What a Production Election System Would Still Need

To transition from an educational prototype to a high-assurance production voting system, the following would be required:

1. **Hardware Security Modules (HSM):** Key generation and Ed25519 signing operations executed within FIPS 140-3 Level 3 hardware boundaries.
2. **End-to-End Verifiability (E2E-V):** Mathematical proofs (zero-knowledge proofs of plaintext validity) allowing individual and universal verification without trusting the central server.
3. **Threshold Mix-Nets or Homomorphic Tallying:** Shuffling and re-encryption across independent distributed trustees so that no single entity can decrypt individual ballots.
4. **External Transparency Witnesses:** Anchoring the audit hash chain to public cryptographic ledgers (e.g., Certificate Transparency RFC 6962 logs or public blockchains) to prevent retroactive history rewrites by a rogue administrator.
5. **Air-Gapped Registration & Voting:** Physical segregation between voter registration databases and ballot accumulation servers.
