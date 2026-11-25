# 05. Technical Report: Cryptographic Workflow & Limitations

## 1. End-to-End Cryptographic Workflow

CipherBallot combines five distinct cryptographic mechanisms aligned with CSEG3040:

1. **Identity & Credential Protection (Argon2id + Registration PIN):**
   - Both account passwords and one-time registration Verification PINs are hashed with **Argon2id** (`m=64 MB`, `t=2`, `p=2`).
   - Why Argon2id? Memory-hard design defeats GPU/ASIC brute-force cracking (unlike fast SHA-256 or non-memory-hard schemes) while maintaining side-channel resistance.

2. **Hybrid Ballot Encryption (RSA-2048 OAEP + Ephemeral AES-256-GCM):**
   - For every cast ballot, the server generates a **unique 256-bit ephemeral AES key** $K_{\text{ballot}}$ and a **unique 96-bit random nonce** $N$ via `os.urandom`.
   - Canonical JSON payload $P$ is sealed with $\text{AES-256-GCM}(K_{\text{ballot}}, N, P, \text{AAD})$ where $\text{AAD} = \text{canonical}(\{\text{ballot\_id}, \text{election\_id}\})$, producing ciphertext $C$ and a 128-bit GHASH authentication tag $T$.
   - $K_{\text{ballot}}$ is encrypted under the Election RSA-2048 public key via **RSA-OAEP (SHA-256 + MGF1-SHA-256)** to produce `wrapped_key_hex`.
   - During tallying, the private key (`rsa_private.pem`) unwraps $K_{\text{ballot}}$ and verifies $T$ and $\text{AAD}$ before releasing any plaintext.

3. **Individual Verifiability (SHA-256 Receipts & Bulletin Board):**
   - For Variants B and C, a random 256-bit `receipt_code` (`secrets.token_urlsafe(32)`) and digest
     $$D = \text{SHA-256}(\text{canonical}([\text{election\_id}, \text{ballot\_id}, N, C, T, \text{wrapped\_key}]))$$
     are published to the Public Bulletin Board so voters can verify ciphertext persistence without revealing their vote.

4. **Result Non-Repudiation (Ed25519 Digital Signatures):**
   - Upon closing an election, the canonical JSON tally summary is signed with an **Ed25519** private key (`signing_private.pem`). Anyone can verify the 64-byte signature using `signing_public.pem`.

5. **Tamper-Evident Audit Logging (SHA-256 Hash Chain) & TLS Transport:**
   - Every sensitive action appends $H_i = \text{SHA-256}(H_{i-1} \parallel \text{canonical}(\text{payload}_i))$.
   - Local HTTPS/TLS (`instance/certs/cert.pem`) secures traffic in transit.

---

## 2. Architectural & Security Limitations

An honest engineering evaluation identifies the following current limitations and production remediations:

1. **Single-Authority Private Key Custody:**
   - `instance/keys/rsa_private.pem` resides on the application server. A malicious server administrator could unwrap and decrypt ballots prematurely.
   - *Production Remediation:* Split the decryption key across independent election trustees using **Threshold Cryptography** (Shamir's Secret Sharing / Threshold ElGamal) or **Additive Homomorphic Encryption** (Paillier / ElectionGuard).

2. **Timing Correlation in Variant B vs. Low-Traffic Variant C:**
   - In Variant B, `participations` and `encrypted_ballots` commit in the same transaction; matching timestamps could reveal choices in very small polls.
   - Variant C separates token issuance (Phase 1) from ballot submission (Phase 2), breaking direct database links, though network-level timing correlation remains if only one user votes during a brief window.
   - *Production Remediation:* Batched mix-nets (Chaumian mix-nets) and blinded RSA signatures issued before voting opens.

3. **Local Self-Signed X.509 Certificate & SQLite Storage:**
   - Local X.509 certs require one-time browser trust warnings; SQLite uses single-file locking and in-memory rate limiting (`memory://`).
   - *Production Remediation:* CA-signed certificates (Let's Encrypt / internal PKI), PostgreSQL with connection pooling, Redis for rate-limiting/sessions, and FIPS 140-3 Hardware Security Modules (HSMs).

4. **Receipt Coercion Resistance:**
   - While receipts hide candidate names, a coercer watching a voter live or demanding a pre-determined receipt check creates coercion exposure.
   - *Production Remediation:* Coercion-resistant protocols (JCJ / Civitas) supporting decoy credentials or vote overwriting.

5. **Internal Audit Log Anchoring:**
   - An attacker with full SQLite write access could rewrite the entire `audit_events` chain from row 1 onward.
   - *Production Remediation:* Periodically anchor the latest $H_n$ root hash to an external immutable witness or public transparency log.
