# 07. Live Presentation Runbook & Individual Viva Guide

## 1. Live Classroom Demonstration Sequence (5–7 Minutes)

1. **Launch over HTTPS/TLS (`python run.py`):**
   - Show startup banner (`https://127.0.0.1:5000`) powered by the self-signed X.509 cert (`instance/certs/cert.pem`).
2. **Demonstrate Registration Criteria & Secret PIN Verification (`/auth/register`):**
   - Try registering `STU-CS-2024-010` (`Frank Miller`) with a **wrong PIN** $\rightarrow$ show immediate rejection & audit log event.
   - Register cleanly with the valid secret PIN (`PIN-010`) $\rightarrow$ show Argon2id hashing & automatic CS Department election enrollment.
3. **Demonstrate All 3 Variants (A, B, and C):**
   - Sign in as `alice` (`Voter@Alice1`):
     - **Variant A** (*CS-501 Single-Class Lab Poll*): Vote directly (no manual roster needed, hybrid encrypted, no public receipt).
     - **Variant B** (*CS Department Student Council*): Vote -> receive 256-bit Receipt Code + SHA-256 Digest -> verify on `/verify-receipt` & `/bulletin-board`.
     - **Variant C** (*Privacy-First Anonymous Senate Poll*): Phase 1 claims a one-time token (`token_issued` logged); copy token -> open `/anonymous-cast/<id>` (even unauthenticated!) -> Phase 2 redeems token anonymously (`ballot.cast_anonymous` logged with zero `voter_id`) -> try reusing token $\rightarrow$ rejected!
4. **Demonstrate All 5 Controlled Security Experiments (`/admin/security-demo`):**
   - Sign in as `admin` (`Admin@Demo123`), click **Run All 5 Experiments Now**, and walk through the live PASS report (Duplicate Vote, Hybrid RSA-OAEP+AES-GCM Bit-Flip, Ed25519 Wrong Public Key, SHA-256 Audit Chain Tamper, Lockout & Access Control).
5. **Show Automated Pytest & Interactive Crypto Lab:**
   - Open `/admin/crypto-lab` for live visual demos + run `pytest tests/ -v` in terminal (**37/37 passed**).
6. **Show Wireshark HTTP vs. HTTPS Comparison** (using screenshots/captures from `docs/04_SECURITY_TESTING_AND_WIRESHARK_GUIDE.md`).

---

## 2. Top 20 Individual Viva Questions & Crisp Answers

### Unit I & II — Symmetric Cryptography
1. **Why do you use Hybrid Encryption instead of encrypting the entire ballot directly with RSA?**  
   *Answer:* RSA is computationally slow and has strict plaintext size limits ($< \text{key size} - \text{padding}$). Hybrid encryption uses fast symmetric **AES-256-GCM** for the ballot payload and **RSA-2048 OAEP** solely to wrap the 32-byte AES key.
2. **Why AES-256-GCM instead of AES-ECB or AES-CBC?**  
   *Answer:* ECB leaks identical plaintext patterns; CBC provides confidentiality only (vulnerable to padding oracle / bit-flipping without a separate HMAC). **GCM** is an **AEAD** mode providing both confidentiality (CTR-mode stream) and integrity/authenticity via its 128-bit GHASH authentication tag.
3. **What happens if a `(Key, Nonce)` pair is reused in AES-GCM?**  
   *Answer:* Reusing a nonce with the same AES-GCM key breaks confidentiality (XOR of two ciphertexts reveals XOR of plaintexts) and leaks the GHASH authentication key. CipherBallot generates both a **fresh ephemeral 256-bit AES key** AND a **fresh 96-bit random nonce** (`os.urandom(12)`) per ballot.
4. **What is AAD (Additional Authenticated Data) in your ballots?**  
   *Answer:* AAD binds canonical JSON `{ballot_id, election_id}` into the GCM tag without encrypting it. Even if an attacker copies a valid ciphertext row into another election, tag verification raises `InvalidTag` (preventing transplantation attacks).

### Unit III — Public-Key Cryptography, RSA, Ed25519 & Certificates
5. **What is RSA-OAEP and why not raw/textbook RSA or PKCS#1 v1.5?**  
   *Answer:* Textbook RSA is deterministic and malleable; PKCS#1 v1.5 is vulnerable to Bleichenbacher's padding oracle attack. **OAEP (Optimal Asymmetric Encryption Padding)** uses SHA-256 and MGF1 to add probabilistic randomness and IND-CCA2 security.
6. **Why use Ed25519 for result signatures instead of RSA signatures?**  
   *Answer:* Ed25519 (Curve25519 Edwards curve) produces compact 64-byte deterministic signatures (no random $k$-reuse vulnerability like ECDSA), verifies rapidly, and avoids timing side-channels.
7. **What is the role of your X.509 certificate in `instance/certs/cert.pem`?**  
   *Answer:* It binds the server's identity (`localhost` / `127.0.0.1`) and public key for the TLS handshake so browsers encrypt all HTTP traffic over HTTPS.

### Unit IV — Hash Functions, Password Storage & Audit Chains
8. **Why do you hash passwords and registration PINs with Argon2id instead of SHA-256?**  
   *Answer:* SHA-256 is designed to be ultra-fast (billions of hashes/sec on GPUs). **Argon2id** is memory-hard ($64\text{ MB}$ RAM per hash) and time-parameterized, making GPU/ASIC dictionary attacks prohibitively expensive while defending against cache side-channels.
9. **How is hashing different from encryption in CipherBallot?**  
   *Answer:* Encryption (AES-GCM, RSA-OAEP) is **reversible** with the private/secret key (used for ballots so they can be tallied). Hashing (SHA-256, Argon2id) is **one-way** (used for passwords, registration PINs, receipt digests, Variant C tokens, and audit chain links).
10. **How does your audit hash chain detect tampering?**  
    *Answer:* Each row stores $H_i = \text{SHA-256}(H_{i-1} \parallel \text{canonical}(\text{payload}_i))$. Altering row $k$ changes $H_k$, which no longer matches `prev_hash` in row $k+1$. `verify_audit_chain()` pinpoints the exact altered ID.
11. **Why use `canonical_json` before hashing or signing?**  
    *Answer:* Dictionary key order or whitespace differences in JSON would change byte representations and break deterministic hashes or signatures. Canonical JSON sorts keys and strips whitespace.

### Unit V — Network Security, Access Control & Voting Trade-offs
12. **How do you prevent Sybil attacks & identity hijacking during registration?**  
    *Answer:* Users must match a pre-approved `InstitutionalIdentity` record, provide its confidential Argon2id-hashed **Verification PIN**, match department/name criteria, and each Student ID can only be claimed once.
13. **How do you prevent brute-force login attacks?**  
    *Answer:* Two layers: IP-level rate limiting via `Flask-Limiter` (`15/min`) plus **per-account temporary lockout** (5 minutes after 5 consecutive wrong passwords) + constant-time dummy Argon2id verification against user enumeration.
14. **How do you prevent duplicate voting in Variant B vs. Variant C?**  
    *Answer:* Variant B uses an atomic DB transaction with `UNIQUE(election_id, voter_id)` on `participations`. Variant C separates issuance (`UNIQUE(election_id, voter_id)` gives 1 token) from anonymous casting (atomic conditional update `WHERE is_spent = False`).
15. **What is the privacy difference between Variant A, Variant B, and Variant C?**  
    *Answer:* Variant A is a single-class baseline without receipts; Variant B isolates `participations` from `encrypted_ballots` and adds verifiable receipts (residual timestamp correlation possible); Variant C decouples identity issuance from anonymous token redemption so ballot submission carries zero `voter_id`.
16. **How does Wireshark prove your TLS control works?**  
    *Answer:* Under `--http`, Wireshark's *Follow HTTP Stream* exposes plaintext passwords, CSRF tokens, cookies, and votes. Under default TLS (`python run.py`), Wireshark shows the X.509 handshake and opaque `Application Data` bytes.
17. **What prevents an adversary from altering an election result after publication?**  
    *Answer:* `/results/<id>` recomputes the Ed25519 signature verification over canonical JSON live; any database edit invalidates the signature immediately.
18. **Why store private keys in `instance/keys/` and `.env` instead of code?**  
    *Answer:* Hardcoding secrets in source code leaks them into GitHub history. Keeping them in `.gitignore`-protected files isolates secrets from code.
19. **What is CSRF protection and how is it enforced?**  
    *Answer:* `Flask-WTF` embeds a cryptographic `csrf_token` in every state-changing form (`POST`), preventing forged cross-origin requests from a victim's browser.
20. **What are the biggest real-world limitations of CipherBallot?**  
    *Answer:* Single-server RSA private key custody (needs threshold decryption across multiple trustees), self-signed local cert (needs CA-signed PKI in production), lack of zero-knowledge tally proofs, and receipt coercion exposure.
