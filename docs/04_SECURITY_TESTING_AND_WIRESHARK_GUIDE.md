# 04. Security Testing Report & Wireshark Lab Guide

## 1. Automated Unit & Integration Test Results
All **36 automated tests** in `tests/` pass (`pytest tests/ -v`):
- `test_auth.py` (7 tests): Argon2id hashing/verification, invalid login error masking, RBAC `403` enforcement, **5-strike temporary account lockout**.
- `test_registration.py` (6 tests): Institutional ID verification, **Secret PIN ownership proof rejection**, unlisted ID rejection, claimed ID anti-Sybil block, department mismatch rejection, password complexity check.
- `test_ballot_encryption.py` (3 tests): **Hybrid RSA-2048 OAEP + AES-256-GCM** encryption/decryption, ephemeral AES key & nonce uniqueness, schema isolation checks.
- `test_ballot_tampering.py` (4 tests): Bit-flipped ciphertext (`InvalidTag`), bit-flipped GCM tag (`InvalidTag`), AAD slot-transplantation rejection, **RSA-OAEP wrapped key bit-flip rejection**.
- `test_duplicate_vote.py` (1 test): Atomic DB uniqueness rollback on duplicate voting.
- `test_variants.py` (3 tests): **Variant A** single-class open voting, **Variant C** two-phase anonymous token protocol & double-spend rejection, and **all 5 live Security Demo experiments**.
- `test_eligibility.py`, `test_receipts.py`, `test_signatures.py`, `test_audit_chain.py`, `test_election_lifecycle.py` (12 tests): Eligibility rosters, SHA-256 receipt tamper detection, Ed25519 signatures, hash-chain integrity, and election state machine.

---

## 2. Five Controlled Security Experiments (`/admin/security-demo`)

| Exp # | Syllabus Link | Attack Simulated | Observed Cryptographic / Security Outcome |
| :--- | :--- | :--- | :--- |
| **1** | Mandatory + Unit V | **Duplicate Vote Submission** | Voter `eve` casts 1 ballot successfully; immediate 2nd attempt rolls back via `UNIQUE(election_id, voter_id)` constraint (`IntegrityError`) and logs `vote.rejected_duplicate`. |
| **2** | Mandatory + Unit II & III | **Hybrid Ballot Tampering** | Flips 1 bit in AES-256-GCM ciphertext (`XOR 0x01`), GCM tag (`XOR 0x80`), and RSA-OAEP wrapped AES key (`XOR 0x01`). All 3 fail verification cleanly (`InvalidTag` / `ValueError`), while the untouched hybrid ballot decrypts. |
| **3** | Unit III (Digital Signatures) | **Manifest Tampering & Wrong Public Key** | Signs canonical tally with Ed25519; rejects when votes are altered (`42 -> 43`) and fails verification when tested against an untrusted Ed25519 public key. |
| **4** | Unit IV (Hash Functions) | **SHA-256 Audit Chain Tampering** | Alters Event #2 in an isolated 3-event SHA-256 chain; proves recomputed hash mismatches Event #3's `prev_hash`, then verifies the live DB audit log is untampered. |
| **5** | Unit V (Auth & Access Control) | **Brute-Force Lockout & Unauthorized Access** | Confirms 5 failed logins trigger a 5-minute account lock and proves unrostered voter access is denied cleanly. |

---

## 3. Wireshark Network Analysis: HTTP vs. HTTPS/TLS (Unit V)

This guide satisfies the syllabus requirement: *"Analyse selected traffic using Wireshark and explain the difference between unprotected and TLS-protected communication."*

### Part A: Capturing Unprotected Plaintext Traffic (`--http`)
1. Open **Wireshark** and select your loopback interface:
   - **macOS:** `Loopback: lo0`
   - **Windows:** `Adapter for loopback traffic capture` (`Npcap Loopback Adapter`)
2. Set the display filter to:
   ```text
   tcp.port == 5000 && http
   ```
3. Start CipherBallot in plain HTTP mode:
   ```bash
   python run.py --http
   ```
4. Open `http://127.0.0.1:5000/auth/login` in your browser and sign in as `alice` / `Voter@Alice1`, then cast a vote.
5. **What to capture & screenshot for your report:**
   - Select the `POST /auth/login HTTP/1.1` packet in Wireshark.
   - Right-click $\rightarrow$ **Follow** $\rightarrow$ **HTTP Stream**.
   - **Observation:** The form body (`username=alice&password=Voter%40Alice1&csrf_token=...`), the returned `Set-Cookie: session=...` header, and the `POST /voter/elections/.../vote` `candidate_id` selection are **completely readable in plaintext** by any network sniffer!

### Part B: Capturing TLS-Protected Traffic (`--https`)
1. Stop the server (`Ctrl+C`) and restart in secure HTTPS/TLS mode (default):
   ```bash
   python run.py
   ```
   *(Server starts at `https://127.0.0.1:5000` using the self-signed X.509 certificate in `instance/certs/cert.pem`.)*
2. Clear the Wireshark capture and set the display filter to:
   ```text
   tcp.port == 5000
   ```
3. Visit `https://127.0.0.1:5000/auth/login` (accept the local self-signed browser warning once), log in, and cast a vote.
4. **What to capture & screenshot for your report:**
   - Look for the **TLSv1.2 / TLSv1.3 Handshake**: `Client Hello`, `Server Hello`, `Certificate` (showing CN=`localhost`, Issuer=`CipherBallot Course Prototype`), and `Change Cipher Spec`.
   - Select an `Application Data` packet and click **Follow** $\rightarrow$ **TLS Stream** (or **TCP Stream**).
   - **Observation:** All HTTP headers, passwords, session cookies, and ballot selections are **cryptographically opaque encrypted bytes**—an eavesdropper sees zero credentials or candidate choices.

### Part C: Summary Comparison Table

| Dimension | Unprotected HTTP (`--http`) | TLS-Protected HTTPS (`--https`) |
| :--- | :--- | :--- |
| **Wireshark Protocol** | `HTTP` / `URLENCODED-FORM` | `TLSv1.2` / `TLSv1.3` (`Application Data`) |
| **Credentials in Transit** | Visible in plaintext (`alice`, `Voter@Alice1`) | Encrypted inside TLS stream |
| **Session Hijacking Risk** | High (`Set-Cookie` exposed in plaintext) | Mitigated (encrypted + `Secure` cookie flag) |
| **Server Authentication** | None | X.509 Certificate (`instance/certs/cert.pem`) |
| **Transport Integrity** | None (vulnerable to MITM alteration) | Authenticated TLS AEAD cipher suite |
