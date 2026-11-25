# CipherBallot — Secure Online Voting Prototype
> **Course:** CSEG3040 — Cryptography and Network Security (Semester V PBL)  
> **Active Implementation Profile:** **Multi-Variant (`A/B/C`)** — Hybrid RSA-2048 OAEP + AES-256-GCM Ballots, Verification-PIN Registration, Account Lockout, Ed25519 Signatures, and Local X.509 HTTPS/TLS

---

## 1. Project Overview & Learning Objectives

**CipherBallot** is an educational web application built for **Problem Statement #28** to demonstrate how real cryptographic primitives and architectural isolation protect online elections across **all three assigned variants (A, B, and C)** in a single platform.

### Core Learning Objectives (Aligned to CSEG3040 Units I–V):
1. **Confidentiality & Hybrid Key Protection (Unit II & III):** Each ballot generates a fresh 256-bit ephemeral **AES-256-GCM** key and 96-bit random nonce, then wraps the AES key using the election **RSA-2048 OAEP (SHA-256)** public key.
2. **Authentication, PIN Verification & Lockout (Unit IV & V):** Student registration verifies `InstitutionalIdentity` criteria + an Argon2id-hashed **Secret Verification PIN**, paired with IP rate limiting and **5-attempt temporary account lockout**.
3. **Multi-Variant Privacy Trade-offs (Variants A, B, C):** Compares single-class encrypted ballots (**A**), eligibility-rostered verifiable receipts (**B**), and two-phase unlinked anonymous voting tokens (**C**).
4. **Verifiable Receipts & Non-Repudiation (Unit III & IV):** 256-bit receipt codes + **SHA-256** ballot digests on the Public Bulletin Board, plus **Ed25519** signed canonical tallies.
5. **Tamper-Evident Audit Trails & TLS Transport (Unit IV & V):** Hash-chained audit logs (`SHA-256(prev_hash || payload)`) and **HTTPS/TLS** via a local self-signed X.509 certificate (`--https` / `--http` toggle for Wireshark).

---

## 2. All 3 Variants Supported Live (`A`, `B`, and `C`)

In [app/config.py](file:///Users/vivekagarwal/Downloads/CipherBallot/app/config.py), `PROJECT_VARIANT = "A/B/C"` activates multi-variant support per election:
- **Variant A:** Single-class election with hybrid-encrypted ballots (open to all active voters without manual rosters or public receipts).
- **Variant B:** Department poll with explicit voter eligibility rosters, hybrid-encrypted ballots, verifiable SHA-256 receipts, and Ed25519 signed results.
- **Variant C:** Privacy-focused two-phase anonymous token model (Phase 1 verifies identity & issues an unlinked token; Phase 2 redeems the token anonymously with zero `voter_id` attached).

View the live side-by-side analysis at `/variants` (`app/templates/admin/variant_comparison.html`).

---

## 3. Technology Stack

- **Backend:** Python 3.10+ with Flask 3.0.3 application factory.
- **Database & ORM:** SQLite for local classroom simplicity with SQLAlchemy 2.0 / Flask-SQLAlchemy 3.1.
- **Cryptography Engine:** `cryptography` library (AES-256-GCM, Ed25519, HKDF) and `argon2-cffi` (Argon2id password hashing).
- **Web Security:** Flask-WTF CSRF tokens on all POST requests, Flask-Limiter brute-force mitigation, HTTPOnly / SameSite session cookies.
- **Frontend & Visualization:** Bootstrap 5.3 + custom design system (cool-grey/indigo palette with dark mode toggle), Bootstrap Icons, and Chart.js 4.4.
- **Testing:** `pytest` test suite with 25 automated tests covering authentication, tampering, signatures, and concurrency.

---

## 4. Project Directory Structure

```text
CipherBallot/
├── app/
│   ├── __init__.py           # Flask application factory with error handlers
│   ├── config.py             # Config classes & PROJECT_VARIANT setting
│   ├── extensions.py         # SQLAlchemy, CSRFProtect, Limiter, LoginManager
│   ├── models.py             # Relational data schema (isolated tables)
│   ├── auth/                 # Authentication blueprint, PIN registration & lockout
│   │   ├── forms.py
│   │   └── routes.py
│   ├── voter/                # Voter dashboard, Variant A/B/C voting, receipt views
│   │   └── routes.py
│   ├── admin/                # Admin dashboard, tallying, audit, 5 security demos
│   │   └── routes.py
│   ├── public/               # Landing, bulletin board, receipt verifier, variants
│   │   └── routes.py
│   ├── api/                  # REST endpoints for elections & signed results
│   │   └── routes.py
│   ├── security/             # Dedicated cryptographic helper library
│   │   ├── passwords.py      # Argon2id hashing & verification
│   │   ├── ballots.py        # Hybrid RSA-OAEP + AES-256-GCM & SHA-256 digest
│   │   ├── signatures.py     # Ed25519 result signing & verification
│   │   ├── audit.py          # Append-only hash-chained audit log
│   │   └── canonical.py      # RFC-compliant canonical JSON encoder
│   ├── services/             # Core business logic
│   │   ├── voting.py         # Multi-variant voting (A, B, C) & eligibility checks
│   │   ├── elections.py      # Voter election list & summaries
│   │   ├── tally.py          # Decryption verification & result publishing
│   │   └── receipts.py       # Cryptographic receipt verification
│   ├── templates/            # Jinja2 responsive templates
│   │   ├── base.html         # Responsive layout with sidebar & dark mode
│   │   ├── auth/             # Login & PIN-verified registration templates
│   │   ├── public/           # Landing, Bulletin Board, Verifier, Privacy Guide, Results
│   │   ├── voter/            # Voter dashboard, Variant A/B/C cast ballot, receipts
│   │   ├── admin/            # Dashboard, elections, eligibility, tally, security demo
│   │   └── errors/           # 403, 404, 500 error pages
│   └── static/
│       ├── css/              # Theme CSS tokens & neumorphic sidebar
│       └── js/               # Theme toggle and UI utilities
├── scripts/
│   ├── init_keys.py          # RSA-2048, Ed25519, X.509 TLS cert & .env generator
│   ├── seed_demo.py          # Demo users, PIN registry, and Variant A/B/C elections
│   └── reset_demo_data.py    # Database reset utility with confirmation
├── tests/                    # 36 automated unit and integration tests
│   ├── conftest.py
│   ├── test_auth.py
│   ├── test_registration.py
│   ├── test_eligibility.py
│   ├── test_duplicate_vote.py
│   ├── test_ballot_encryption.py
│   ├── test_ballot_tampering.py
│   ├── test_receipts.py
│   ├── test_signatures.py
│   ├── test_audit_chain.py
│   ├── test_variants.py
│   └── test_election_lifecycle.py
├── instance/
│   ├── keys/                 # Ignored by Git (RSA-2048 & Ed25519 PEM keys)
│   ├── certs/                # Ignored by Git (Self-signed X.509 TLS cert/key)
│   └── cipherballet.db       # Local SQLite database (ignored by Git)
├── .env                      # Local secret variables (ignored by Git)
├── .env.example              # Template environment file
├── requirements.txt          # Pinned Python package dependencies
├── SECURITY_NOTES.md         # Threat model, assumptions, and mitigations
└── run.py                    # Application launch entrypoint
```

---

## 5. Local Setup & Execution Guide

### Windows (PowerShell):
```powershell
# 1. Navigate to project root
cd d:\01\Crypto\CipherBallot

# 2. Create and activate a Python virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# 3. Install pinned dependencies
pip install -r requirements.txt

# 4. Generate cryptographic keys & environment file
python scripts\init_keys.py

# 5. Initialize database tables and seed classroom demo data
flask --app run.py init-db
python scripts\seed_demo.py

# 6. Launch the development server
python run.py
```

### macOS / Linux:
```bash
cd CipherBallot
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 scripts/init_keys.py
flask --app run.py init-db
python3 scripts/seed_demo.py
python3 run.py
```

Open your browser to: **`http://127.0.0.1:5000/`**

---

## 6. Seeded Demo Accounts (Local Demonstration Only)

| Role | Username | Password | Purpose |
|------|----------|----------|---------|
| **Admin** | `admin` | `Admin@Demo123` | Full access to election management, tallying, audit log, security demo |
| **Voter 1** | `alice` | `Voter@Alice1` | Eligible voter in CS Council 2024 (uncast ballot ready to test) |
| **Voter 2** | `bob` | `Voter@Bob123` | Eligible voter in CS Council 2024 |
| **Voter 3** | `carol` | `Voter@Carol1` | Eligible voter in CS Council 2024 |
| **Voter 4** | `dave` | `Voter@Dave123` | Eligible voter in CS Council 2024 |
| **Voter 5** | `eve` | `Voter@Eve1234` | Dedicated test account for live security demonstrations |

> ⚠️ **Classroom Demo Warning:** Passwords are stored in the database strictly as **Argon2id** hashes. In a real deployment, change default credentials and never commit local keys.

---

## 7. Complete User Journeys & Walkthroughs

### 7.1 Voter Journey:
1. Navigate to **`http://127.0.0.1:5000/auth/login`**.
2. Sign in as `alice` with password `Voter@Alice1`.
3. You are redirected to the **Voter Dashboard**. Notice summary cards showing eligible elections.
4. Click **Available Elections** or **Cast Ballot** on *"CS Department Student Council Election 2024"*.
5. **Step 1:** Select a candidate (e.g., *Priya Sharma*). Click **Proceed to Review**.
6. **Step 2:** Review your selection and warning notice. Click **Seal & Submit Encrypted Vote**.
7. The server encrypts your choice under AES-256-GCM, writes to the isolated `encrypted_ballots` table, and commits atomically with your participation record.
8. You are presented with your **Official Ballot Receipt** containing a 43-character receipt token and the ballot's SHA-256 digest.
9. Click **Verify on Public Bulletin Board** or copy the receipt code to **Verify Receipt** to confirm that the live recomputed digest matches the bulletin board record.

### 7.2 Administrator Journey:
1. Sign in as `admin` with password `Admin@Demo123`.
2. Open **Elections** in the sidebar.
3. You can create a new election draft, add candidates, and configure voter rosters.
4. Click **Manage Voter Eligibility** on an election to grant or revoke voter eligibility individually.
5. Change election status: **Draft → Open**. Voters can now cast ballots.
6. When voting concludes, click **Close Election**.
7. Click **Tally & Publish**:
   - The server decrypts all stored ballots using AES-256-GCM and verifies MAC tags.
   - Any tampered ballots are flagged.
   - Aggregate totals and turnout percentages are computed.
8. Click **Sign & Publish Official Results**. The results are canonically serialized and signed using the institutional **Ed25519 private key**.

---

## 8. Live Classroom Demonstrations (5 Controlled Experiments)

Navigate to **Security Demo** (`/admin/security-demo`) and click **Run All 5 Experiments Now**:
1. **Duplicate Vote Prevention (Mandatory + Unit V):** Rejects 2nd vote attempt via `UNIQUE(election_id, voter_id)` atomic rollback.
2. **Hybrid Ballot Tampering (Mandatory + Unit II & III):** Flips 1 bit in AES-GCM ciphertext, GCM tag, and RSA-OAEP wrapped key—proving all 3 are rejected.
3. **Ed25519 Signature Forgery & Wrong Public Key (Unit III):** Rejects altered tally counts and verification against an incorrect public key.
4. **SHA-256 Audit Chain Tampering (Unit IV):** Detects historical payload edits via broken `prev_hash` links.
5. **Account Lockout & Unauthorized Access (Unit V):** Verifies 5-attempt temporary lockout and ineligible voter rejection.

> See `docs/` (`01` through `07`) for the complete Threat Model, Architecture/DFD/DB/API specification, Wireshark HTTP vs. TLS Lab Guide, Technical Report, 5-Member Contribution Matrix, and Viva Defense Q&A.

---

## 9. Automated Test Suite

Run the full automated test suite containing **36 tests**:
```bash
python -m pytest tests/ -v
```

Running with TLS/HTTPS vs. plain HTTP (for Wireshark capture):
```bash
python run.py          # HTTPS/TLS using instance/certs/cert.pem (default)
python run.py --http   # Plain HTTP for Wireshark plaintext comparison
```

All 25 tests verify the core security guarantees:
- `test_auth.py`: Password hashing, constant-time dummy verification, rate limiting, role access guards.
- `test_eligibility.py`: Ineligible voters blocked, eligibility checks enforced.
- `test_duplicate_vote.py`: Atomic database constraint rejects second submissions.
- `test_ballot_encryption.py`: AES-GCM encryption, fresh nonces, zero voter_id in ballot table.
- `test_ballot_tampering.py`: Bit-flipped ciphertext, modified tag, and AAD transplantation raise `InvalidTag`.
- `test_receipts.py`: SHA-256 digest verified unchanged and detects database tampering.
- `test_signatures.py`: Ed25519 signature verified intact and rejected upon document alteration.
- `test_audit_chain.py`: Hash-chain verification confirms untampered log and pinpoints modified events.
- `test_election_lifecycle.py`: Tallying blocked while open, permitted when closed, result signed.

---

## 11. Security & Privacy Limitations (Disclaimer)

- **Educational Purpose:** This software is a pedagogical prototype for university cryptography coursework. It is **not** suitable for real-world governmental or binding elections.
- **Insider Threat:** The server administrator holds the AES-256 ballot key. A compromised administrator could decrypt ballots. Production systems require multi-party threshold cryptography or homomorphic encryption (e.g. Helios / ElectionGuard).
- **Correlation Risks:** While participation logs have no foreign key to ballots, timing attacks (correlating network logs or database timestamps) remain a residual threat in low-turnout elections.
- **Coercion Resistance:** Receipts enable individual verification but do not provide receipt-falsification properties required for formal coercion resistance.
