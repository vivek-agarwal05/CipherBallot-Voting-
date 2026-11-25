# app/security/__init__.py
"""
CipherBallot security package.

Provides:
  passwords  — Argon2id password hashing/verification
  ballots    — AES-256-GCM ballot encryption/decryption
  signatures — Ed25519 document signing/verification
  audit      — Hash-chained audit log
  canonical  — Canonical JSON serialisation for deterministic hashing
"""
