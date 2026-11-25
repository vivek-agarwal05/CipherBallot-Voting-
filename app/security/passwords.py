"""
app/security/passwords.py — Argon2id password hashing.

Argon2id is the Password Hashing Competition winner and the recommended
algorithm for new systems (OWASP 2024).

Parameters chosen per OWASP recommendations for interactive logins:
  time_cost    = 2 iterations
  memory_cost  = 65536 KiB (64 MiB)
  parallelism  = 2 threads

The encoded hash string is self-describing (includes algorithm, params, salt)
so it can be stored as a single opaque column value and re-verified without
storing parameters separately.
"""
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

_ph = PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=2,
)


def hash_password(password: str) -> str:
    """
    Hash *password* with Argon2id and return the encoded hash string.

    The returned string includes the algorithm identifier, parameters, salt,
    and hash — it is safe to store directly in the ``password_hash`` column.
    """
    return _ph.hash(password)


def verify_password(encoded_hash: str, candidate_password: str) -> bool:
    """
    Verify *candidate_password* against *encoded_hash*.

    Returns True if the password matches, False for any mismatch or error.
    All exceptions are caught to present a uniform False result, preventing
    timing-based oracle attacks from exception type leakage.
    """
    try:
        return _ph.verify(encoded_hash, candidate_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(encoded_hash: str) -> bool:
    """
    Return True if *encoded_hash* was created with outdated parameters.

    Call this after a successful verify_password() and re-hash if True, to
    transparently upgrade users to current security parameters on next login.
    """
    return _ph.check_needs_rehash(encoded_hash)
