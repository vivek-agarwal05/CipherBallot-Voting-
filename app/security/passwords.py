"""
app/security/passwords.py — Argon2id password hashing, complexity checks, and reset tokens.

Argon2id is the Password Hashing Competition winner and the recommended
algorithm for new systems (OWASP 2024).

Parameters chosen per OWASP recommendations for interactive logins:
  time_cost    = 2 iterations
  memory_cost  = 65536 KiB (64 MiB)
  parallelism  = 2 threads
"""
import hashlib
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

_ph = PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=2,
)

_RESET_SALT = 'cipherballot-password-reset'
_SPECIAL_CHARS = r"!@#$%^&*()-_=+[]{}|;:,.<>?/~`"


def hash_password(password: str) -> str:
    """Hash *password* with Argon2id and return the encoded hash string."""
    return _ph.hash(password)


def verify_password(encoded_hash: str, candidate_password: str) -> bool:
    """
    Verify *candidate_password* against *encoded_hash*.

    Returns True if the password matches, False for any mismatch or error.
    """
    try:
        return _ph.verify(encoded_hash, candidate_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(encoded_hash: str) -> bool:
    """Return True if *encoded_hash* was created with outdated parameters."""
    return _ph.check_needs_rehash(encoded_hash)


def validate_password_strength(password: str) -> tuple[bool, str | None]:
    """Enforce password complexity criteria (length >= 8, upper, lower, digit, symbol)."""
    if not password or len(password) < 8:
        return False, 'Password must be at least 8 characters long.'
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in _SPECIAL_CHARS for c in password)
    if not (has_upper and has_lower and has_digit and has_special):
        return (
            False,
            'Password criteria not met: Must contain at least one uppercase letter, '
            'one lowercase letter, one numeric digit, and one special character (!@#$%^&*...).',
        )
    return True, None


def _hash_fingerprint(password_hash: str) -> str:
    return hashlib.sha256(password_hash.encode('utf-8')).hexdigest()[:16]


def generate_password_reset_token(secret_key: str, user_id: int, password_hash: str) -> str:
    """
    Create a signed, time-limited, single-use password reset token.

    Binding the token to a fingerprint of the current password hash ensures
    the token is automatically invalidated as soon as the password is changed.
    """
    serializer = URLSafeTimedSerializer(secret_key, salt=_RESET_SALT)
    return serializer.dumps({'uid': user_id, 'pwh': _hash_fingerprint(password_hash)})


def verify_password_reset_token(
    secret_key: str,
    token: str,
    max_age_seconds: int = 900,
) -> tuple[dict | None, str | None]:
    """
    Verify signature & expiration of a reset token.

    Returns:
        ({'uid': int, 'pwh': str}, None) on valid token, or (None, error_message).
    """
    serializer = URLSafeTimedSerializer(secret_key, salt=_RESET_SALT)
    try:
        data = serializer.loads(token, max_age=max_age_seconds)
        if not isinstance(data, dict) or 'uid' not in data or 'pwh' not in data:
            return None, 'Invalid password reset token.'
        return data, None
    except SignatureExpired:
        return None, 'This password reset link has expired. Please request a new one.'
    except BadSignature:
        return None, 'Invalid or tampered password reset link.'


def reset_token_matches_user(token_data: dict, password_hash: str) -> bool:
    """Return True if the reset token has not already been invalidated by a password change."""
    return token_data.get('pwh') == _hash_fingerprint(password_hash)
