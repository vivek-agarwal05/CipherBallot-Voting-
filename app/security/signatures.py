"""
app/security/signatures.py — Ed25519 document signing and verification.

Ed25519 provides:
  - 128-bit security level
  - Deterministic signatures (no random nonce, no k-reuse risk)
  - Fast verification
  - 64-byte signatures (compact)

Key storage:
  - Private key: PEM file at SIGNING_PRIVATE_KEY_PATH (keep secret; .gitignore'd)
  - Public key:  PEM file at SIGNING_PUBLIC_KEY_PATH  (safe to publish)

Usage pattern:
  sig_hex = sign_document(result_bytes)
  ok      = verify_document_signature(result_bytes, sig_hex)
"""
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

from flask import current_app


# ---------------------------------------------------------------------------
# Key loading
# ---------------------------------------------------------------------------

def _load_pem_bytes(pem_env_key: str, path_key: str, label: str) -> bytes:
    """Load PEM key bytes from config env string first, then fallback to file path."""
    pem_inline: str | None = current_app.config.get(pem_env_key)
    if pem_inline:
        return pem_inline.replace('\\n', '\n').encode('utf-8')
    path_str: str = current_app.config.get(path_key, '')
    path = Path(path_str)
    if not path.exists():
        raise RuntimeError(
            f"{label} not found at '{path}' (and {pem_env_key} is not set). "
            "Run: python scripts/init_keys.py --ensure-missing"
        )
    return path.read_bytes()


def _load_private_key() -> Ed25519PrivateKey:
    """
    Load the Ed25519 private key from env or PEM file at SIGNING_PRIVATE_KEY_PATH.
    """
    pem_bytes = _load_pem_bytes(
        'SIGNING_PRIVATE_KEY_PEM', 'SIGNING_PRIVATE_KEY_PATH', 'Ed25519 private key'
    )
    key = load_pem_private_key(pem_bytes, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise RuntimeError("Configured Ed25519 private key is invalid.")
    return key


def _load_public_key() -> Ed25519PublicKey:
    """
    Load the Ed25519 public key from env or PEM file at SIGNING_PUBLIC_KEY_PATH.
    """
    pem_bytes = _load_pem_bytes(
        'SIGNING_PUBLIC_KEY_PEM', 'SIGNING_PUBLIC_KEY_PATH', 'Ed25519 public key'
    )
    key = load_pem_public_key(pem_bytes)
    if not isinstance(key, Ed25519PublicKey):
        raise RuntimeError("Configured Ed25519 public key is invalid.")
    return key


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def sign_document(document_bytes: bytes) -> str:
    """
    Sign *document_bytes* with the Ed25519 private key.

    Args:
        document_bytes: Raw bytes of the document to sign (e.g. canonical JSON
                        of an election result).

    Returns:
        Lowercase hex-encoded 64-byte Ed25519 signature (128 hex chars).
    """
    private_key = _load_private_key()
    signature_bytes: bytes = private_key.sign(document_bytes)
    return signature_bytes.hex()


def verify_document_signature(document_bytes: bytes, signature_hex: str) -> bool:
    """
    Verify *signature_hex* over *document_bytes* using the Ed25519 public key.

    Args:
        document_bytes: The original bytes that were signed.
        signature_hex:  Hex-encoded 64-byte signature returned by sign_document.

    Returns:
        True if the signature is valid, False otherwise.

    This function never raises on a bad signature — callers receive a simple
    boolean so they can generate consistent error messages.
    """
    try:
        public_key = _load_public_key()
        signature_bytes = bytes.fromhex(signature_hex)
        public_key.verify(signature_bytes, document_bytes)
        return True
    except Exception:
        return False


def get_public_key_hex() -> str:
    """
    Return the raw 32-byte Ed25519 public key as a hex string.

    Useful as a ``public_key_id`` fingerprint stored alongside signed results.
    """
    public_key = _load_public_key()
    raw_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return raw_bytes.hex()
