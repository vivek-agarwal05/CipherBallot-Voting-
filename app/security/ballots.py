"""
app/security/ballots.py — Hybrid RSA-2048 OAEP + AES-256-GCM ballot encryption/decryption.

Design decisions:
  - Every ballot is encrypted using Hybrid Cryptography:
      1. Generate a fresh 256-bit (32-byte) ephemeral AES key per ballot.
      2. Encrypt canonical JSON ballot payload with AES-256-GCM + fresh 12-byte nonce + AAD.
      3. Wrap the ephemeral AES key with the Election RSA-2048 public key using RSA-OAEP (SHA-256).
      4. During tallying, unwrap the AES key with the RSA private key, then decrypt & verify GCM tag.
  - Additional Authenticated Data (AAD) binds each ciphertext to (election_id, ballot_id).
  - Receipt codes use secrets.token_urlsafe(32) → 256 bits of entropy.
"""
import hashlib
import json
import os
import secrets
from pathlib import Path

from cryptography.exceptions import InvalidTag  # re-exported for callers
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from flask import current_app

from .canonical import canonical_json


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


def _load_rsa_public_key() -> RSAPublicKey:
    """Load the RSA-2048 public key for hybrid AES key wrapping."""
    pem_bytes = _load_pem_bytes('RSA_PUBLIC_KEY_PEM', 'RSA_PUBLIC_KEY_PATH', 'RSA public key')
    key = load_pem_public_key(pem_bytes)
    if not isinstance(key, RSAPublicKey):
        raise RuntimeError("Configured RSA public key is not an RSAPublicKey.")
    return key


def _load_rsa_private_key() -> RSAPrivateKey:
    """Load the RSA-2048 private key for unwrapping per-ballot AES keys during tally."""
    pem_bytes = _load_pem_bytes('RSA_PRIVATE_KEY_PEM', 'RSA_PRIVATE_KEY_PATH', 'RSA private key')
    key = load_pem_private_key(pem_bytes, password=None)
    if not isinstance(key, RSAPrivateKey):
        raise RuntimeError("Configured RSA private key is not an RSAPrivateKey.")
    return key


def encrypt_ballot_hybrid(
    ballot_payload: dict,
    election_id: int,
    ballot_id: str,
) -> tuple[str, str, str, str, str]:
    """
    Encrypt *ballot_payload* with a unique ephemeral AES-256-GCM key,
    then protect that AES key with the election RSA-2048 OAEP public key.

    Returns:
        (nonce_hex, ciphertext_hex, tag_hex, aad_hex, wrapped_key_hex)
    """
    ephemeral_aes_key: bytes = os.urandom(32)
    nonce: bytes = os.urandom(12)
    plaintext: bytes = canonical_json(ballot_payload)
    aad: bytes = canonical_json({'ballot_id': ballot_id, 'election_id': election_id})

    aesgcm = AESGCM(ephemeral_aes_key)
    ct_with_tag: bytes = aesgcm.encrypt(nonce, plaintext, aad)
    tag: bytes = ct_with_tag[-16:]
    ciphertext: bytes = ct_with_tag[:-16]

    rsa_pub = _load_rsa_public_key()
    wrapped_key: bytes = rsa_pub.encrypt(
        ephemeral_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return (
        nonce.hex(),
        ciphertext.hex(),
        tag.hex(),
        aad.hex(),
        wrapped_key.hex(),
    )


def decrypt_ballot(
    nonce_hex: str,
    ciphertext_hex: str,
    tag_hex: str,
    aad_hex: str,
    election_id: int,  # noqa: ARG001
    ballot_id: str,    # noqa: ARG001
    wrapped_key_hex: str,
) -> dict:
    """
    Unwrap the per-ballot AES key using the RSA-2048 private key (RSA-OAEP SHA-256)
    and decrypt + authenticate the AES-256-GCM ballot ciphertext.
    """
    if not wrapped_key_hex:
        raise ValueError("Missing RSA-OAEP wrapped key for hybrid decryption.")

    rsa_priv = _load_rsa_private_key()
    wrapped_bytes = bytes.fromhex(wrapped_key_hex)
    key = rsa_priv.decrypt(
        wrapped_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    aesgcm = AESGCM(key)
    nonce = bytes.fromhex(nonce_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    tag = bytes.fromhex(tag_hex)
    aad = bytes.fromhex(aad_hex)

    plaintext = aesgcm.decrypt(nonce, ciphertext + tag, aad)
    return json.loads(plaintext.decode('utf-8'))


def compute_ballot_digest(
    election_id: int,
    ballot_id: str,
    nonce_hex: str,
    ciphertext_hex: str,
    tag_hex: str,
    wrapped_key_hex: str | None = None,
) -> str:
    """Compute a SHA-256 digest over the ballot's key cryptographic fields."""
    fields: dict = {
        'ballot_id': ballot_id,
        'ciphertext_hex': ciphertext_hex,
        'election_id': election_id,
        'nonce_hex': nonce_hex,
        'tag_hex': tag_hex,
    }
    if wrapped_key_hex:
        fields['wrapped_key_hex'] = wrapped_key_hex
    data = canonical_json(fields)
    return hashlib.sha256(data).hexdigest()


def generate_receipt_code() -> str:
    """Generate a cryptographically random 256-bit receipt code."""
    return secrets.token_urlsafe(32)
