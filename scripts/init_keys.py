#!/usr/bin/env python3
"""
scripts/init_keys.py — Generate all cryptographic secrets & TLS certificate for CipherBallot.

Generates:
  1. SECRET_KEY                           — 256-bit Flask session secret (hex)
  2. instance/keys/ballot.key             — 256-bit AES key (legacy / fallback)
  3. instance/keys/rsa_private.pem        — RSA-2048 private key (for hybrid key unwrapping)
  4. instance/keys/rsa_public.pem         — RSA-2048 public key  (for hybrid key wrapping)
  5. instance/keys/signing_private.pem    — Ed25519 private key  (for tally certification)
  6. instance/keys/signing_public.pem     — Ed25519 public key
  7. instance/certs/cert.pem & key.pem    — Self-signed X.509 TLS certificate (localhost)
  8. .env                                 — Environment variable file for Flask

Usage:
    python scripts/init_keys.py                  # Abort if .env already exists
    python scripts/init_keys.py --ensure-missing # Create missing keys/certs without overwriting existing ones
    python scripts/init_keys.py --force          # Overwrite existing files

IMPORTANT: Keep private keys, certs, and .env SECRET. They are in .gitignore by default.
"""
import argparse
import ipaddress
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def _abort(message: str) -> None:
    print(f'\n❌  ERROR: {message}\n', file=sys.stderr)
    sys.exit(1)


def _info(message: str) -> None:
    print(f'   {message}')


def _ok(message: str) -> None:
    print(f'✅  {message}')


def _generate_rsa_keypair(keys_dir: Path, overwrite: bool = False) -> None:
    """Generate RSA-2048 keypair for hybrid AES-256-GCM key encapsulation."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat, PublicFormat,
    )

    priv_path = keys_dir / 'rsa_private.pem'
    pub_path = keys_dir / 'rsa_public.pem'
    if not overwrite and priv_path.exists() and pub_path.exists():
        _info(f'[skip] RSA-2048 keypair already exists at {priv_path}')
        return

    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_pub = rsa_priv.public_key()

    priv_path.write_bytes(rsa_priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    priv_path.chmod(0o600)
    pub_path.write_bytes(rsa_pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    pub_path.chmod(0o644)
    _ok(f'RSA-2048 keypair (Hybrid Encryption): {priv_path} & {pub_path}')


def _generate_self_signed_tls_cert(certs_dir: Path, overwrite: bool = False) -> None:
    """Generate a local self-signed X.509 certificate for HTTPS/TLS."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat,
    )
    from cryptography.x509.oid import NameOID

    cert_path = certs_dir / 'cert.pem'
    key_path = certs_dir / 'key.pem'
    if not overwrite and cert_path.exists() and key_path.exists():
        _info(f'[skip] TLS X.509 cert already exists at {cert_path}')
        return

    certs_dir.mkdir(parents=True, exist_ok=True)
    tls_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'IN'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'CipherBallot Course Prototype'),
        x509.NameAttribute(NameOID.COMMON_NAME, 'localhost'),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(tls_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName('localhost'),
                x509.IPAddress(ipaddress.IPv4Address('127.0.0.1')),
            ]),
            critical=False,
        )
        .sign(tls_key, hashes.SHA256())
    )

    key_path.write_bytes(tls_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    key_path.chmod(0o600)
    cert_path.write_bytes(cert.public_bytes(Encoding.PEM))
    cert_path.chmod(0o644)
    _ok(f'X.509 TLS cert & key (HTTPS): {cert_path} & {key_path}')


def main(force: bool = False, ensure_missing: bool = False) -> None:
    os.chdir(PROJECT_ROOT)

    env_path = PROJECT_ROOT / '.env'
    keys_dir = PROJECT_ROOT / 'instance' / 'keys'
    certs_dir = PROJECT_ROOT / 'instance' / 'certs'

    if not force and not ensure_missing:
        if env_path.exists():
            _abort(
                f'.env already exists at {env_path}.\n'
                '       Pass --ensure-missing to add only missing keys/certs, or --force to overwrite all.'
            )
        ballot_key = keys_dir / 'ballot.key'
        if ballot_key.exists():
            _abort(
                f'Ballot key already exists at {ballot_key}.\n'
                '       Pass --ensure-missing or --force.'
            )

    keys_dir.mkdir(parents=True, exist_ok=True)
    certs_dir.mkdir(parents=True, exist_ok=True)
    _ok(f'Keys directory: {keys_dir}')

    # 1. AES-256 fallback key
    ballot_key_path = keys_dir / 'ballot.key'
    if force or not ballot_key_path.exists():
        ballot_key_path.write_bytes(os.urandom(32))
        ballot_key_path.chmod(0o600)
        _ok(f'Ballot key: {ballot_key_path} (32 bytes, mode 0600)')
    else:
        _info(f'[skip] Ballot key exists: {ballot_key_path}')

    # 2. RSA-2048 keypair (Hybrid Encryption)
    _generate_rsa_keypair(keys_dir, overwrite=force)

    # 3. Ed25519 signing keypair
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat, PublicFormat,
    )

    private_key_path = keys_dir / 'signing_private.pem'
    public_key_path = keys_dir / 'signing_public.pem'
    if force or not private_key_path.exists() or not public_key_path.exists():
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        private_key_path.write_bytes(
            private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        )
        private_key_path.chmod(0o600)
        public_key_path.write_bytes(
            public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        )
        public_key_path.chmod(0o644)
        _ok(f'Ed25519 keypair: {private_key_path} & {public_key_path}')
    else:
        _info(f'[skip] Ed25519 keypair exists: {private_key_path}')

    # 4. Self-signed X.509 TLS certificate
    _generate_self_signed_tls_cert(certs_dir, overwrite=force)

    # 5. .env file
    if force or not env_path.exists():
        secret_key = secrets.token_hex(32)
        env_content = f"""\
# CipherBallot environment configuration
# Generated by scripts/init_keys.py — DO NOT COMMIT THIS FILE.

SECRET_KEY={secret_key}
DATABASE_URL=sqlite:///cipherballet.db

BALLOT_KEY_PATH=instance/keys/ballot.key
RSA_PRIVATE_KEY_PATH=instance/keys/rsa_private.pem
RSA_PUBLIC_KEY_PATH=instance/keys/rsa_public.pem
SIGNING_PRIVATE_KEY_PATH=instance/keys/signing_private.pem
SIGNING_PUBLIC_KEY_PATH=instance/keys/signing_public.pem
TLS_CERT_PATH=instance/certs/cert.pem
TLS_KEY_PATH=instance/certs/key.pem

FLASK_ENV=development
FLASK_APP=run.py
"""
        env_path.write_text(env_content, encoding='utf-8')
        _ok(f'.env written: {env_path}')
    else:
        _info(f'[skip] .env already exists at {env_path}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Generate CipherBallot cryptographic keys, TLS certs, and .env file.'
    )
    parser.add_argument('--force', action='store_true', help='Overwrite existing .env and key/cert files.')
    parser.add_argument('--ensure-missing', action='store_true', help='Create only missing keys/certs without overwriting existing files.')
    args = parser.parse_args()
    main(force=args.force, ensure_missing=args.ensure_missing)
