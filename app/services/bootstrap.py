"""
app/services/bootstrap.py — Runtime initialization for production & cloud deployments.

Safely ensures:
  1. Database tables exist when AUTO_INIT_DB=true (idempotent db.create_all()).
  2. Cryptographic RSA-2048 & Ed25519 keys exist when AUTO_INIT_KEYS=true and
     neither env PEMs nor PEM files are present yet.
  3. Initial Admin account is provisioned from ADMIN_USERNAME / ADMIN_PASSWORD
     env vars if configured and not already present.
"""
import logging
from pathlib import Path

from flask import Flask
from sqlalchemy.exc import IntegrityError

from ..extensions import db
from ..models import User
from ..security.audit import append_audit_event
from ..security.passwords import hash_password

logger = logging.getLogger(__name__)


def _ensure_keypairs(app: Flask) -> None:
    """Create missing RSA-2048 and Ed25519 PEM files when env PEMs are unset."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat, PublicFormat,
    )

    rsa_priv_path = Path(app.config['RSA_PRIVATE_KEY_PATH'])
    rsa_pub_path = Path(app.config['RSA_PUBLIC_KEY_PATH'])
    if (
        not app.config.get('RSA_PRIVATE_KEY_PEM')
        and not app.config.get('RSA_PUBLIC_KEY_PEM')
        and (not rsa_priv_path.exists() or not rsa_pub_path.exists())
    ):
        rsa_priv_path.parent.mkdir(parents=True, exist_ok=True)
        rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_priv_path.write_bytes(
            rsa_priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        )
        rsa_priv_path.chmod(0o600)
        rsa_pub_path.write_bytes(
            rsa_priv.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        )
        rsa_pub_path.chmod(0o644)
        logger.warning(
            'Auto-generated ephemeral RSA-2048 keypair at %s. '
            'Set RSA_PRIVATE_KEY_PEM/RSA_PUBLIC_KEY_PEM in production for persistence.',
            rsa_priv_path,
        )

    sig_priv_path = Path(app.config['SIGNING_PRIVATE_KEY_PATH'])
    sig_pub_path = Path(app.config['SIGNING_PUBLIC_KEY_PATH'])
    if (
        not app.config.get('SIGNING_PRIVATE_KEY_PEM')
        and not app.config.get('SIGNING_PUBLIC_KEY_PEM')
        and (not sig_priv_path.exists() or not sig_pub_path.exists())
    ):
        sig_priv_path.parent.mkdir(parents=True, exist_ok=True)
        sig_priv = Ed25519PrivateKey.generate()
        sig_priv_path.write_bytes(
            sig_priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        )
        sig_priv_path.chmod(0o600)
        sig_pub_path.write_bytes(
            sig_priv.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        )
        sig_pub_path.chmod(0o644)
        logger.warning(
            'Auto-generated ephemeral Ed25519 keypair at %s. '
            'Set SIGNING_PRIVATE_KEY_PEM/SIGNING_PUBLIC_KEY_PEM in production for persistence.',
            sig_priv_path,
        )


def _ensure_admin_from_env(app: Flask) -> None:
    """Create initial admin account if ADMIN_USERNAME and ADMIN_PASSWORD are provided."""
    username = (app.config.get('ADMIN_USERNAME') or '').strip().lower()
    password = app.config.get('ADMIN_PASSWORD') or ''
    display_name = (app.config.get('ADMIN_DISPLAY_NAME') or 'Election Administrator').strip()

    if not username or not password:
        return

    with app.app_context():
        existing = db.session.query(User).filter_by(username=username).first()
        if existing:
            return
        admin = User(
            username=username,
            display_name=display_name,
            password_hash=hash_password(password),
            role='admin',
            id_verified=True,
            is_active=True,
        )
        try:
            db.session.add(admin)
            db.session.commit()
            append_audit_event(
                event_type='system.admin_bootstrapped',
                actor_category='system',
                actor_ref='system',
                payload={'username': username},
            )
            logger.info('Bootstrapped admin account "%s" from environment.', username)
        except IntegrityError:
            db.session.rollback()


def bootstrap_runtime(app: Flask) -> None:
    """Run idempotent runtime initialization based on app configuration."""
    if app.config.get('TESTING'):
        return

    if app.config.get('AUTO_INIT_KEYS'):
        _ensure_keypairs(app)

    if app.config.get('AUTO_INIT_DB'):
        with app.app_context():
            db.create_all()
        _ensure_admin_from_env(app)
        with app.app_context():
            db.engine.dispose()
