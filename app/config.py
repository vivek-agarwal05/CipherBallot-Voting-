"""
app/config.py — CipherBallot application configuration.

PROJECT_VARIANT controls the active system showcase mode:
  "A"     = Single-class election with encrypted ballots
  "B"     = Department poll with voter eligibility + verifiable receipts
  "C"     = Privacy-focused anonymous token model vs. identity-linked audit records
  "A/B/C" = Multi-variant mode supporting all three variants per election (default)
"""
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

PROJECT_VARIANT = "A/B/C"  # Supports A, B, C per election — see README.md


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == '':
        return default
    return raw.strip().lower() in ('1', 'true', 'yes', 'on')


def _normalize_database_url(raw_url: str | None) -> str:
    """Normalize Postgres connection URLs (e.g. Render/Railway) for SQLAlchemy + psycopg."""
    if not raw_url:
        return 'sqlite:///cipherballet.db'
    url = raw_url.strip()
    if url.startswith('postgres://'):
        return 'postgresql+psycopg://' + url[len('postgres://'):]
    if url.startswith('postgresql://'):
        return 'postgresql+psycopg://' + url[len('postgresql://'):]
    return url


class Config:
    # ------------------------------------------------------------------ #
    # Core Flask                                                           #
    # ------------------------------------------------------------------ #
    SECRET_KEY: str | None = os.environ.get('SECRET_KEY') or None
    SQLALCHEMY_DATABASE_URI: str = _normalize_database_url(os.environ.get('DATABASE_URL'))
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    SQLALCHEMY_ENGINE_OPTIONS: dict = {'pool_pre_ping': True}

    # ------------------------------------------------------------------ #
    # Security / Session / Proxy                                          #
    # ------------------------------------------------------------------ #
    WTF_CSRF_ENABLED: bool = True
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = 'Lax'
    SESSION_COOKIE_SECURE: bool = _env_bool('SESSION_COOKIE_SECURE', False)
    PERMANENT_SESSION_LIFETIME: int = 3600  # 1 hour in seconds
    TRUST_PROXY: bool = _env_bool('TRUST_PROXY', False)

    # ------------------------------------------------------------------ #
    # Demo Hints & Automated Runtime Bootstrap                            #
    # ------------------------------------------------------------------ #
    SHOW_DEMO_HINTS: bool = _env_bool('SHOW_DEMO_HINTS', True)
    AUTO_INIT_DB: bool = _env_bool('AUTO_INIT_DB', True)
    AUTO_INIT_KEYS: bool = _env_bool('AUTO_INIT_KEYS', False)
    ADMIN_USERNAME: str | None = os.environ.get('ADMIN_USERNAME') or None
    ADMIN_PASSWORD: str | None = os.environ.get('ADMIN_PASSWORD') or None
    ADMIN_DISPLAY_NAME: str = os.environ.get('ADMIN_DISPLAY_NAME') or 'Election Administrator'

    # ------------------------------------------------------------------ #
    # Rate Limiting & Account Lockout                                     #
    # ------------------------------------------------------------------ #
    RATELIMIT_DEFAULT: str = "5000 per day;1000 per hour"
    RATELIMIT_STORAGE_URL: str = (
        os.environ.get('RATELIMIT_STORAGE_URL')
        or os.environ.get('REDIS_URL')
        or "memory://"
    )
    MAX_FAILED_LOGINS: int = 5
    LOCKOUT_MINUTES: int = 5
    PASSWORD_RESET_MAX_AGE_SECONDS: int = 900  # 15 minutes

    # ------------------------------------------------------------------ #
    # Optional SMTP Email Delivery (PINs & Password Reset)                #
    # ------------------------------------------------------------------ #
    MAIL_SERVER: str | None = os.environ.get('MAIL_SERVER') or None
    MAIL_PORT: int = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS: bool = _env_bool('MAIL_USE_TLS', True)
    MAIL_USE_SSL: bool = _env_bool('MAIL_USE_SSL', False)
    MAIL_USERNAME: str | None = os.environ.get('MAIL_USERNAME') or None
    MAIL_PASSWORD: str | None = os.environ.get('MAIL_PASSWORD') or None
    MAIL_DEFAULT_SENDER: str | None = (
        os.environ.get('MAIL_DEFAULT_SENDER')
        or os.environ.get('MAIL_USERNAME')
        or None
    )

    # ------------------------------------------------------------------ #
    # Cryptographic Key & Certificate Paths / Env PEMs                    #
    # ------------------------------------------------------------------ #
    RSA_PRIVATE_KEY_PEM: str | None = os.environ.get('RSA_PRIVATE_KEY_PEM') or None
    RSA_PUBLIC_KEY_PEM: str | None = os.environ.get('RSA_PUBLIC_KEY_PEM') or None
    SIGNING_PRIVATE_KEY_PEM: str | None = os.environ.get('SIGNING_PRIVATE_KEY_PEM') or None
    SIGNING_PUBLIC_KEY_PEM: str | None = os.environ.get('SIGNING_PUBLIC_KEY_PEM') or None

    RSA_PRIVATE_KEY_PATH: str = (
        os.environ.get('RSA_PRIVATE_KEY_PATH')
        or str(Path('instance/keys/rsa_private.pem'))
    )
    RSA_PUBLIC_KEY_PATH: str = (
        os.environ.get('RSA_PUBLIC_KEY_PATH')
        or str(Path('instance/keys/rsa_public.pem'))
    )
    SIGNING_PRIVATE_KEY_PATH: str = (
        os.environ.get('SIGNING_PRIVATE_KEY_PATH')
        or str(Path('instance/keys/signing_private.pem'))
    )
    SIGNING_PUBLIC_KEY_PATH: str = (
        os.environ.get('SIGNING_PUBLIC_KEY_PATH')
        or str(Path('instance/keys/signing_public.pem'))
    )
    TLS_CERT_PATH: str = (
        os.environ.get('TLS_CERT_PATH')
        or str(Path('instance/certs/cert.pem'))
    )
    TLS_KEY_PATH: str = (
        os.environ.get('TLS_KEY_PATH')
        or str(Path('instance/certs/key.pem'))
    )

    # ------------------------------------------------------------------ #
    # Upload limits                                                        #
    # ------------------------------------------------------------------ #
    MAX_CONTENT_LENGTH: int = 2 * 1024 * 1024  # 2 MB


class DevelopmentConfig(Config):
    DEBUG: bool = True


class TestingConfig(Config):
    TESTING: bool = True
    WTF_CSRF_ENABLED: bool = False
    RATELIMIT_ENABLED: bool = False
    RATELIMIT_STORAGE_URL: str = 'memory://'
    SQLALCHEMY_DATABASE_URI: str = 'sqlite:///:memory:'
    SQLALCHEMY_ENGINE_OPTIONS: dict = {}
    TRUST_PROXY: bool = False
    SHOW_DEMO_HINTS: bool = True
    AUTO_INIT_DB: bool = False
    AUTO_INIT_KEYS: bool = False
    MAIL_SERVER: str | None = None
    RSA_PRIVATE_KEY_PEM: str | None = None
    RSA_PUBLIC_KEY_PEM: str | None = None
    SIGNING_PRIVATE_KEY_PEM: str | None = None
    SIGNING_PUBLIC_KEY_PEM: str | None = None
    RSA_PRIVATE_KEY_PATH: str = 'instance/keys/rsa_private.pem'
    RSA_PUBLIC_KEY_PATH: str = 'instance/keys/rsa_public.pem'
    SIGNING_PRIVATE_KEY_PATH: str = 'instance/keys/signing_private.pem'
    SIGNING_PUBLIC_KEY_PATH: str = 'instance/keys/signing_public.pem'


class ProductionConfig(Config):
    DEBUG: bool = False
    SESSION_COOKIE_SECURE: bool = _env_bool('SESSION_COOKIE_SECURE', True)
    TRUST_PROXY: bool = _env_bool('TRUST_PROXY', True)
    SHOW_DEMO_HINTS: bool = _env_bool('SHOW_DEMO_HINTS', False)
    AUTO_INIT_KEYS: bool = _env_bool('AUTO_INIT_KEYS', True)


config: dict = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig,
}
