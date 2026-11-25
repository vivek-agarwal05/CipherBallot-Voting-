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


class Config:
    # ------------------------------------------------------------------ #
    # Core Flask                                                           #
    # ------------------------------------------------------------------ #
    SECRET_KEY: str | None = os.environ.get('SECRET_KEY') or None
    SQLALCHEMY_DATABASE_URI: str = (
        os.environ.get('DATABASE_URL') or 'sqlite:///cipherballet.db'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False

    # ------------------------------------------------------------------ #
    # Security / Session                                                  #
    # ------------------------------------------------------------------ #
    WTF_CSRF_ENABLED: bool = True
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = 'Lax'
    SESSION_COOKIE_SECURE: bool = False  # Set True automatically when TLS is enabled
    PERMANENT_SESSION_LIFETIME: int = 3600  # 1 hour in seconds

    # ------------------------------------------------------------------ #
    # Rate Limiting & Account Lockout                                     #
    # ------------------------------------------------------------------ #
    RATELIMIT_DEFAULT: str = "200 per day;50 per hour"
    RATELIMIT_STORAGE_URL: str = "memory://"
    MAX_FAILED_LOGINS: int = 5
    LOCKOUT_MINUTES: int = 5

    # ------------------------------------------------------------------ #
    # Cryptographic Key & Certificate Paths                               #
    # ------------------------------------------------------------------ #
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
    SQLALCHEMY_DATABASE_URI: str = 'sqlite:///:memory:'
    # Tests supply their own key material or mock it
    RSA_PRIVATE_KEY_PATH: str = 'instance/keys/rsa_private.pem'
    RSA_PUBLIC_KEY_PATH: str = 'instance/keys/rsa_public.pem'
    SIGNING_PRIVATE_KEY_PATH: str = 'instance/keys/signing_private.pem'
    SIGNING_PUBLIC_KEY_PATH: str = 'instance/keys/signing_public.pem'


class ProductionConfig(Config):
    SESSION_COOKIE_SECURE: bool = True
    # In production, SECRET_KEY and key paths MUST come from environment
    # variables or a secrets manager — never hardcoded.


config: dict = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig,
}
