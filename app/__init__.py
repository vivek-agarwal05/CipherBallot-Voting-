"""
app/__init__.py — CipherBallot application factory.

Supports all three course variants (A, B, C) per election using:
  - Hybrid Encryption (RSA-2048 OAEP + ephemeral AES-256-GCM per ballot)
  - Ed25519 Digital Signatures + SHA-256 Verifiable Receipts & Audit Chain
"""
import os
from flask import Flask, render_template
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import config, PROJECT_VARIANT, _env_bool, _normalize_database_url
from .extensions import db, csrf, limiter, login_manager


def _apply_env_overrides(app: Flask) -> None:
    """Refresh env-driven config keys at create_app() time for non-testing runs."""
    if os.environ.get('SECRET_KEY'):
        app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
    if os.environ.get('DATABASE_URL'):
        app.config['SQLALCHEMY_DATABASE_URI'] = _normalize_database_url(os.environ['DATABASE_URL'])
    if os.environ.get('RATELIMIT_STORAGE_URL') or os.environ.get('REDIS_URL'):
        app.config['RATELIMIT_STORAGE_URL'] = (
            os.environ.get('RATELIMIT_STORAGE_URL') or os.environ.get('REDIS_URL')
        )
    for bool_key in ('SHOW_DEMO_HINTS', 'TRUST_PROXY', 'AUTO_INIT_DB', 'AUTO_INIT_KEYS', 'SESSION_COOKIE_SECURE', 'MAIL_USE_TLS', 'MAIL_USE_SSL'):
        if os.environ.get(bool_key) is not None and os.environ.get(bool_key) != '':
            app.config[bool_key] = _env_bool(bool_key, bool(app.config.get(bool_key)))
    for str_key in (
        'ADMIN_USERNAME', 'ADMIN_PASSWORD', 'ADMIN_DISPLAY_NAME',
        'RSA_PRIVATE_KEY_PEM', 'RSA_PUBLIC_KEY_PEM',
        'SIGNING_PRIVATE_KEY_PEM', 'SIGNING_PUBLIC_KEY_PEM',
        'RSA_PRIVATE_KEY_PATH', 'RSA_PUBLIC_KEY_PATH',
        'SIGNING_PRIVATE_KEY_PATH', 'SIGNING_PUBLIC_KEY_PATH',
        'MAIL_SERVER', 'MAIL_USERNAME', 'MAIL_PASSWORD', 'MAIL_DEFAULT_SENDER',
    ):
        if os.environ.get(str_key):
            app.config[str_key] = os.environ[str_key]
    if os.environ.get('MAIL_PORT'):
        app.config['MAIL_PORT'] = int(os.environ['MAIL_PORT'])


def create_app(config_name: str | None = None) -> Flask:
    """
    Application factory.

    Args:
        config_name: One of 'development', 'testing', 'production', or None.
                     If None, reads FLASK_ENV environment variable (default:
                     'development').

    Returns:
        Configured Flask application instance.

    Raises:
        RuntimeError: If SECRET_KEY is not set (run scripts/init_keys.py).
    """
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')

    app = Flask(__name__, instance_relative_config=True)

    # ------------------------------------------------------------------ #
    # Configuration                                                        #
    # ------------------------------------------------------------------ #
    cfg = config.get(config_name, config['default'])
    app.config.from_object(cfg)
    if config_name != 'testing':
        _apply_env_overrides(app)
    app.config['PROJECT_VARIANT'] = PROJECT_VARIANT

    # Validate required config
    if not app.config.get('SECRET_KEY'):
        raise RuntimeError(
            "SECRET_KEY is not set.\n"
            "Run:  python scripts/init_keys.py\n"
            "Then: copy .env.example to .env and fill in the values."
        )

    # ------------------------------------------------------------------ #
    # Ensure instance directories exist                                    #
    # ------------------------------------------------------------------ #
    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(os.path.join(app.instance_path, 'keys'), exist_ok=True)

    # ------------------------------------------------------------------ #
    # Initialise extensions                                                #
    # ------------------------------------------------------------------ #
    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    login_manager.init_app(app)

    if app.config.get('TRUST_PROXY'):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    # ------------------------------------------------------------------ #
    # Register blueprints                                                  #
    # ------------------------------------------------------------------ #
    from .auth.routes import auth_bp
    app.register_blueprint(auth_bp)

    from .public.routes import public_bp
    app.register_blueprint(public_bp)

    from .voter.routes import voter_bp
    app.register_blueprint(voter_bp, url_prefix='/voter')

    from .admin.routes import admin_bp
    app.register_blueprint(admin_bp, url_prefix='/admin')

    from .api.routes import api_bp
    app.register_blueprint(api_bp, url_prefix='/api/v1')

    # ------------------------------------------------------------------ #
    # Runtime bootstrap (DB tables, optional keys/admin from env)          #
    # ------------------------------------------------------------------ #
    from .services.bootstrap import bootstrap_runtime
    bootstrap_runtime(app)

    # ------------------------------------------------------------------ #
    # Error handlers                                                       #
    # ------------------------------------------------------------------ #
    @app.errorhandler(404)
    def not_found(e):
        return render_template('errors/404.html'), 404

    @app.errorhandler(403)
    def forbidden(e):
        return render_template('errors/403.html'), 403

    @app.errorhandler(429)
    def too_many_requests(e):
        return render_template('errors/429.html'), 429

    @app.errorhandler(500)
    def server_error(e):
        return render_template('errors/500.html'), 500

    # ------------------------------------------------------------------ #
    # CLI commands                                                         #
    # ------------------------------------------------------------------ #
    @app.cli.command('init-db')
    def init_db_command():
        """Create all SQLAlchemy database tables."""
        db.create_all()
        print('Database tables initialized successfully.')

    # ------------------------------------------------------------------ #
    # Template context processor — inject global UI flags                 #
    # ------------------------------------------------------------------ #
    from .security.email import is_email_configured

    @app.context_processor
    def inject_variant():
        return {
            'project_variant': PROJECT_VARIANT,
            'show_demo_hints': bool(app.config.get('SHOW_DEMO_HINTS', False)),
            'email_configured': is_email_configured(),
        }

    return app
