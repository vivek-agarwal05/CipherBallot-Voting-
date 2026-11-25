"""
app/__init__.py — CipherBallot application factory.

Supports all three course variants (A, B, C) per election using:
  - Hybrid Encryption (RSA-2048 OAEP + ephemeral AES-256-GCM per ballot)
  - Ed25519 Digital Signatures + SHA-256 Verifiable Receipts & Audit Chain
"""
import os
from flask import Flask, render_template

from .config import config, PROJECT_VARIANT
from .extensions import db, csrf, limiter, login_manager


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
    # Error handlers                                                       #
    # ------------------------------------------------------------------ #
    @app.errorhandler(404)
    def not_found(e):
        return render_template('errors/404.html'), 404

    @app.errorhandler(403)
    def forbidden(e):
        return render_template('errors/403.html'), 403

    @app.errorhandler(500)
    def server_error(e):
        return render_template('errors/500.html'), 500

    # ------------------------------------------------------------------ #
    # Template context processor — inject variant into every template     #
    # ------------------------------------------------------------------ #
    @app.context_processor
    def inject_variant():
        return {'project_variant': PROJECT_VARIANT}

    return app
