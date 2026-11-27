"""
app/extensions.py — Shared Flask extension singletons.

All extensions are initialised here (without an app) and then bound to the
application in create_app() via the application-factory pattern.
"""
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager

# SQLAlchemy ORM
db = SQLAlchemy()

# CSRF protection for all state-changing forms
csrf = CSRFProtect()

# IP-based rate limiter (in-memory by default; switch to Redis in production)
limiter = Limiter(key_func=get_remote_address, storage_uri='memory://')

# Session / authentication manager
login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please sign in to access this page.'
login_manager.login_message_category = 'warning'
