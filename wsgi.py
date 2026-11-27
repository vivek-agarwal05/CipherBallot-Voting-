"""
wsgi.py — Production WSGI entrypoint for Gunicorn / cloud deployments.

Usage:
    gunicorn --bind 0.0.0.0:8000 --workers 2 --threads 4 wsgi:app
"""
import os
from dotenv import load_dotenv

load_dotenv()

from app import create_app

app = create_app(os.environ.get('FLASK_ENV', 'production'))
