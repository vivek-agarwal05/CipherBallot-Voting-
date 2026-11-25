"""
app/commands.py — Flask CLI commands for CipherBallot.

Usage (with FLASK_APP=run.py set):
    flask init-db          — Create all tables
    flask seed-demo        — Seed demo users and elections
    flask verify-audit     — Verify the audit chain integrity
    flask init-keys        — Generate cryptographic keys (alias for scripts/init_keys.py)
"""
import click
from flask import Flask


def register_commands(app: Flask) -> None:
    """Attach all CLI commands to *app*."""

    @app.cli.command('init-db')
    def init_db_command():
        """Create all database tables."""
        from .extensions import db
        with app.app_context():
            db.create_all()
        click.echo('✅  Database tables created.')

    @app.cli.command('seed-demo')
    def seed_demo_command():
        """Seed demo users and elections (idempotent)."""
        import subprocess, sys
        result = subprocess.run(
            [sys.executable, 'scripts/seed_demo.py'],
            capture_output=False,
        )
        if result.returncode != 0:
            click.echo('❌  Seeding failed.', err=True)
        else:
            click.echo('✅  Demo data seeded.')

    @app.cli.command('verify-audit')
    def verify_audit_command():
        """Verify the integrity of the audit event hash chain."""
        from .security.audit import verify_audit_chain
        with app.app_context():
            result = verify_audit_chain()
        if result['verified']:
            click.echo(f"✅  {result['message']}")
        else:
            click.echo(f"❌  {result['message']}", err=True)
            raise SystemExit(1)

    @app.cli.command('init-keys')
    @click.option('--force', is_flag=True, default=False,
                  help='Overwrite existing keys and .env file.')
    def init_keys_command(force: bool):
        """Generate SECRET_KEY, ballot key, and Ed25519 keypair."""
        import subprocess, sys
        args = [sys.executable, 'scripts/init_keys.py']
        if force:
            args.append('--force')
        result = subprocess.run(args, capture_output=False)
        if result.returncode != 0:
            click.echo('❌  Key generation failed.', err=True)
