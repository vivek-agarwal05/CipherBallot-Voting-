#!/usr/bin/env python3
"""
scripts/reset_demo_data.py — Drop all tables and re-seed demo data.

⚠️  WARNING: This permanently deletes ALL data in the database.
   Use only in development / demo environments.

Requires interactive confirmation: type 'RESET' at the prompt.
Pass --yes to skip the prompt (for automated test pipelines only).
"""
import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv
load_dotenv(PROJECT_ROOT / '.env')


def main(skip_confirm: bool = False) -> None:
    print()
    print('=' * 60)
    print('  ⚠️   CipherBallot — RESET DEMO DATA')
    print('=' * 60)
    print()
    print('  This will:')
    print('    1. DROP all database tables (all data is LOST)')
    print('    2. Re-create all tables from the SQLAlchemy models')
    print('    3. Re-seed with fresh demo users and elections')
    print()
    print('  Cryptographic keys in instance/keys/ are NOT touched.')
    print()

    if not skip_confirm:
        try:
            answer = input("  Type 'RESET' to confirm, or press Ctrl-C to abort: ").strip()
        except KeyboardInterrupt:
            print('\n\n  Aborted.')
            sys.exit(0)

        if answer != 'RESET':
            print(f'\n  You typed {answer!r}, not RESET. Aborted.')
            sys.exit(0)

    print()
    print('  Resetting...')

    from app import create_app
    from app.extensions import db

    app = create_app('development')

    with app.app_context():
        print('  [1/3] Dropping all tables...')
        db.drop_all()
        print('        Done.')

        print('  [2/3] Re-creating all tables...')
        db.create_all()
        print('        Done.')

    print('  [3/3] Re-seeding demo data...')
    # Import and run seed after app context is set up
    import importlib.util
    seed_path = PROJECT_ROOT / 'scripts' / 'seed_demo.py'
    spec = importlib.util.spec_from_file_location('seed_demo', seed_path)
    seed_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(seed_module)
    seed_module.main()

    print()
    print('=' * 60)
    print('✅  Reset complete.')
    print('=' * 60)
    print()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Drop all tables and re-seed CipherBallot demo data.'
    )
    parser.add_argument(
        '--yes',
        action='store_true',
        help='Skip the interactive confirmation prompt.',
    )
    args = parser.parse_args()
    main(skip_confirm=args.yes)
