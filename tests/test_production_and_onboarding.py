import io
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from app import create_app
from app.config import ProductionConfig, _normalize_database_url
from app.extensions import db as _db
from app.models import Election, InstitutionalIdentity, User
from app.security.ballots import decrypt_ballot, encrypt_ballot_hybrid
from app.security.canonical import canonical_json
from app.security.email import send_password_reset_email, send_verification_pin_email
from app.security.passwords import hash_password, verify_password
from app.security.signatures import sign_document, verify_document_signature
from app.services.voting import check_voter_eligibility


def test_custom_department_registration_and_email_mismatch(client, db):
    """Students from any custom department can register; mismatched institutional emails are rejected."""
    db.session.add(InstitutionalIdentity(
        student_id='STU-MECH-2026-01',
        full_name='Aarav Patel',
        department='Mechanical Engineering',
        email='aarav.patel@univ.edu',
        verification_pin_hash=hash_password('PIN-MECH1'),
    ))
    db.session.commit()

    # Mismatched email rejected
    r_bad = client.post('/auth/register', data={
        'student_id': 'STU-MECH-2026-01',
        'verification_pin': 'PIN-MECH1',
        'username': 'aarav_p',
        'display_name': 'Aarav Patel',
        'department': 'Mechanical Engineering',
        'email': 'wrong@univ.edu',
        'password': 'StrongPassword!1',
        'confirm_password': 'StrongPassword!1',
    }, follow_redirects=True)
    assert b'Institutional email does not match' in r_bad.data

    # Exact details succeed for custom department
    r_ok = client.post('/auth/register', data={
        'student_id': 'STU-MECH-2026-01',
        'verification_pin': 'PIN-MECH1',
        'username': 'aarav_p',
        'display_name': 'Aarav Patel',
        'department': 'Mechanical Engineering',
        'email': 'aarav.patel@univ.edu',
        'password': 'StrongPassword!1',
        'confirm_password': 'StrongPassword!1',
    }, follow_redirects=True)
    assert r_ok.status_code == 200
    assert b'Student identity successfully verified' in r_ok.data
    user = db.session.query(User).filter_by(username='aarav_p').first()
    assert user is not None
    assert user.department == 'Mechanical Engineering'


def test_csv_bulk_import_and_reissue_pin(client, db, admin_user):
    """Admin can bulk-import students via CSV and reissue PINs for unclaimed identities."""
    client.post('/auth/login', data={'username': 'testadmin', 'password': 'AdminPass123!'}, follow_redirects=True)

    csv_content = (
        "student_id,full_name,department,email,verification_pin\n"
        "STU-BIO-2026-01,Neha Sharma,Bioinformatics,neha@univ.edu,\n"
        "STU-LAW-2026-02,Rohan Verma,Corporate Law,rohan@univ.edu,CUSTOM-99\n"
        "STU-LAW-2026-02,Dup User,Corporate Law,rohan@univ.edu,\n"
    ).encode('utf-8')

    resp = client.post(
        '/admin/registry/import-csv',
        data={'csv_file': (io.BytesIO(csv_content), 'students.csv')},
        content_type='multipart/form-data',
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b'Imported 2 student record(s)' in resp.data
    assert b'Newly Imported Verification PINs' in resp.data
    assert b'STU-BIO-2026-01' in resp.data
    assert b'CUSTOM-99' in resp.data

    ident = db.session.query(InstitutionalIdentity).filter_by(student_id='STU-BIO-2026-01').first()
    assert ident is not None

    # Re-issue PIN invalidates old PIN and sets a fresh one
    reissue_resp = client.post(f'/admin/registry/{ident.id}/reissue-pin', follow_redirects=True)
    assert reissue_resp.status_code == 200
    m = re.search(r'New One-Time Verification PIN[^:]*:\s*(PIN-[A-F0-9]+)', reissue_resp.data.decode())
    assert m is not None
    new_pin = m.group(1)
    refreshed = db.session.get(InstitutionalIdentity, ident.id)
    assert verify_password(refreshed.verification_pin_hash, new_pin) is True


def test_password_reset_single_use_flow(client, db, admin_user, voter_user):
    """Admin-issued or emailed reset token updates password, clears lockout, and cannot be reused."""
    voter_user.failed_login_attempts = 5
    voter_user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=5)
    db.session.commit()

    client.post('/auth/login', data={'username': 'testadmin', 'password': 'AdminPass123!'}, follow_redirects=True)
    r_issue = client.post(f'/admin/users/{voter_user.id}/reset-link', follow_redirects=True)
    assert r_issue.status_code == 200
    m = re.search(r'id="generatedResetUrl"[^>]*>([^<]+)<', r_issue.data.decode())
    assert m is not None
    reset_path = '/' + m.group(1).split('://', 1)[-1].split('/', 1)[-1]
    client.post('/auth/logout', follow_redirects=True)

    # Reset password via token
    r_reset = client.post(
        reset_path,
        data={'password': 'BrandNewPass!2026', 'confirm_password': 'BrandNewPass!2026'},
        follow_redirects=True,
    )
    assert r_reset.status_code == 200
    assert b'password has been reset cleanly' in r_reset.data

    # Old password fails, new password works, lockout cleared
    r_old = client.post('/auth/login', data={'username': 'testvoter', 'password': 'VoterPass123!'}, follow_redirects=True)
    assert b'Invalid username or password' in r_old.data
    r_new = client.post('/auth/login', data={'username': 'testvoter', 'password': 'BrandNewPass!2026'}, follow_redirects=True)
    assert b'Hello, Test Voter 1' in r_new.data
    client.post('/auth/logout', follow_redirects=True)

    # Same reset token cannot be reused
    r_reuse = client.get(reset_path, follow_redirects=True)
    assert b'no longer valid or has already been used' in r_reuse.data


def test_election_scheduling_window_enforced(client, db, admin_user, voter_user):
    """Admin can configure start_dt/end_dt and future/expired windows block voting."""
    client.post('/auth/login', data={'username': 'testadmin', 'password': 'AdminPass123!'}, follow_redirects=True)

    # Invalid window (end <= start) rejected
    r_bad = client.post('/admin/elections/new', data={
        'title': 'Bad Window Poll',
        'variant': 'A',
        'start_dt': '2026-12-10T10:00',
        'end_dt': '2026-12-09T10:00',
    }, follow_redirects=True)
    assert b'Closing date/time must be after opening date/time' in r_bad.data

    # Future start window
    future_start = (datetime.now(timezone.utc) + timedelta(days=2)).strftime('%Y-%m-%dT%H:%M')
    future_end = (datetime.now(timezone.utc) + timedelta(days=5)).strftime('%Y-%m-%dT%H:%M')
    r_ok = client.post('/admin/elections/new', data={
        'title': 'Scheduled Future Poll',
        'variant': 'A',
        'start_dt': future_start,
        'end_dt': future_end,
    }, follow_redirects=True)
    assert r_ok.status_code == 200
    el = db.session.query(Election).filter_by(title='Scheduled Future Poll').first()
    assert el is not None
    el.status = 'open'
    db.session.commit()

    elig = check_voter_eligibility(el.id, voter_user.id)
    assert elig['can_vote'] is False
    assert elig['election_open'] is False


def test_smtp_email_helpers_use_configured_server(app):
    """Optional SMTP helpers send PIN and password reset emails when configured."""
    app.config.update({
        'MAIL_SERVER': 'smtp.example.com',
        'MAIL_PORT': 587,
        'MAIL_USE_TLS': True,
        'MAIL_USE_SSL': False,
        'MAIL_USERNAME': 'noreply@example.com',
        'MAIL_PASSWORD': 'app-password',
        'MAIL_DEFAULT_SENDER': 'CipherBallot <noreply@example.com>',
    })
    with app.app_context():
        with patch('app.security.email.smtplib.SMTP') as mock_smtp:
            smtp_inst = MagicMock()
            mock_smtp.return_value.__enter__.return_value = smtp_inst
            ok1, err1 = send_verification_pin_email(
                'student@univ.edu', 'Maya Lin', 'STU-1', 'CS', 'PIN-1234', 'https://example.com/auth/register'
            )
            ok2, err2 = send_password_reset_email(
                'student@univ.edu', 'Maya Lin', 'maya', 'https://example.com/auth/reset-password/tok'
            )
            assert ok1 is True and err1 is None
            assert ok2 is True and err2 is None
            assert smtp_inst.send_message.call_count == 2


def test_production_config_env_pems_demo_toggle_and_bootstrap(tmp_path, monkeypatch):
    """Production mode hides demo hints, loads inline env PEM keys, normalizes Postgres URLs, and bootstraps admin."""
    assert _normalize_database_url('postgres://user:pass@host:5432/db') == 'postgresql+psycopg://user:pass@host:5432/db'
    assert _normalize_database_url('postgresql://user:pass@host:5432/db') == 'postgresql+psycopg://user:pass@host:5432/db'
    assert ProductionConfig.SHOW_DEMO_HINTS is False
    assert ProductionConfig.TRUST_PROXY is True

    root = Path(__file__).resolve().parent.parent
    rsa_priv = (root / 'instance' / 'keys' / 'rsa_private.pem').read_text().replace('\n', '\\n')
    rsa_pub = (root / 'instance' / 'keys' / 'rsa_public.pem').read_text().replace('\n', '\\n')
    sig_priv = (root / 'instance' / 'keys' / 'signing_private.pem').read_text().replace('\n', '\\n')
    sig_pub = (root / 'instance' / 'keys' / 'signing_public.pem').read_text().replace('\n', '\\n')

    prod_db = tmp_path / 'prod_boot.db'
    monkeypatch.setenv('SECRET_KEY', 'prod-secret-key-for-testing-32-chars!!')
    monkeypatch.setenv('DATABASE_URL', f'sqlite:///{prod_db}')
    monkeypatch.setenv('ADMIN_USERNAME', 'rootadmin')
    monkeypatch.setenv('ADMIN_PASSWORD', 'RootAdmin@2026!')
    monkeypatch.setenv('SESSION_COOKIE_SECURE', 'false')
    monkeypatch.setenv('RSA_PRIVATE_KEY_PEM', rsa_priv)
    monkeypatch.setenv('RSA_PUBLIC_KEY_PEM', rsa_pub)
    monkeypatch.setenv('SIGNING_PRIVATE_KEY_PEM', sig_priv)
    monkeypatch.setenv('SIGNING_PUBLIC_KEY_PEM', sig_pub)
    monkeypatch.setenv('RSA_PRIVATE_KEY_PATH', str(tmp_path / 'nonexistent_rsa_priv.pem'))
    monkeypatch.setenv('RSA_PUBLIC_KEY_PATH', str(tmp_path / 'nonexistent_rsa_pub.pem'))
    monkeypatch.setenv('SIGNING_PRIVATE_KEY_PATH', str(tmp_path / 'nonexistent_sig_priv.pem'))
    monkeypatch.setenv('SIGNING_PUBLIC_KEY_PATH', str(tmp_path / 'nonexistent_sig_pub.pem'))

    prod_app = create_app('production')
    prod_app.config['WTF_CSRF_ENABLED'] = False

    # Verify demo hints are hidden on login & register when SHOW_DEMO_HINTS=False
    pc = prod_app.test_client()
    assert b'Seeded Demo Credentials' not in pc.get('/auth/login').data
    assert b'Pre-Approved Roster IDs for Testing' not in pc.get('/auth/register').data

    # Verify env PEM keys work without local key files
    with prod_app.app_context():
        n, ct, tag, aad, wk = encrypt_ballot_hybrid({'candidate_id': 1}, 1, 'env-pem-test')
        dec = decrypt_ballot(n, ct, tag, aad, 1, 'env-pem-test', wrapped_key_hex=wk)
        assert dec['candidate_id'] == 1

        msg = canonical_json({'ok': True})
        sig = sign_document(msg)
        assert verify_document_signature(msg, sig) is True

        # Admin was bootstrapped from env during create_app() -> bootstrap_runtime()
        admin = _db.session.query(User).filter_by(username='rootadmin').first()
        assert admin is not None and admin.is_admin


def test_account_settings_change_username_and_password(client, db, admin_user, voter_user):
    """Authenticated user (admin or voter) can update username and password with verification."""
    # Unauthenticated access redirects to login
    r_anon = client.get('/auth/account')
    assert r_anon.status_code == 302

    # Sign in as admin
    client.post('/auth/login', data={'username': 'testadmin', 'password': 'AdminPass123!'}, follow_redirects=True)
    r_page = client.get('/auth/account')
    assert r_page.status_code == 200
    assert b'Change Username' in r_page.data

    # Wrong current password rejected for username update
    r_bad_pw = client.post('/auth/account/username', data={
        'username': 'newadmin',
        'display_name': 'Chief Admin',
        'current_password': 'WrongPassword!1',
    }, follow_redirects=True)
    assert b'Current password is incorrect' in r_bad_pw.data

    # Duplicate username rejected
    r_dup = client.post('/auth/account/username', data={
        'username': 'testvoter',
        'display_name': 'Chief Admin',
        'current_password': 'AdminPass123!',
    }, follow_redirects=True)
    assert b'already in use' in r_dup.data

    # Valid username + display name update succeeds
    r_upd = client.post('/auth/account/username', data={
        'username': 'Chief_Admin',
        'display_name': 'Chief Admin',
        'current_password': 'AdminPass123!',
    }, follow_redirects=True)
    assert r_upd.status_code == 200
    assert b'Signed in as @chief_admin' in r_upd.data

    # Weak password rejected
    r_weak = client.post('/auth/account/password', data={
        'current_password': 'AdminPass123!',
        'new_password': 'weak',
        'confirm_password': 'weak',
    }, follow_redirects=True)
    assert b'at least 8 characters' in r_weak.data

    # Valid password update succeeds and works on re-login
    r_pw = client.post('/auth/account/password', data={
        'current_password': 'AdminPass123!',
        'new_password': 'NewAdmin@2026!',
        'confirm_password': 'NewAdmin@2026!',
    }, follow_redirects=True)
    assert b'password has been updated cleanly' in r_pw.data

    client.post('/auth/logout', follow_redirects=True)
    assert b'Invalid username or password' in client.post(
        '/auth/login', data={'username': 'chief_admin', 'password': 'AdminPass123!'}, follow_redirects=True
    ).data
    assert b'Election Administration Hub' in client.post(
        '/auth/login', data={'username': 'chief_admin', 'password': 'NewAdmin@2026!'}, follow_redirects=True
    ).data
