from app.security.passwords import hash_password, verify_password


def test_password_hash_verify_success(app):
    """Argon2id hashing correctly verifies matching passwords."""
    raw_pwd = 'StrongPassword!2024'
    h = hash_password(raw_pwd)
    assert h.startswith('$argon2id$')
    assert verify_password(h, raw_pwd) is True


def test_password_hash_wrong_password_fails(app):
    """Argon2id hashing rejects non-matching passwords."""
    raw_pwd = 'CorrectPassword#1'
    h = hash_password(raw_pwd)
    assert verify_password(h, 'WrongPassword#9') is False


def test_login_valid_credentials(client, db, voter_user):
    """Authenticated user successfully logs in."""
    resp = client.post(
        '/auth/login',
        data={'username': 'testvoter', 'password': 'VoterPass123!'},
        follow_redirects=True
    )
    assert resp.status_code == 200
    assert b'testvoter' in resp.data or b'Sign Out' in resp.data


def test_login_invalid_credentials_generic_message(client, db, voter_user):
    """Invalid credentials yield a generic message without leaking username existence."""
    resp = client.post(
        '/auth/login',
        data={'username': 'testvoter', 'password': 'WrongPassword999'},
        follow_redirects=True
    )
    assert resp.status_code == 200
    assert b'Invalid username or password' in resp.data


def test_unauthenticated_access_blocked(client, db):
    """Unauthenticated users cannot access protected voter or admin pages."""
    resp = client.get('/voter/')
    assert resp.status_code in (302, 401)
    
    resp_admin = client.get('/admin/')
    assert resp_admin.status_code in (302, 401)


def test_voter_cannot_access_admin_routes(client, db, voter_user):
    """Role-based access control: a student voter cannot access admin routes."""
    # Log in as voter
    client.post(
        '/auth/login',
        data={'username': 'testvoter', 'password': 'VoterPass123!'},
        follow_redirects=True
    )
    resp = client.get('/admin/')
    assert resp.status_code == 403


def test_account_lockout_after_repeated_failures(client, db, voter_user):
    """Consecutive failed logins trigger temporary account lockout and block even valid passwords during the window."""
    # Make 5 consecutive wrong-password attempts
    for _ in range(5):
        client.post(
            '/auth/login',
            data={'username': 'testvoter', 'password': 'WrongPassword!1'},
            follow_redirects=True
        )

    # 6th attempt using the CORRECT password must still be blocked while locked out
    resp = client.post(
        '/auth/login',
        data={'username': 'testvoter', 'password': 'VoterPass123!'},
        follow_redirects=True
    )
    assert resp.status_code == 200
    assert b'temporarily locked' in resp.data.lower()
