import pytest
from app.models import User, InstitutionalIdentity, Election, ElectionEligibility
from app.security.passwords import verify_password, hash_password


def test_registration_success_with_verified_id(client, db):
    """A voter with a valid, unclaimed institutional ID, secret PIN, and strong password registers successfully."""
    admin = User(username='adm', display_name='Admin', password_hash='h', role='admin')
    db.session.add(admin)
    db.session.flush()

    el = Election(title='CS Poll', group_dept='CS Department', created_by=admin.id, status='open')
    db.session.add(el)

    ident = InstitutionalIdentity(
        student_id='STU-CS-2024-099',
        full_name='Devon Vance',
        department='CS Department',
        email='devon@univ.edu',
        verification_pin_hash=hash_password('PIN-099'),
        is_claimed=False
    )
    db.session.add(ident)
    db.session.commit()

    resp = client.post(
        '/auth/register',
        data={
            'student_id': 'STU-CS-2024-099',
            'verification_pin': 'PIN-099',
            'username': 'devon_v',
            'display_name': 'Devon Vance',
            'department': 'CS Department',
            'email': 'devon@univ.edu',
            'password': 'SecurePass!2024',
            'confirm_password': 'SecurePass!2024',
        },
        follow_redirects=True
    )
    assert resp.status_code == 200
    assert b'Student identity successfully verified' in resp.data

    user = db.session.query(User).filter_by(username='devon_v').first()
    assert user is not None
    assert user.display_name == 'Devon Vance'
    assert user.student_id == 'STU-CS-2024-099'
    assert user.department == 'CS Department'
    assert user.id_verified is True
    assert user.password_hash.startswith('$argon2id$')
    assert verify_password(user.password_hash, 'SecurePass!2024') is True

    ident_after = db.session.query(InstitutionalIdentity).filter_by(student_id='STU-CS-2024-099').first()
    assert ident_after.is_claimed is True
    assert ident_after.claimed_by_user_id == user.id

    elig = db.session.query(ElectionEligibility).filter_by(election_id=el.id, voter_id=user.id).first()
    assert elig is not None
    assert elig.status == 'eligible'


def test_registration_rejected_invalid_verification_pin(client, db):
    """Providing another student's ID & name with a wrong verification PIN is rejected (anti-impersonation)."""
    ident = InstitutionalIdentity(
        student_id='STU-CS-2024-050',
        full_name='Devon Vance',
        department='CS Department',
        email='devon50@univ.edu',
        verification_pin_hash=hash_password('SECRET-PIN-50'),
        is_claimed=False
    )
    db.session.add(ident)
    db.session.commit()

    resp = client.post(
        '/auth/register',
        data={
            'student_id': 'STU-CS-2024-050',
            'verification_pin': 'WRONG-PIN',
            'username': 'imposter',
            'display_name': 'Devon Vance',
            'department': 'CS Department',
            'email': 'devon50@univ.edu',
            'password': 'StrongPassword#1',
            'confirm_password': 'StrongPassword#1',
        },
        follow_redirects=True
    )
    assert resp.status_code == 200
    assert b'Invalid Secret Verification PIN' in resp.data
    assert db.session.query(User).filter_by(username='imposter').first() is None


def test_registration_rejected_unverified_id(client, db):
    """Fabricated or unlisted student IDs are rejected by the ID verification check."""
    resp = client.post(
        '/auth/register',
        data={
            'student_id': 'STU-FAKE-999',
            'verification_pin': 'PIN-999',
            'username': 'intruder',
            'display_name': 'Fake Person',
            'department': 'CS Department',
            'email': 'fake@univ.edu',
            'password': 'StrongPassword#1',
            'confirm_password': 'StrongPassword#1',
        },
        follow_redirects=True
    )
    assert resp.status_code == 200
    assert b'ID Verification Failed' in resp.data
    assert db.session.query(User).filter_by(username='intruder').first() is None


def test_registration_rejected_already_claimed_id(client, db, voter_user):
    """A student ID that is already claimed cannot be registered again (anti-Sybil)."""
    ident = InstitutionalIdentity(
        student_id='STU-CLAIMED-100',
        full_name='Test Voter 1',
        department='CS Department',
        email='voter1@univ.edu',
        verification_pin_hash=hash_password('PIN-100'),
        is_claimed=True,
        claimed_by_user_id=voter_user.id
    )
    db.session.add(ident)
    db.session.commit()

    resp = client.post(
        '/auth/register',
        data={
            'student_id': 'STU-CLAIMED-100',
            'verification_pin': 'PIN-100',
            'username': 'duplicate_voter',
            'display_name': 'Test Voter 1',
            'department': 'CS Department',
            'email': 'dup@univ.edu',
            'password': 'StrongPassword#1',
            'confirm_password': 'StrongPassword#1',
        },
        follow_redirects=True
    )
    assert resp.status_code == 200
    assert b'already been claimed and registered' in resp.data
    assert db.session.query(User).filter_by(username='duplicate_voter').first() is None


def test_registration_rejected_department_mismatch(client, db):
    """Registration fails if the student's claimed department differs from institutional record."""
    ident = InstitutionalIdentity(
        student_id='STU-SEC-888',
        full_name='Maya Lin',
        department='Information Security',
        email='maya@univ.edu',
        verification_pin_hash=hash_password('PIN-888'),
        is_claimed=False
    )
    db.session.add(ident)
    db.session.commit()

    resp = client.post(
        '/auth/register',
        data={
            'student_id': 'STU-SEC-888',
            'verification_pin': 'PIN-888',
            'username': 'maya_lin',
            'display_name': 'Maya Lin',
            'department': 'CS Department',
            'email': 'maya@univ.edu',
            'password': 'StrongPassword#1',
            'confirm_password': 'StrongPassword#1',
        },
        follow_redirects=True
    )
    assert resp.status_code == 200
    assert b'Criteria Mismatch' in resp.data
    assert db.session.query(User).filter_by(username='maya_lin').first() is None


def test_registration_rejected_weak_password(client, db):
    """Password complexity criteria (Argon2id requirements: length, uppercase, digit, symbol) are enforced."""
    ident = InstitutionalIdentity(
        student_id='STU-CS-777',
        full_name='Sam Smith',
        department='CS Department',
        email='sam@univ.edu',
        verification_pin_hash=hash_password('PIN-777'),
        is_claimed=False
    )
    db.session.add(ident)
    db.session.commit()

    resp = client.post(
        '/auth/register',
        data={
            'student_id': 'STU-CS-777',
            'verification_pin': 'PIN-777',
            'username': 'sam_s',
            'display_name': 'Sam Smith',
            'department': 'CS Department',
            'email': 'sam@univ.edu',
            'password': 'simplepassword1',
            'confirm_password': 'simplepassword1',
        },
        follow_redirects=True
    )
    assert resp.status_code == 200
    assert b'Password criteria not met' in resp.data
    assert db.session.query(User).filter_by(username='sam_s').first() is None
