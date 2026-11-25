import os
import sys
import pytest
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Ensure project root is in python path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

# Ensure test keys exist in instance/keys
keys_dir = ROOT_DIR / 'instance' / 'keys'
keys_dir.mkdir(parents=True, exist_ok=True)

ballot_key_file = keys_dir / 'ballot.key'
if not ballot_key_file.exists():
    ballot_key_file.write_bytes(os.urandom(32))

rsa_priv_file = keys_dir / 'rsa_private.pem'
rsa_pub_file = keys_dir / 'rsa_public.pem'
if not rsa_priv_file.exists() or not rsa_pub_file.exists():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_priv_file.write_bytes(rsa_priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    rsa_pub_file.write_bytes(rsa_priv.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))

priv_key_file = keys_dir / 'signing_private.pem'
pub_key_file = keys_dir / 'signing_public.pem'
if not priv_key_file.exists() or not pub_key_file.exists():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
    priv = Ed25519PrivateKey.generate()
    priv_key_file.write_bytes(priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    pub_key_file.write_bytes(priv.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))

os.environ.setdefault('SECRET_KEY', 'test-secret-key-32-chars-long-testing-purposes!')
os.environ.setdefault('BALLOT_KEY_PATH', str(ballot_key_file))
os.environ.setdefault('RSA_PRIVATE_KEY_PATH', str(rsa_priv_file))
os.environ.setdefault('RSA_PUBLIC_KEY_PATH', str(rsa_pub_file))
os.environ.setdefault('SIGNING_PRIVATE_KEY_PATH', str(priv_key_file))
os.environ.setdefault('SIGNING_PUBLIC_KEY_PATH', str(pub_key_file))

from app import create_app
from app.extensions import db as _db
from app.models import User, Election, Candidate, ElectionEligibility, Participation, InstitutionalIdentity
from app.security.passwords import hash_password


@pytest.fixture(scope='session')
def app():
    test_app = create_app('testing')
    with test_app.app_context():
        _db.create_all()
        yield test_app
        _db.drop_all()


@pytest.fixture(scope='function')
def client(app):
    return app.test_client()


@pytest.fixture(scope='function')
def db(app):
    with app.app_context():
        _db.drop_all()
        _db.create_all()
        yield _db
        _db.session.rollback()


@pytest.fixture
def admin_user(db):
    u = User(
        username='testadmin',
        display_name='Test Admin',
        password_hash=hash_password('AdminPass123!'),
        role='admin',
        is_active=True
    )
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture
def voter_user(db):
    u = User(
        username='testvoter',
        display_name='Test Voter 1',
        password_hash=hash_password('VoterPass123!'),
        role='voter',
        is_active=True
    )
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture
def voter_user2(db):
    u = User(
        username='testvoter2',
        display_name='Test Voter 2',
        password_hash=hash_password('VoterPass123!'),
        role='voter',
        is_active=True
    )
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture
def open_election(db, admin_user):
    now = datetime.now(timezone.utc)
    e = Election(
        title='Open Council Election',
        description='A test election for automated verification',
        group_dept='Computer Science',
        start_dt=now - timedelta(hours=1),
        end_dt=now + timedelta(hours=24),
        status='open',
        variant='B',
        created_by=admin_user.id
    )
    db.session.add(e)
    db.session.flush()

    for idx, name in enumerate(['Alice Candidate', 'Bob Candidate', 'Carol Candidate']):
        c = Candidate(
            election_id=e.id,
            display_name=name,
            description=f'Option {idx+1}',
            is_active=True,
            display_order=idx
        )
        db.session.add(c)
    db.session.commit()
    return e


@pytest.fixture
def eligible_voter_setup(db, voter_user, open_election):
    elig = ElectionEligibility(
        election_id=open_election.id,
        voter_id=voter_user.id,
        status='eligible'
    )
    db.session.add(elig)
    db.session.commit()
    return voter_user, open_election
