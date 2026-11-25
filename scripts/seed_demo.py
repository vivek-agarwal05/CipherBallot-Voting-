#!/usr/bin/env python3
"""
scripts/seed_demo.py — Seed CipherBallot with realistic demo data.

Creates:
  Admin:   username=admin,  password=Admin@Demo123
  Voters:  alice/Voter@Alice1  bob/Voter@Bob123  carol/Voter@Carol1
           dave/Voter@Dave123  eve/Voter@Eve1234
  Elections:
    1. "CS Department Student Council Election 2024" (status=open, all voters eligible)
    2. "Database Systems Course Rep Poll"            (status=draft)
    3. "Security Module Demo Election"               (status=open, isolated)

Safe to run multiple times: skips existing users and elections by username/title.
"""
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Allow running from project root without installing the package
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv
load_dotenv(PROJECT_ROOT / '.env')

from app import create_app
from app.extensions import db
from app.models import (
    Candidate, Election, ElectionEligibility, User, InstitutionalIdentity,
)
from app.security.passwords import hash_password


def get_or_create_user(
    username: str,
    display_name: str,
    password: str,
    role: str,
    student_id: str | None = None,
    department: str | None = None,
) -> User:
    user = db.session.query(User).filter_by(username=username).first()
    if user:
        print(f'   [skip] User already exists: {username}')
        return user
    user = User(
        username=username,
        display_name=display_name,
        password_hash=hash_password(password),
        role=role,
        student_id=student_id,
        department=department,
        id_verified=True,
    )
    db.session.add(user)
    db.session.flush()  # get id before commit
    print(f'   [+] Created user: {username} ({role})')
    return user


def get_or_create_identity(
    student_id: str,
    full_name: str,
    department: str,
    email: str,
    verification_pin: str | None = None,
    is_claimed: bool = False,
    claimed_by_user_id: int | None = None,
) -> InstitutionalIdentity:
    identity = db.session.query(InstitutionalIdentity).filter_by(student_id=student_id).first()
    if identity:
        return identity
    pin_hash = hash_password(verification_pin) if verification_pin else None
    identity = InstitutionalIdentity(
        student_id=student_id,
        full_name=full_name,
        department=department,
        email=email,
        verification_pin_hash=pin_hash,
        is_claimed=is_claimed,
        claimed_by_user_id=claimed_by_user_id,
    )
    db.session.add(identity)
    db.session.flush()
    status_str = "Claimed" if is_claimed else f"Available (PIN: {verification_pin})"
    print(f'   [+] Roster Identity: {student_id} ({full_name}) -> {status_str}')
    return identity


def get_or_create_election(title: str, **kwargs) -> Election:
    election = db.session.query(Election).filter_by(title=title).first()
    if election:
        print(f'   [skip] Election already exists: {title!r}')
        return election
    election = Election(title=title, **kwargs)
    db.session.add(election)
    db.session.flush()
    print(f'   [+] Created election: {title!r} (status={election.status})')
    return election


def add_candidate(election: Election, display_name: str, description: str, order: int) -> None:
    for c in election.candidates:
        if c.display_name == display_name:
            print(f'       [skip] Candidate: {display_name}')
            return
    c = Candidate(
        election_id=election.id,
        display_name=display_name,
        description=description,
        display_order=order,
    )
    db.session.add(c)
    print(f'       [+] Candidate: {display_name}')


def grant_eligibility(election: Election, voter: User) -> None:
    existing = db.session.query(ElectionEligibility).filter_by(
        election_id=election.id, voter_id=voter.id,
    ).first()
    if existing:
        return
    e = ElectionEligibility(
        election_id=election.id,
        voter_id=voter.id,
        status='eligible',
    )
    db.session.add(e)


def main() -> None:
    app = create_app('development')

    with app.app_context():
        db.create_all()

        print('\n📦  Seeding demo data...\n')

        # ------------------------------------------------------------------ #
        # Users & Institutional Identity Registry                            #
        # ------------------------------------------------------------------ #
        print('👤  Users & Institutional Identity Registry')
        admin = get_or_create_user('admin', 'Administrator', 'Admin@Demo123', 'admin')
        alice = get_or_create_user('alice', 'Alice Johnson', 'Voter@Alice1', 'voter', 'STU-CS-2024-001', 'CS Department')
        bob   = get_or_create_user('bob',   'Bob Smith',    'Voter@Bob123',  'voter', 'STU-CS-2024-002', 'CS Department')
        carol = get_or_create_user('carol', 'Carol Davis',  'Voter@Carol1',  'voter', 'STU-CS-2024-003', 'CS Department')
        dave  = get_or_create_user('dave',  'Dave Wilson',  'Voter@Dave123', 'voter', 'STU-CS-2024-004', 'CS Department')
        eve   = get_or_create_user('eve',   'Eve Martinez', 'Voter@Eve1234', 'voter', 'STU-SEC-2024-005', 'Information Security')

        # Link identities for seeded voters (marked claimed)
        get_or_create_identity('STU-CS-2024-001', 'Alice Johnson', 'CS Department', 'alice@univ.edu', is_claimed=True, claimed_by_user_id=alice.id)
        get_or_create_identity('STU-CS-2024-002', 'Bob Smith', 'CS Department', 'bob@univ.edu', is_claimed=True, claimed_by_user_id=bob.id)
        get_or_create_identity('STU-CS-2024-003', 'Carol Davis', 'CS Department', 'carol@univ.edu', is_claimed=True, claimed_by_user_id=carol.id)
        get_or_create_identity('STU-CS-2024-004', 'Dave Wilson', 'CS Department', 'dave@univ.edu', is_claimed=True, claimed_by_user_id=dave.id)
        get_or_create_identity('STU-SEC-2024-005', 'Eve Martinez', 'Information Security', 'eve@univ.edu', is_claimed=True, claimed_by_user_id=eve.id)

        # Pre-approved UNCLAIMED roster for new user registration demonstrations
        print('\n📋  Seeding Pre-Approved Institutional Roster (Available for Live Registration):')
        get_or_create_identity('STU-CS-2024-010', 'Frank Miller', 'CS Department', 'frank.miller@univ.edu', verification_pin='PIN-010', is_claimed=False)
        get_or_create_identity('STU-SEC-2024-011', 'Grace Hopper', 'Information Security', 'grace.hopper@univ.edu', verification_pin='PIN-011', is_claimed=False)
        get_or_create_identity('STU-CS-2024-012', 'Hassan Ali', 'CS Department', 'hassan.ali@univ.edu', verification_pin='PIN-012', is_claimed=False)
        get_or_create_identity('STU-DS-2024-013', 'Isabella Cruz', 'Data Science', 'isabella.cruz@univ.edu', verification_pin='PIN-013', is_claimed=False)

        voters = [alice, bob, carol, dave, eve]

        # ------------------------------------------------------------------ #
        # Election 1 — CS Student Council (open, all voters)                 #
        # ------------------------------------------------------------------ #
        print('\n🗳️   Election 1: CS Student Council (Variant B — AES-GCM + Ed25519)')
        e1 = get_or_create_election(
            title='CS Department Student Council Election 2024',
            description=(
                'Annual election for the Computer Science Department student council. '
                'Demonstrates AES-256-GCM ballot encryption and Ed25519 result signing.'
            ),
            group_dept='CS Department',
            status='open',
            variant='B',
            created_by=admin.id,
        )
        add_candidate(e1, 'Priya Sharma',   'Year 3, focus on student welfare and mental health support.', 0)
        add_candidate(e1, 'James O\'Brien', 'Year 2, focus on academic resources and lab access.', 1)
        add_candidate(e1, 'Mei Lin',        'Year 4, focus on industry partnerships and internships.', 2)

        for voter in voters:
            grant_eligibility(e1, voter)
        print(f'       Granted eligibility to {len(voters)} voter(s).')

        # ------------------------------------------------------------------ #
        # Election 2 — Database Systems (draft)                              #
        # ------------------------------------------------------------------ #
        print('\n🗳️   Election 2: Database Systems Course Rep (draft)')
        e2 = get_or_create_election(
            title='Database Systems Course Rep Poll',
            description=(
                'Poll to elect a student representative for the Database Systems module. '
                'Currently in draft — not yet open for voting.'
            ),
            group_dept='CS Department',
            status='draft',
            variant='B',
            created_by=admin.id,
        )
        add_candidate(e2, 'Sam Okafor',   'Enthusiastic about database performance tuning.', 0)
        add_candidate(e2, 'Lena Fischer', 'Interested in distributed databases and NoSQL.', 1)
        add_candidate(e2, 'Raj Patel',    'Focus on query optimisation and indexing strategies.', 2)

        # Only grant eligibility to alice, bob, carol for this election
        for voter in [alice, bob, carol]:
            grant_eligibility(e2, voter)

        # ------------------------------------------------------------------ #
        # Election 3 — Security Demo (open, isolated)                        #
        # ------------------------------------------------------------------ #
        print('\n🗳️   Election 3: Security Module Demo (isolated open election)')
        e3 = get_or_create_election(
            title='Security Module Demo Election',
            description=(
                'Demo election used in security seminars to illustrate how ballot '
                'encryption prevents vote-linkage even in an educational prototype.'
            ),
            group_dept='Security Module',
            status='open',
            variant='B',
            created_by=admin.id,
        )
        add_candidate(e3, 'Option A: Symmetric Encryption Demo',  'AES-256-GCM with fresh nonces.', 0)
        add_candidate(e3, 'Option B: Asymmetric Encryption Demo', 'RSA-OAEP key encapsulation.', 1)
        add_candidate(e3, 'Option C: Hybrid Scheme Demo',         'ECDH key exchange + AES-GCM.', 2)

        # Only dave and eve are eligible for this one
        for voter in [dave, eve]:
            grant_eligibility(e3, voter)

        # ------------------------------------------------------------------ #
        # Election 4 — Variant A (Single-Class Open Election)                #
        # ------------------------------------------------------------------ #
        print('\n🗳️   Election 4: Single-Class Lab Rep Poll (Variant A — Open Class)')
        e4 = get_or_create_election(
            title='CS-501 Single-Class Lab Representative Poll (Variant A)',
            description=(
                'Variant A demonstration: single-class election open to all active voters '
                'using Hybrid RSA-OAEP + AES-256-GCM encryption without public receipts.'
            ),
            group_dept='CS-501 Class',
            status='open',
            variant='A',
            created_by=admin.id,
        )
        add_candidate(e4, 'Arjun Mehta', 'Morning Lab Coordinator.', 0)
        add_candidate(e4, 'Sofia Rossi', 'Evening Lab Coordinator.', 1)

        # ------------------------------------------------------------------ #
        # Election 5 — Variant C (Privacy-Focused Anonymous Token Election)  #
        # ------------------------------------------------------------------ #
        print('\n🗳️   Election 5: Anonymous Senate Poll (Variant C — Blind-Style Tokens)')
        e5 = get_or_create_election(
            title='Privacy-First Anonymous Senate Poll (Variant C)',
            description=(
                'Variant C demonstration: two-phase anonymous token model separating '
                'identity-linked token issuance from anonymous ballot redemption.'
            ),
            group_dept='CS Department',
            status='open',
            variant='C',
            created_by=admin.id,
        )
        add_candidate(e5, 'Proposal A: Adopt Open-Source Lab Stack', 'Full open-source tooling across labs.', 0)
        add_candidate(e5, 'Proposal B: Hybrid Cloud Sandbox Lab', 'Keep hybrid cloud sandbox access.', 1)
        for voter in voters:
            grant_eligibility(e5, voter)

        # ------------------------------------------------------------------ #
        # Commit                                                              #
        # ------------------------------------------------------------------ #
        db.session.commit()

        print('\n' + '=' * 60)
        print('✅  Demo data seeded successfully.')
        print('=' * 60)
        print('\n🔑  Demo credentials:')
        print('   Admin :  admin        / Admin@Demo123')
        print('   Voter :  alice        / Voter@Alice1')
        print('   Voter :  bob          / Voter@Bob123')
        print('   Voter :  carol        / Voter@Carol1')
        print('   Voter :  dave         / Voter@Dave123')
        print('   Voter :  eve          / Voter@Eve1234')
        print('\n   Run the app (TLS):  python run.py')
        print('   Open:               https://127.0.0.1:5000/')
        print()


if __name__ == '__main__':
    main()
