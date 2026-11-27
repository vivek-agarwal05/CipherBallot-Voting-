import json
from app.models import (
    AuditEvent,
    Candidate,
    Election,
    ElectionEligibility,
    InstitutionalIdentity,
    User,
)
from app.security.passwords import hash_password
from app.services.voting import cast_vote_atomic, issue_anonymous_token


def test_ballot_cast_audit_does_not_link_voter_to_ballot(app, db, eligible_voter_setup):
    """Identity-linked ballot.cast audit records must never expose ballot_id or receipt_prefix."""
    voter, election = eligible_voter_setup
    with app.app_context():
        candidate = election.candidates[0]
        ok, receipt_code, err = cast_vote_atomic(election.id, voter.id, candidate.id)
        assert ok is True, err
        assert receipt_code is not None

        ev = db.session.query(AuditEvent).filter_by(event_type='ballot.cast').order_by(AuditEvent.id.desc()).first()
        assert ev is not None
        payload = json.loads(ev.safe_payload)
        assert 'ballot_id' not in payload
        assert 'receipt_prefix' not in payload
        assert payload.get('participation_recorded') is True


def test_anonymous_cast_portal_works_while_logged_in_as_admin(app, client, db, admin_user, voter_user):
    """Variant C /anonymous-cast/<id> must submit to public.anonymous_cast even when admin is logged in."""
    with app.app_context():
        e = Election(title='Variant C Demo', group_dept='CS', status='open', variant='C', created_by=admin_user.id)
        db.session.add(e)
        db.session.flush()
        c = Candidate(election_id=e.id, display_name='Proposal 1', is_active=True, display_order=0)
        db.session.add(c)
        db.session.add(ElectionEligibility(election_id=e.id, voter_id=voter_user.id, status='eligible'))
        db.session.commit()
        _, raw_token, _ = issue_anonymous_token(e.id, voter_user.id)
        eid, cid = e.id, c.id

    client.post('/auth/login', data={'username': 'testadmin', 'password': 'AdminPass123!'}, follow_redirects=True)
    get_resp = client.get(f'/anonymous-cast/{eid}')
    assert get_resp.status_code == 200
    assert f'action="/anonymous-cast/{eid}"'.encode() in get_resp.data

    post_resp = client.post(
        f'/anonymous-cast/{eid}',
        data={'action': 'cast_with_token', 'anonymous_token': raw_token, 'candidate_id': str(cid)},
        follow_redirects=True,
    )
    assert post_resp.status_code == 200
    assert b'DIGEST VERIFIED INTACT' in post_resp.data


def test_deactivate_candidate_blocked_after_draft(client, db, admin_user, open_election):
    """Candidate status cannot be toggled once an election leaves Draft."""
    client.post('/auth/login', data={'username': 'testadmin', 'password': 'AdminPass123!'}, follow_redirects=True)
    cand = open_election.candidates[0]
    resp = client.post(
        f'/admin/elections/{open_election.id}/candidates/{cand.id}/deactivate',
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b'only be modified while the election is in Draft' in resp.data
    refreshed = db.session.get(Candidate, cand.id)
    assert refreshed.is_active is True


def test_admin_duplicate_email_in_registry_handled_cleanly(client, db, admin_user):
    """Duplicate institutional email in /admin/registry/add flashes a warning instead of raising IntegrityError."""
    db.session.add(InstitutionalIdentity(
        student_id='STU-CS-2024-301',
        full_name='First Student',
        department='CS Department',
        email='shared@univ.edu',
        verification_pin_hash=hash_password('PIN-301'),
    ))
    db.session.commit()

    client.post('/auth/login', data={'username': 'testadmin', 'password': 'AdminPass123!'}, follow_redirects=True)
    resp = client.post(
        '/admin/registry/add',
        data={
            'student_id': 'STU-CS-2024-302',
            'full_name': 'Second Student',
            'department': 'CS Department',
            'email': 'shared@univ.edu',
            'verification_pin': 'PIN-302',
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b'already assigned to another student record' in resp.data
    assert db.session.query(InstitutionalIdentity).filter_by(student_id='STU-CS-2024-302').first() is None


def test_login_supports_mixed_case_username_and_student_id(client, db):
    """Registered users can sign in with mixed-case username or their Student ID."""
    db.session.add(InstitutionalIdentity(
        student_id='STU-CS-2024-401',
        full_name='Frank Miller',
        department='CS Department',
        email='frank401@univ.edu',
        verification_pin_hash=hash_password('PIN-401'),
    ))
    db.session.commit()

    reg_resp = client.post(
        '/auth/register',
        data={
            'student_id': 'STU-CS-2024-401',
            'verification_pin': 'PIN-401',
            'username': 'FrankM',
            'display_name': 'Frank Miller',
            'department': 'CS Department',
            'email': 'frank401@univ.edu',
            'password': 'StrongPassword!1',
            'confirm_password': 'StrongPassword!1',
        },
        follow_redirects=True,
    )
    assert reg_resp.status_code == 200
    assert b'successfully verified' in reg_resp.data

    # Mixed-case username login
    r1 = client.post('/auth/login', data={'username': 'FrankM', 'password': 'StrongPassword!1'}, follow_redirects=True)
    assert b'Hello, Frank Miller' in r1.data
    client.post('/auth/logout', follow_redirects=True)

    # Student ID login
    r2 = client.post('/auth/login', data={'username': 'STU-CS-2024-401', 'password': 'StrongPassword!1'}, follow_redirects=True)
    assert b'Hello, Frank Miller' in r2.data


def test_admin_eligibility_student_id_lookup_and_redirect(client, db, admin_user, open_election):
    """Admin eligibility lookup accepts Student ID and toggling redirects back to eligibility page."""
    voter = User(
        username='stud_lookup',
        display_name='Student Lookup',
        password_hash=hash_password('VoterPass123!'),
        role='voter',
        student_id='STU-CS-2024-501',
        is_active=True,
    )
    db.session.add(voter)
    db.session.commit()

    client.post('/auth/login', data={'username': 'testadmin', 'password': 'AdminPass123!'}, follow_redirects=True)

    r_add = client.post(
        f'/admin/elections/{open_election.id}/eligibility/add',
        data={'username': 'STU-CS-2024-501'},
        follow_redirects=True,
    )
    assert r_add.status_code == 200
    assert b'granted eligibility' in r_add.data

    r_tog = client.post(
        f'/admin/elections/{open_election.id}/edit',
        data={'action': 'toggle_eligibility', 'next': 'eligibility', 'voter_id': str(voter.id)},
        follow_redirects=False,
    )
    assert r_tog.status_code == 302
    assert r_tog.headers['Location'].endswith(f'/admin/elections/{open_election.id}/eligibility')


def test_security_demo_isolated_when_user_demo_election_closed(client, db, admin_user, voter_user):
    """Closing 'Security Module Demo Election' must not break /admin/security-demo/run."""
    e3 = Election(
        title='Security Module Demo Election',
        group_dept='Security Module',
        status='closed',
        variant='B',
        created_by=admin_user.id,
    )
    db.session.add(e3)
    db.session.flush()
    db.session.add(Candidate(election_id=e3.id, display_name='Option 1', is_active=True, display_order=0))
    db.session.commit()

    client.post('/auth/login', data={'username': 'testadmin', 'password': 'AdminPass123!'}, follow_redirects=True)
    resp = client.post('/admin/security-demo/run', headers={'Accept': 'application/json'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['all_passed'] is True
    assert db.session.get(Election, e3.id).status == 'closed'


def test_validation_and_public_boundaries(client, db, admin_user, open_election):
    """Blank election titles are rejected, audit negative pages are clamped, and draft/missing bulletin boards 404."""
    draft = Election(title='Hidden Draft', status='draft', variant='B', created_by=admin_user.id)
    db.session.add(draft)
    db.session.commit()

    assert client.get(f'/bulletin-board/{draft.id}').status_code == 404
    assert client.get('/bulletin-board/99999').status_code == 404

    client.post('/auth/login', data={'username': 'testadmin', 'password': 'AdminPass123!'}, follow_redirects=True)
    client.post(f'/admin/elections/{open_election.id}/edit', data={'action': 'update_details', 'title': '   '})
    assert db.session.get(Election, open_election.id).title == 'Open Council Election'
    assert client.get('/admin/audit?page=-1').status_code == 200
