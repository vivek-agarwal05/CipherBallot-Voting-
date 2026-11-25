from sqlalchemy import inspect
from app.models import (
    AnonymousToken,
    Candidate,
    Election,
    ElectionEligibility,
    EncryptedBallot,
    Participation,
    Receipt,
)
from app.services.voting import (
    cast_vote_atomic,
    cast_vote_with_token,
    check_voter_eligibility,
    issue_anonymous_token,
)
from app.services.tally import tally_election


def test_variant_a_single_class_allows_active_voter_without_roster(app, db, admin_user, voter_user2):
    """Variant A lets any active voter vote without manual ElectionEligibility, prevents duplicates, and issues no public receipt."""
    with app.app_context():
        e = Election(title='Variant A Class Poll', group_dept='CS-501', status='open', variant='A', created_by=admin_user.id)
        db.session.add(e)
        db.session.flush()
        c = Candidate(election_id=e.id, display_name='Option 1', is_active=True, display_order=0)
        db.session.add(c)
        db.session.commit()

        # voter_user2 is NOT in ElectionEligibility, yet eligible in Variant A
        elig = check_voter_eligibility(e.id, voter_user2.id)
        assert elig['eligible'] is True
        assert elig['can_vote'] is True

        ok, receipt_code, err = cast_vote_atomic(e.id, voter_user2.id, c.id)
        assert ok is True, f"Variant A vote failed: {err}"
        assert receipt_code is None

        # Duplicate vote still blocked
        ok2, _, err2 = cast_vote_atomic(e.id, voter_user2.id, c.id)
        assert ok2 is False
        assert 'already voted' in err2.lower() or 'duplicate' in err2.lower()

        # Tally works cleanly with Hybrid decryption
        e.status = 'closed'
        db.session.commit()
        summary, invalid, errors = tally_election(e.id)
        assert invalid == 0
        assert summary['valid_ballots'] == 1


def test_variant_c_two_phase_anonymous_token_protocol(app, db, admin_user, voter_user):
    """Variant C decouples voter identity (Phase 1) from ballot submission (Phase 2) via one-time hashed tokens."""
    with app.app_context():
        # Verify AnonymousToken schema stores no voter_id
        token_cols = [c.key for c in inspect(AnonymousToken).mapper.column_attrs]
        assert 'voter_id' not in token_cols

        e = Election(title='Variant C Senate', group_dept='CS Department', status='open', variant='C', created_by=admin_user.id)
        db.session.add(e)
        db.session.flush()
        c1 = Candidate(election_id=e.id, display_name='Yes', is_active=True, display_order=0)
        c2 = Candidate(election_id=e.id, display_name='No', is_active=True, display_order=1)
        db.session.add_all([c1, c2])
        db.session.add(ElectionEligibility(election_id=e.id, voter_id=voter_user.id, status='eligible'))
        db.session.commit()

        # Phase 1: Claim 1 anonymous token
        ok, raw_token, err = issue_anonymous_token(e.id, voter_user.id)
        assert ok is True, f"Token issuance failed: {err}"
        assert raw_token is not None

        # Requesting a second token for same voter fails
        ok_dup, _, err_dup = issue_anonymous_token(e.id, voter_user.id)
        assert ok_dup is False

        # Phase 2: Redeem token anonymously (no voter_id passed)
        cast_ok, receipt_code, cast_err = cast_vote_with_token(e.id, raw_token, c1.id)
        assert cast_ok is True, f"Anonymous vote failed: {cast_err}"
        assert receipt_code is not None

        # Replay of the spent token MUST be rejected
        replay_ok, _, replay_err = cast_vote_with_token(e.id, raw_token, c2.id)
        assert replay_ok is False
        assert 'already been redeemed' in replay_err.lower()

        # Tally counts anonymous ballot cleanly
        e.status = 'closed'
        db.session.commit()
        summary, invalid, _ = tally_election(e.id)
        assert invalid == 0
        assert summary['valid_ballots'] == 1
        assert summary['candidate_results'][0]['votes'] == 1


def test_security_demo_all_five_experiments_pass(client, db, admin_user, voter_user):
    """Admin Security Demo endpoint executes all 5 CSEG3040 experiments and passes."""
    client.post('/auth/login', data={'username': 'testadmin', 'password': 'AdminPass123!'}, follow_redirects=True)
    resp = client.post('/admin/security-demo/run', headers={'Accept': 'application/json'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['all_passed'] is True
    assert len(data['tests']) == 5
