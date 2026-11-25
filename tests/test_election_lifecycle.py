from datetime import datetime, timezone, timedelta
from app.models import Election, Candidate, ElectionEligibility
from app.services.voting import cast_vote_atomic
from app.services.tally import tally_election, publish_election_results


def test_cannot_vote_in_closed_election(app, db, voter_user):
    """Voting while an election is closed is blocked."""
    with app.app_context():
        now = datetime.now(timezone.utc)
        e = Election(
            title='Closed Poll',
            status='closed',
            variant='B',
            created_by=voter_user.id
        )
        db.session.add(e)
        db.session.flush()
        c = Candidate(election_id=e.id, display_name='Candidate A', is_active=True, display_order=0)
        elig = ElectionEligibility(election_id=e.id, voter_id=voter_user.id, status='eligible')
        db.session.add_all([c, elig])
        db.session.commit()

        success, receipt, err = cast_vote_atomic(e.id, voter_user.id, c.id)
        assert success is False
        assert 'closed' in err.lower()


def test_results_cannot_be_tallied_while_election_open(app, db, open_election):
    """Results cannot be tallied while an election is still open."""
    with app.app_context():
        assert open_election.status == 'open'
        summary, invalid_count, errors = tally_election(open_election.id)
        assert summary is None
        assert 'only permitted on \'closed\'' in errors[0]


def test_tallying_and_publishing_closed_election(app, db, eligible_voter_setup):
    """Closing an election allows tallying, AES-GCM decryption, and Ed25519 signing."""
    voter, election = eligible_voter_setup
    with app.app_context():
        # Cast a vote
        candidate = election.candidates[0]
        s, r, err = cast_vote_atomic(election.id, voter.id, candidate.id)
        assert s is True, f"Vote failed: {err}"

        # Close election in fresh session query
        el = db.session.get(Election, election.id)
        el.status = 'closed'
        db.session.commit()

        # Tally
        summary, invalid, errors = tally_election(el.id)
        assert summary is not None, f"Tally failed with errors: {errors}"
        assert invalid == 0
        assert summary['valid_ballots'] == 1
        assert summary['candidate_results'][0]['votes'] == 1

        # Publish results
        pub_ok, pub_err = publish_election_results(el.id, 'admin')
        assert pub_ok is True
        assert el.status == 'published'
        assert el.published_result is not None
        assert len(el.published_result.signature_hex) == 128
