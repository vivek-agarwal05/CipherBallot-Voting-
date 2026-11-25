from app.services.voting import cast_vote_atomic, check_voter_eligibility
from app.models import EncryptedBallot, Participation


def test_duplicate_vote_blocked_at_service_and_db(app, db, eligible_voter_setup):
    """
    Submitting two votes for the same voter in the same election MUST be rejected
    atomically by the unique database constraint and service logic.
    """
    voter, election = eligible_voter_setup
    with app.app_context():
        candidate = election.candidates[0]

        # 1. First vote must succeed
        s1, r1, err1 = cast_vote_atomic(election.id, voter.id, candidate.id)
        assert s1 is True, f"First vote failed: {err1}"
        assert r1 is not None

        # Verify ballot and participation exist
        ballot_count = db.session.query(EncryptedBallot).filter_by(election_id=election.id).count()
        assert ballot_count == 1
        part_count = db.session.query(Participation).filter_by(election_id=election.id, voter_id=voter.id).count()
        assert part_count == 1

        # Check eligibility now reflects 'already_voted'
        check = check_voter_eligibility(election.id, voter.id)
        assert check['can_vote'] is False
        assert check['already_voted'] is True

        # 2. Second vote attempt MUST be rejected
        s2, r2, err2 = cast_vote_atomic(election.id, voter.id, candidate.id)
        assert s2 is False, "Second vote should have been rejected!"
        assert r2 is None
        assert 'already voted' in err2.lower() or 'duplicate' in err2.lower()

        # Database must still only have 1 ballot and 1 participation
        assert db.session.query(EncryptedBallot).filter_by(election_id=election.id).count() == 1
        assert db.session.query(Participation).filter_by(election_id=election.id, voter_id=voter.id).count() == 1
