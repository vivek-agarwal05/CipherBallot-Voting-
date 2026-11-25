from app.services.voting import check_voter_eligibility, cast_vote_atomic
from app.models import EncryptedBallot


def test_ineligible_voter_cannot_vote(app, db, voter_user2, open_election):
    """A voter who is not on the eligibility roster cannot cast a ballot."""
    with app.app_context():
        # voter_user2 is NOT in ElectionEligibility
        elig = check_voter_eligibility(open_election.id, voter_user2.id)
        assert elig['can_vote'] is False
        assert elig['eligible'] is False

        candidate = open_election.candidates[0]
        success, receipt_code, err = cast_vote_atomic(open_election.id, voter_user2.id, candidate.id)
        assert success is False
        assert receipt_code is None
        assert 'not on the eligibility roster' in err.lower() or 'not eligible' in err.lower()

        # Ensure no ballot was stored
        count = db.session.query(EncryptedBallot).filter_by(election_id=open_election.id).count()
        assert count == 0


def test_eligible_voter_can_vote(app, db, eligible_voter_setup):
    """An eligible voter with an open election can cast a ballot."""
    voter, election = eligible_voter_setup
    with app.app_context():
        elig = check_voter_eligibility(election.id, voter.id)
        assert elig['can_vote'] is True
        assert elig['eligible'] is True
