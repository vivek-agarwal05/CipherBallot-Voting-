"""
app/services/elections.py — Election querying, lifecycle, and voter view services.
"""
from datetime import datetime, timezone
from ..extensions import db
from ..models import (
    Election, Candidate, ElectionEligibility,
    Participation, EncryptedBallot, Receipt, User
)
from .voting import check_voter_eligibility


def list_voter_elections(voter_id: int) -> list[dict]:
    """
    Get all elections with personalized status for the voter.
    """
    all_elections = db.session.query(Election).order_by(Election.created_at.desc()).all()
    results = []

    for election in all_elections:
        status_info = check_voter_eligibility(election.id, voter_id)
        results.append({
            'election': election,
            'status_info': status_info,
            'is_eligible': status_info['eligible'],
            'already_voted': status_info['already_voted'],
            'can_vote': status_info['can_vote'],
            'status_label': status_info['status_label'],
            'reason': status_info['reason']
        })
    return results


def get_election_summary(election_id: int) -> dict:
    """
    Get admin summary statistics for an election.
    """
    election = db.session.get(Election, election_id)
    if not election:
        return {}

    if (election.variant or 'B').upper() == 'A':
        total_eligible = db.session.query(User).filter_by(
            role='voter', is_active=True
        ).count()
    else:
        total_eligible = db.session.query(ElectionEligibility).filter_by(
            election_id=election_id, status='eligible'
        ).count()

    total_voted = db.session.query(Participation).filter_by(
        election_id=election_id
    ).count()

    total_ballots = db.session.query(EncryptedBallot).filter_by(
        election_id=election_id
    ).count()

    cast_count = total_ballots if (election.variant or 'B').upper() == 'C' else total_voted
    turnout_pct = round((cast_count / total_eligible * 100), 1) if total_eligible > 0 else 0.0

    return {
        'election': election,
        'total_eligible': total_eligible,
        'total_voted': total_voted,
        'total_ballots': total_ballots,
        'turnout_pct': turnout_pct,
        'candidate_count': len(election.candidates)
    }
