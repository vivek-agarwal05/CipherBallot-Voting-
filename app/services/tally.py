"""
app/services/tally.py — Election tallying, decryption verification, and Ed25519 signing.
"""
import json
import logging
from datetime import datetime, timezone

from ..extensions import db
from ..models import (
    Election, Candidate, ElectionEligibility,
    EncryptedBallot, Participation, PublishedResult, User
)
from ..security.ballots import decrypt_ballot
from ..security.canonical import canonical_json
from ..security.signatures import sign_document, verify_document_signature, get_public_key_hex
from ..security.audit import append_audit_event

logger = logging.getLogger(__name__)


def tally_election(election_id: int) -> tuple[dict | None, int, list[str]]:
    """
    Decrypt all ballots for an election, count votes per candidate,
    and detect any invalid or tampered ballots.
    
    Returns:
        (result_summary: dict | None, invalid_count: int, errors: list[str])
    """
    election = db.session.get(Election, election_id)
    if not election:
        return None, 0, ["Election not found."]

    if election.status not in ('closed', 'published'):
        return None, 0, [f"Election status is '{election.status}'. Tallying is only permitted on 'closed' or 'published' elections."]

    ballots = db.session.query(EncryptedBallot).filter_by(election_id=election_id).all()
    candidates = {c.id: c for c in election.candidates}

    tally_counts = {c.id: 0 for c in election.candidates}
    invalid_ballots = []
    errors = []
    valid_count = 0

    for ballot in ballots:
        try:
            payload = decrypt_ballot(
                nonce_hex=ballot.nonce_hex,
                ciphertext_hex=ballot.ciphertext_hex,
                tag_hex=ballot.tag_hex,
                aad_hex=ballot.aad_hex,
                election_id=election_id,
                ballot_id=ballot.id,
                wrapped_key_hex=ballot.wrapped_key_hex,
            )
            cid = payload.get('candidate_id')
            if cid in candidates:
                tally_counts[cid] += 1
                valid_count += 1
            else:
                invalid_ballots.append(ballot.id)
                errors.append(f"Ballot {ballot.id[:8]}... contains invalid candidate_id: {cid}")
        except Exception as exc:
            invalid_ballots.append(ballot.id)
            errors.append(f"Ballot {ballot.id[:8]}... failed AES-GCM authentication/decryption: {str(exc)}")

    if (election.variant or 'B').upper() == 'A':
        total_eligible = db.session.query(User).filter_by(
            role='voter', is_active=True
        ).count()
    else:
        total_eligible = db.session.query(ElectionEligibility).filter_by(
            election_id=election_id, status='eligible'
        ).count()
    
    total_participated = db.session.query(Participation).filter_by(
        election_id=election_id
    ).count()

    candidate_results = []
    for c in election.candidates:
        candidate_results.append({
            'candidate_id': c.id,
            'display_name': c.display_name,
            'description': c.description or '',
            'votes': tally_counts[c.id],
            'vote_percentage': round((tally_counts[c.id] / valid_count * 100), 1) if valid_count > 0 else 0.0
        })

    # Sort descending by votes
    candidate_results.sort(key=lambda x: x['votes'], reverse=True)

    summary = {
        'election_id': election.id,
        'election_title': election.title,
        'variant': election.variant,
        'total_eligible': total_eligible,
        'total_participated': total_participated,
        'total_ballots_stored': len(ballots),
        'valid_ballots': valid_count,
        'invalid_ballots': len(invalid_ballots),
        'turnout_percentage': round((total_participated / total_eligible * 100), 1) if total_eligible > 0 else 0.0,
        'candidate_results': candidate_results,
        'tallied_at': datetime.now(timezone.utc).isoformat()
    }

    return summary, len(invalid_ballots), errors


def publish_election_results(election_id: int, admin_username: str) -> tuple[bool, str | None]:
    """
    Tally votes, produce canonical JSON, sign with Ed25519, and publish.
    """
    election = db.session.get(Election, election_id)
    if not election:
        return False, "Election not found."

    if election.status != 'closed':
        return False, "Election must be closed before publishing results."

    summary, invalid_count, errors = tally_election(election_id)
    if summary is None:
        return False, "; ".join(errors)

    # Convert to canonical bytes for Ed25519 signing
    canonical_bytes = canonical_json(summary)
    try:
        signature_hex = sign_document(canonical_bytes)
        pub_key_id = get_public_key_hex()[:32]
    except Exception as exc:
        return False, f"Signing error: {str(exc)}"

    # Store PublishedResult
    pub_res = db.session.query(PublishedResult).filter_by(election_id=election_id).first()
    if not pub_res:
        pub_res = PublishedResult(
            election_id=election_id,
            result_json=json.dumps(summary, sort_keys=True),
            signature_hex=signature_hex,
            public_key_id=pub_key_id
        )
        db.session.add(pub_res)
    else:
        pub_res.result_json = json.dumps(summary, sort_keys=True)
        pub_res.signature_hex = signature_hex
        pub_res.public_key_id = pub_key_id
        pub_res.published_at = datetime.now(timezone.utc)

    election.status = 'published'
    db.session.commit()

    append_audit_event(
        event_type='result.published',
        actor_category='admin',
        actor_ref=admin_username,
        payload={
            'election_id': election_id,
            'valid_ballots': summary['valid_ballots'],
            'invalid_ballots': summary['invalid_ballots'],
            'signature_prefix': signature_hex[:16] + '...',
            'public_key_id': pub_key_id
        }
    )

    return True, None
