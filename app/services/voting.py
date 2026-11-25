"""
app/services/voting.py — Multi-variant atomic voting service (Variants A, B, and C).

Supports all three Problem #28 architectural variants:
  - Variant A: Single-class election with hybrid RSA-OAEP + AES-256-GCM encrypted ballots.
               Any active voter account can cast 1 vote (no manual roster needed; no public receipt).
  - Variant B: Department poll with explicit voter eligibility roster, hybrid encrypted ballots,
               SHA-256 verifiable receipts, and Ed25519 signed results.
  - Variant C: Privacy-focused two-phase anonymous token model vs. identity-linked audit records:
               Phase 1 verifies eligibility, marks Participation ('token_issued'), and issues an
               unlinked 256-bit anonymous voting token (only SHA-256(token) stored).
               Phase 2 redeems that token anonymously with zero voter_id attached.
"""
import hashlib
import logging
import secrets
import uuid
from datetime import datetime, timezone

from sqlalchemy.exc import IntegrityError

from ..extensions import db
from ..models import (
    AnonymousToken,
    Candidate,
    Election,
    ElectionEligibility,
    EncryptedBallot,
    Participation,
    Receipt,
    User,
)
from ..security.audit import append_audit_event
from ..security.ballots import (
    compute_ballot_digest,
    encrypt_ballot_hybrid,
    generate_receipt_code,
)

logger = logging.getLogger(__name__)


def _check_election_timing(election: Election) -> tuple[bool, bool]:
    """Return (is_open, is_expired) normalizing naive/aware timestamps."""
    now = datetime.now(timezone.utc)
    is_open = election.status == 'open'

    election_start = election.start_dt
    if election_start and election_start.tzinfo is None:
        election_start = election_start.replace(tzinfo=timezone.utc)

    election_end = election.end_dt
    if election_end and election_end.tzinfo is None:
        election_end = election_end.replace(tzinfo=timezone.utc)

    if election_start and now < election_start:
        is_open = False
    is_expired = bool(election_end and now > election_end)
    if is_expired:
        is_open = False
    return is_open, is_expired


def check_voter_eligibility(election_id: int, voter_id: int) -> dict:
    """
    Check voter eligibility and participation status according to election.variant (A, B, or C).
    """
    election = db.session.get(Election, election_id)
    if not election:
        return {
            'eligible': False,
            'already_voted': False,
            'election_open': False,
            'status_label': 'Not Found',
            'can_vote': False,
            'reason': 'Election not found.',
        }

    is_open, is_expired = _check_election_timing(election)

    part = db.session.query(Participation).filter_by(
        election_id=election_id, voter_id=voter_id
    ).first()
    already_voted = part is not None

    variant = (election.variant or 'B').upper()
    if variant == 'A':
        voter = db.session.get(User, voter_id)
        is_eligible = bool(voter and voter.role == 'voter' and voter.is_active)
    else:
        elig = db.session.query(ElectionEligibility).filter_by(
            election_id=election_id, voter_id=voter_id, status='eligible'
        ).first()
        is_eligible = elig is not None

    if already_voted:
        status_label = 'Token Issued' if (variant == 'C' and part.status == 'token_issued') else 'Already Voted'
        can_vote = False
        reason = (
            'Your anonymous voting token was already issued for this election. '
            'Use Phase 2 (Anonymous Ballot Box) to cast your ballot anonymously.'
            if variant == 'C'
            else 'You have already voted in this election.'
        )
    elif not is_eligible:
        status_label = 'Not Eligible'
        can_vote = False
        reason = 'You are not on the eligibility roster for this election.'
    elif election.status == 'draft':
        status_label = 'Election Draft'
        can_vote = False
        reason = 'This election is not open yet.'
    elif election.status in ('closed', 'published') or is_expired:
        status_label = 'Election Closed'
        can_vote = False
        reason = 'This election has closed.'
    elif not is_open:
        status_label = 'Election Not Open'
        can_vote = False
        reason = 'Voting period is not currently active.'
    else:
        status_label = 'Eligible'
        can_vote = True
        reason = (
            'Eligible for Variant C anonymous token issuance.'
            if variant == 'C'
            else 'You are eligible to vote.'
        )

    return {
        'eligible': is_eligible,
        'already_voted': already_voted,
        'election_open': is_open,
        'status_label': status_label,
        'can_vote': can_vote,
        'reason': reason,
    }


def cast_vote_atomic(election_id: int, voter_id: int, candidate_id: int) -> tuple[bool, str | None, str | None]:
    """
    Atomically cast a hybrid-encrypted ballot for Variant A or Variant B elections.

    - Variant A (Single-Class): Hybrid RSA-OAEP + AES-256-GCM ballot + Participation (no receipt code).
    - Variant B (Department Poll): Hybrid RSA-OAEP + AES-256-GCM ballot + Participation + Verifiable Receipt.
    """
    election = db.session.get(Election, election_id)
    if not election:
        return False, None, 'Election not found.'

    variant = (election.variant or 'B').upper()
    if variant == 'C':
        return False, None, 'Variant C elections use two-phase anonymous tokens. Claim a token first and submit via the anonymous ballot box.'

    elig_check = check_voter_eligibility(election_id, voter_id)
    if not elig_check['can_vote']:
        return False, None, elig_check['reason']

    candidate = db.session.get(Candidate, candidate_id)
    if not candidate or candidate.election_id != election_id or not candidate.is_active:
        return False, None, 'Invalid candidate selection.'

    voter = db.session.get(User, voter_id)
    username = voter.username if voter else f'voter_{voter_id}'

    ballot_id = str(uuid.uuid4())
    ballot_payload = {
        'candidate_id': candidate_id,
        'election_id': election_id,
        'variant': variant,
        'timestamp': datetime.now(timezone.utc).isoformat(),
    }

    try:
        nonce_hex, ciphertext_hex, tag_hex, aad_hex, wrapped_key_hex = encrypt_ballot_hybrid(
            ballot_payload=ballot_payload,
            election_id=election_id,
            ballot_id=ballot_id,
        )
    except Exception as exc:
        logger.error("Hybrid encryption failed for election %s: %s", election_id, exc)
        return False, None, f"Ballot encryption failed: {str(exc)}"

    receipt_code: str | None = None
    if variant == 'B':
        receipt_code = generate_receipt_code()
        digest = compute_ballot_digest(
            election_id=election_id,
            ballot_id=ballot_id,
            nonce_hex=nonce_hex,
            ciphertext_hex=ciphertext_hex,
            tag_hex=tag_hex,
            wrapped_key_hex=wrapped_key_hex,
        )

    try:
        ballot = EncryptedBallot(
            id=ballot_id,
            election_id=election_id,
            nonce_hex=nonce_hex,
            ciphertext_hex=ciphertext_hex,
            tag_hex=tag_hex,
            aad_hex=aad_hex,
            wrapped_key_hex=wrapped_key_hex,
            algorithm='RSA-OAEP+AES-256-GCM',
            version=2,
        )
        db.session.add(ballot)

        participation = Participation(
            election_id=election_id,
            voter_id=voter_id,
            status='voted',
        )
        db.session.add(participation)

        if variant == 'B' and receipt_code is not None:
            receipt = Receipt(
                receipt_code=receipt_code,
                election_id=election_id,
                ballot_id=ballot_id,
                ballot_digest_hex=digest,
            )
            db.session.add(receipt)

        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        logger.warning("Duplicate vote or constraint violation for voter %s on election %s: %s", voter_id, election_id, exc)
        append_audit_event(
            event_type='vote.rejected_duplicate',
            actor_category='voter',
            actor_ref=username,
            payload={
                'election_id': election_id,
                'reason': 'Duplicate vote attempt caught by database uniqueness constraint',
            },
        )
        return False, None, 'Duplicate vote detected — second submission rejected.'
    except Exception as exc:
        db.session.rollback()
        logger.error("Transaction failed during vote casting: %s", exc)
        return False, None, f"Vote casting failed: {str(exc)}"

    append_audit_event(
        event_type='ballot.cast',
        actor_category='voter',
        actor_ref=username,
        payload={
            'election_id': election_id,
            'variant': variant,
            'ballot_id': ballot_id,
            'receipt_prefix': (receipt_code[:8] + '...') if receipt_code else 'none (Variant A)',
            'algorithm': 'RSA-OAEP+AES-256-GCM',
        },
    )

    return True, receipt_code, None


# ---------------------------------------------------------------------------
# Variant C: Two-Phase Anonymous Voting Token Protocol
# ---------------------------------------------------------------------------

def issue_anonymous_token(election_id: int, voter_id: int) -> tuple[bool, str | None, str | None]:
    """
    Variant C Phase 1 (Identity-Linked Issuance):
      1. Verify voter is eligible and has not already claimed a token.
      2. Generate a random 256-bit anonymous token.
      3. Atomically record Participation(status='token_issued') AND store ONLY
         SHA-256(token) in AnonymousToken (zero voter_id link).
    """
    election = db.session.get(Election, election_id)
    if not election:
        return False, None, 'Election not found.'
    if (election.variant or 'B').upper() != 'C':
        return False, None, 'Anonymous token issuance is only supported for Variant C elections.'

    elig_check = check_voter_eligibility(election_id, voter_id)
    if not elig_check['can_vote']:
        return False, None, elig_check['reason']

    voter = db.session.get(User, voter_id)
    username = voter.username if voter else f'voter_{voter_id}'

    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode('utf-8')).hexdigest()

    try:
        participation = Participation(
            election_id=election_id,
            voter_id=voter_id,
            status='token_issued',
        )
        db.session.add(participation)

        anon_token = AnonymousToken(
            election_id=election_id,
            token_hash=token_hash,
            is_spent=False,
        )
        db.session.add(anon_token)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        append_audit_event(
            event_type='token.rejected_duplicate',
            actor_category='voter',
            actor_ref=username,
            payload={'election_id': election_id, 'reason': 'Voter already claimed anonymous token'},
        )
        return False, None, 'Duplicate token request rejected — you have already claimed a token for this election.'
    except Exception as exc:
        db.session.rollback()
        return False, None, f'Token issuance failed: {str(exc)}'

    # Identity-linked audit log (records who got a token, never which token)
    append_audit_event(
        event_type='token.issued',
        actor_category='voter',
        actor_ref=username,
        payload={
            'election_id': election_id,
            'variant': 'C',
            'note': 'Identity verified; unlinked anonymous token issued',
        },
    )

    return True, raw_token, None


def cast_vote_with_token(election_id: int, raw_token: str, candidate_id: int) -> tuple[bool, str | None, str | None]:
    """
    Variant C Phase 2 (Unlinked Anonymous Redemption):
      Accepts NO voter_id! Verifies SHA-256(raw_token) exists and is unspent,
      marks it spent atomically with EncryptedBallot + Receipt, and emits an
      anonymous audit record with zero voter identity.
    """
    election = db.session.get(Election, election_id)
    if not election:
        return False, None, 'Election not found.'
    if (election.variant or 'B').upper() != 'C':
        return False, None, 'Anonymous token redemption is only valid for Variant C elections.'

    is_open, is_expired = _check_election_timing(election)
    if election.status != 'open' or is_expired or not is_open:
        return False, None, 'This election is not currently open for voting.'

    clean_token = (raw_token or '').strip()
    if not clean_token:
        return False, None, 'An anonymous voting token is required.'

    token_hash = hashlib.sha256(clean_token.encode('utf-8')).hexdigest()
    token_rec = db.session.query(AnonymousToken).filter_by(
        election_id=election_id,
        token_hash=token_hash,
    ).first()

    if not token_rec:
        append_audit_event(
            event_type='vote.rejected_invalid_token',
            actor_category='anonymous',
            actor_ref='unknown_token',
            payload={'election_id': election_id, 'reason': 'Unrecognized anonymous token'},
        )
        return False, None, 'Invalid anonymous voting token for this election.'

    if token_rec.is_spent:
        append_audit_event(
            event_type='vote.rejected_spent_token',
            actor_category='anonymous',
            actor_ref='token_holder',
            payload={
                'election_id': election_id,
                'token_hash_prefix': token_hash[:12] + '...',
                'reason': 'Replay / double-spend of anonymous token rejected',
            },
        )
        return False, None, 'Duplicate vote blocked: This anonymous voting token has already been redeemed.'

    candidate = db.session.get(Candidate, candidate_id)
    if not candidate or candidate.election_id != election_id or not candidate.is_active:
        return False, None, 'Invalid candidate selection.'

    ballot_id = str(uuid.uuid4())
    ballot_payload = {
        'candidate_id': candidate_id,
        'election_id': election_id,
        'variant': 'C',
        'timestamp': datetime.now(timezone.utc).isoformat(),
    }

    try:
        nonce_hex, ciphertext_hex, tag_hex, aad_hex, wrapped_key_hex = encrypt_ballot_hybrid(
            ballot_payload=ballot_payload,
            election_id=election_id,
            ballot_id=ballot_id,
        )
    except Exception as exc:
        return False, None, f'Ballot encryption failed: {str(exc)}'

    receipt_code = generate_receipt_code()
    digest = compute_ballot_digest(
        election_id=election_id,
        ballot_id=ballot_id,
        nonce_hex=nonce_hex,
        ciphertext_hex=ciphertext_hex,
        tag_hex=tag_hex,
        wrapped_key_hex=wrapped_key_hex,
    )

    try:
        # Atomic double-spend guard using conditional update
        updated = (
            db.session.query(AnonymousToken)
            .filter_by(id=token_rec.id, is_spent=False)
            .update({'is_spent': True, 'spent_at': datetime.now(timezone.utc)})
        )
        if updated != 1:
            db.session.rollback()
            return False, None, 'Duplicate vote blocked: This anonymous voting token has already been redeemed.'

        ballot = EncryptedBallot(
            id=ballot_id,
            election_id=election_id,
            nonce_hex=nonce_hex,
            ciphertext_hex=ciphertext_hex,
            tag_hex=tag_hex,
            aad_hex=aad_hex,
            wrapped_key_hex=wrapped_key_hex,
            algorithm='RSA-OAEP+AES-256-GCM',
            version=2,
        )
        db.session.add(ballot)

        receipt = Receipt(
            receipt_code=receipt_code,
            election_id=election_id,
            ballot_id=ballot_id,
            ballot_digest_hex=digest,
        )
        db.session.add(receipt)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        return False, None, f'Anonymous vote submission failed: {str(exc)}'

    append_audit_event(
        event_type='ballot.cast_anonymous',
        actor_category='anonymous',
        actor_ref='anonymous_token_holder',
        payload={
            'election_id': election_id,
            'variant': 'C',
            'ballot_id': ballot_id,
            'token_hash_prefix': token_hash[:12] + '...',
            'receipt_prefix': receipt_code[:8] + '...',
            'algorithm': 'RSA-OAEP+AES-256-GCM',
        },
    )

    return True, receipt_code, None
