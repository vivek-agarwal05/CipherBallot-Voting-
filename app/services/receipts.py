"""
app/services/receipts.py — Verifiable receipt lookup and cryptographic digest verification.
"""
from ..extensions import db
from ..models import Receipt, EncryptedBallot, Election
from ..security.ballots import compute_ballot_digest


def verify_receipt(receipt_code: str) -> dict:
    """
    Verify a voter's receipt code against the public bulletin board / database.
    
    Checks:
    1. Does the receipt exist?
    2. Does the corresponding encrypted ballot record exist?
    3. Does a recomputed SHA-256 digest over the stored ballot parameters
       match the digest recorded in the receipt?
       
    Returns dict with verification details. Never reveals voter identity or vote choice.
    """
    clean_code = receipt_code.strip() if receipt_code else ''
    if not clean_code:
        return {
            'found': False,
            'verified': False,
            'message': 'No receipt code provided.'
        }

    receipt = db.session.query(Receipt).filter_by(receipt_code=clean_code).first()
    if not receipt:
        return {
            'found': False,
            'verified': False,
            'message': 'Receipt code not found on the bulletin board. Please check for typos.'
        }

    ballot = db.session.query(EncryptedBallot).filter_by(id=receipt.ballot_id).first()
    if not ballot:
        return {
            'found': True,
            'verified': False,
            'receipt': receipt,
            'election': receipt.election,
            'message': 'Receipt found, but associated encrypted ballot record is missing!'
        }

    # Recompute cryptographic digest
    recomputed_digest = compute_ballot_digest(
        election_id=ballot.election_id,
        ballot_id=ballot.id,
        nonce_hex=ballot.nonce_hex,
        ciphertext_hex=ballot.ciphertext_hex,
        tag_hex=ballot.tag_hex,
        wrapped_key_hex=ballot.wrapped_key_hex,
    )

    digest_matches = (recomputed_digest == receipt.ballot_digest_hex)

    return {
        'found': True,
        'verified': digest_matches,
        'receipt_code': receipt.receipt_code,
        'election_id': receipt.election_id,
        'election_title': receipt.election.title if receipt.election else 'Unknown Election',
        'election_status': receipt.election.status if receipt.election else 'Unknown',
        'ballot_id': receipt.ballot_id,
        'ballot_digest_hex': receipt.ballot_digest_hex,
        'recomputed_digest_hex': recomputed_digest,
        'digest_matches': digest_matches,
        'created_at': receipt.created_at,
        'message': 'Receipt verified: Encrypted ballot is recorded and matches the published cryptographic digest.' if digest_matches else 'INTEGRITY MISMATCH: Recomputed digest does not match recorded receipt digest!'
    }
