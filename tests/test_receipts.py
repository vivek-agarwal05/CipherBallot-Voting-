from app.services.voting import cast_vote_atomic
from app.services.receipts import verify_receipt
from app.models import EncryptedBallot


def test_receipt_digest_verifies_unchanged(app, db, eligible_voter_setup):
    """Receipt SHA-256 digest accurately confirms an unchanged ballot record."""
    voter, election = eligible_voter_setup
    with app.app_context():
        candidate = election.candidates[0]
        success, receipt_code, _ = cast_vote_atomic(election.id, voter.id, candidate.id)
        assert success is True

        res = verify_receipt(receipt_code)
        assert res['found'] is True
        assert res['verified'] is True
        assert res['digest_matches'] is True


def test_receipt_detects_tampered_ballot_record(app, db, eligible_voter_setup):
    """If the stored ciphertext in the database is modified, receipt verification fails."""
    voter, election = eligible_voter_setup
    with app.app_context():
        candidate = election.candidates[0]
        success, receipt_code, _ = cast_vote_atomic(election.id, voter.id, candidate.id)
        assert success is True

        # Tamper with the database ballot record
        ballot = db.session.query(EncryptedBallot).filter_by(election_id=election.id).first()
        ct_bytes = bytearray(bytes.fromhex(ballot.ciphertext_hex))
        ct_bytes[0] ^= 0x01
        ballot.ciphertext_hex = ct_bytes.hex()
        db.session.commit()

        # Verification must now report mismatch!
        res = verify_receipt(receipt_code)
        assert res['found'] is True
        assert res['verified'] is False
        assert res['digest_matches'] is False
        assert 'mismatch' in res['message'].lower()
