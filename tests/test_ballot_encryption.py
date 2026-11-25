from sqlalchemy import inspect
from app.security.ballots import encrypt_ballot, encrypt_ballot_hybrid, decrypt_ballot
from app.services.voting import cast_vote_atomic
from app.models import EncryptedBallot, Participation


def test_hybrid_rsa_aes_gcm_encrypt_decrypt_succeeds(app):
    """Hybrid encryption wraps a fresh ephemeral AES-256-GCM key with RSA-OAEP and decrypts cleanly."""
    with app.app_context():
        payload = {'candidate_id': 7, 'election_id': 2, 'timestamp': '2024-01-01T12:00:00Z'}
        nonce1, ct1, tag1, aad1, wk1 = encrypt_ballot_hybrid(payload, election_id=2, ballot_id='hybrid-1')
        nonce2, ct2, tag2, aad2, wk2 = encrypt_ballot_hybrid(payload, election_id=2, ballot_id='hybrid-2')

        # Unique ephemeral AES key -> unique RSA-OAEP wrapped key & nonce
        assert wk1 != wk2
        assert nonce1 != nonce2

        decrypted = decrypt_ballot(nonce1, ct1, tag1, aad1, election_id=2, ballot_id='hybrid-1', wrapped_key_hex=wk1)
        assert decrypted['candidate_id'] == 7
        assert decrypted['election_id'] == 2


def test_aes_gcm_encrypt_decrypt_succeeds(app):
    """AES-256-GCM authenticated encryption correctly decrypts the original payload."""
    with app.app_context():
        payload = {
            'candidate_id': 42,
            'election_id': 10,
            'timestamp': '2024-01-01T12:00:00Z'
        }
        nonce, ct, tag, aad = encrypt_ballot(payload, election_id=10, ballot_id='uuid-test-123')
        
        decrypted = decrypt_ballot(nonce, ct, tag, aad, election_id=10, ballot_id='uuid-test-123')
        assert decrypted['candidate_id'] == 42
        assert decrypted['election_id'] == 10


def test_nonce_freshness_never_reused(app):
    """Encrypting the same payload twice generates fresh, distinct nonces and ciphertexts."""
    with app.app_context():
        payload = {'candidate_id': 1}
        n1, ct1, t1, _ = encrypt_ballot(payload, 1, 'b1')
        n2, ct2, t2, _ = encrypt_ballot(payload, 1, 'b2')
        assert n1 != n2, "Nonces must never be reused!"
        assert ct1 != ct2


def test_vote_stored_without_voter_id_or_plaintext_choice(app, db, eligible_voter_setup):
    """EncryptedBallot table schema strictly lacks voter_id and candidate_id columns."""
    voter, election = eligible_voter_setup
    with app.app_context():
        # Inspect EncryptedBallot columns
        mapper = inspect(EncryptedBallot)
        columns = [c.key for c in mapper.mapper.column_attrs]
        assert 'voter_id' not in columns, "EncryptedBallot must never contain a voter_id column!"
        assert 'candidate_id' not in columns, "EncryptedBallot must never contain a plaintext candidate_id column!"

        # Inspect Participation columns
        p_mapper = inspect(Participation)
        p_columns = [c.key for c in p_mapper.mapper.column_attrs]
        assert 'candidate_id' not in p_columns, "Participation table must never contain candidate_id!"
        assert 'ballot_id' not in p_columns, "Participation table must never link to ballot_id!"
