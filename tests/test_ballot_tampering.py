import pytest
from cryptography.exceptions import InvalidTag
from app.security.ballots import encrypt_ballot, encrypt_ballot_hybrid, decrypt_ballot


def test_hybrid_wrapped_key_tampering_rejected(app):
    """Altering 1 bit in the RSA-OAEP wrapped ephemeral AES key causes decryption failure."""
    with app.app_context():
        payload = {'candidate_id': 99, 'election_id': 1}
        nonce, ct_hex, tag_hex, aad_hex, wk_hex = encrypt_ballot_hybrid(payload, 1, 'hybrid-tamper-1')

        wk_bytes = bytearray(bytes.fromhex(wk_hex))
        wk_bytes[0] ^= 0x01
        with pytest.raises(Exception):
            decrypt_ballot(nonce, ct_hex, tag_hex, aad_hex, 1, 'hybrid-tamper-1', wrapped_key_hex=wk_bytes.hex())


def test_aes_gcm_modified_ciphertext_raises_invalid_tag(app):
    """Flipping a single bit in the ciphertext causes AES-GCM MAC check to fail."""
    with app.app_context():
        payload = {'candidate_id': 99, 'election_id': 1}
        nonce, ct_hex, tag_hex, aad_hex = encrypt_ballot(payload, 1, 'ballot-test-tamper')

        # 1. Original decrypts OK
        orig = decrypt_ballot(nonce, ct_hex, tag_hex, aad_hex, 1, 'ballot-test-tamper')
        assert orig['candidate_id'] == 99

        # 2. Alter first byte of ciphertext
        ct_bytes = bytearray(bytes.fromhex(ct_hex))
        ct_bytes[0] ^= 0x01
        tampered_ct = ct_bytes.hex()

        with pytest.raises(InvalidTag):
            decrypt_ballot(nonce, tampered_ct, tag_hex, aad_hex, 1, 'ballot-test-tamper')


def test_aes_gcm_modified_tag_raises_invalid_tag(app):
    """Flipping a bit in the authentication tag causes AES-GCM decryption failure."""
    with app.app_context():
        payload = {'candidate_id': 99, 'election_id': 1}
        nonce, ct_hex, tag_hex, aad_hex = encrypt_ballot(payload, 1, 'ballot-test-tag')

        # Alter tag byte
        tag_bytes = bytearray(bytes.fromhex(tag_hex))
        tag_bytes[0] ^= 0x80
        tampered_tag = tag_bytes.hex()

        with pytest.raises(InvalidTag):
            decrypt_ballot(nonce, ct_hex, tampered_tag, aad_hex, 1, 'ballot-test-tag')


def test_aes_gcm_transplantation_aad_mismatch_fails(app):
    """Transplanting a ciphertext into another ballot slot fails because AAD binds it."""
    with app.app_context():
        payload = {'candidate_id': 7}
        nonce, ct_hex, tag_hex, aad_hex = encrypt_ballot(payload, 1, 'ballot-original-slot')

        # Try to verify against a different ballot_id
        from app.security.canonical import canonical_json
        different_aad = canonical_json({'ballot_id': 'ballot-stolen-slot', 'election_id': 1}).hex()

        with pytest.raises(InvalidTag):
            decrypt_ballot(nonce, ct_hex, tag_hex, different_aad, 1, 'ballot-stolen-slot')
