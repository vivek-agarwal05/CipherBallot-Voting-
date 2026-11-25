from app.security.signatures import sign_document, verify_document_signature
from app.security.canonical import canonical_json


def test_ed25519_sign_and_verify_succeeds(app):
    """Ed25519 digital signature verifies valid canonical JSON document."""
    with app.app_context():
        doc = {
            'election_id': 1,
            'title': 'CS Council 2024',
            'winner': 'Alice',
            'total_votes': 150
        }
        doc_bytes = canonical_json(doc)
        sig_hex = sign_document(doc_bytes)
        assert len(sig_hex) == 128  # 64 bytes = 128 hex chars

        assert verify_document_signature(doc_bytes, sig_hex) is True


def test_ed25519_modified_document_fails_verification(app):
    """Altering any payload field in a signed document causes verification to fail."""
    with app.app_context():
        doc = {'election_id': 1, 'total_votes': 150}
        doc_bytes = canonical_json(doc)
        sig_hex = sign_document(doc_bytes)

        # Alter vote total from 150 to 151
        tampered_doc = {'election_id': 1, 'total_votes': 151}
        tampered_bytes = canonical_json(tampered_doc)

        assert verify_document_signature(tampered_bytes, sig_hex) is False


def test_ed25519_corrupted_signature_fails_verification(app):
    """Corrupting the signature itself causes verification to fail safely."""
    with app.app_context():
        doc_bytes = canonical_json({'test': 'doc'})
        sig_hex = sign_document(doc_bytes)

        # Corrupt first byte of signature
        corrupted_sig = '00' + sig_hex[2:]
        assert verify_document_signature(doc_bytes, corrupted_sig) is False
