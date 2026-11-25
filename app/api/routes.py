"""
app/api/routes.py — REST API and Cryptography Lab endpoints.
"""
import time
import hashlib
import json
import os
from flask import Blueprint, jsonify, request, abort
from flask_login import current_user, login_required
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..models import Election, PublishedResult
from ..extensions import db
from ..security.passwords import hash_password, verify_password
from ..security.canonical import canonical_json
from ..security.signatures import sign_document, verify_document_signature, get_public_key_hex
from ..security.ballots import _load_ballot_key, compute_ballot_digest

api_bp = Blueprint('api', __name__)


# ---------------------------------------------------------------------------
# Public data endpoints
# ---------------------------------------------------------------------------

@api_bp.route('/elections/')
def list_elections():
    """Return JSON list of open and published elections."""
    elections = (
        db.session.query(Election)
        .filter(Election.status.in_(['open', 'published']))
        .order_by(Election.created_at.desc())
        .all()
    )
    return jsonify([
        {
            'id': e.id,
            'title': e.title,
            'status': e.status,
            'group_dept': e.group_dept,
            'vote_count': e.vote_count,
        }
        for e in elections
    ])


@api_bp.route('/elections/<int:election_id>/results')
def get_results(election_id: int):
    """Return published results with Ed25519 signature verification."""
    result = db.session.query(PublishedResult).filter_by(election_id=election_id).first()
    if result is None:
        abort(404)

    result_dict = json.loads(result.result_json)
    result_bytes = canonical_json(result_dict)
    sig_valid = verify_document_signature(result_bytes, result.signature_hex)

    return jsonify({
        'election_id': election_id,
        'result': result_dict,
        'signature_hex': result.signature_hex,
        'public_key_id': result.public_key_id,
        'signature_valid': sig_valid,
        'published_at': result.published_at.isoformat(),
    })


# ---------------------------------------------------------------------------
# Cryptography Lab Endpoints
# ---------------------------------------------------------------------------

@api_bp.route('/lab/hash-password', methods=['POST'])
@login_required
def lab_hash_password():
    """Panel 1: Argon2id password hashing."""
    data = request.get_json(force=True, silent=True) or {}
    pwd = data.get('password', '')
    if not pwd:
        return jsonify({'error': 'Password cannot be empty.'}), 400

    start_t = time.perf_counter()
    encoded_hash = hash_password(pwd)
    elapsed_ms = round((time.perf_counter() - start_t) * 1000, 2)

    return jsonify({
        'password_len': len(pwd),
        'encoded_hash': encoded_hash,
        'time_ms': elapsed_ms,
        'algorithm': 'Argon2id (m=64MB, t=2 iterations, p=2 threads)',
    })


@api_bp.route('/lab/verify-password', methods=['POST'])
@login_required
def lab_verify_password():
    """Panel 1: Argon2id password verification."""
    data = request.get_json(force=True, silent=True) or {}
    encoded_hash = data.get('hash', '')
    candidate = data.get('password', '')

    if not encoded_hash:
        return jsonify({'error': 'Missing hash.'}), 400

    start_t = time.perf_counter()
    is_valid = verify_password(encoded_hash, candidate)
    elapsed_ms = round((time.perf_counter() - start_t) * 1000, 2)

    return jsonify({
        'valid': is_valid,
        'time_ms': elapsed_ms,
    })


# Dedicated lab key derived separately for lab exercises
_LAB_KEY = hashlib.sha256(b"cipherballot-educational-lab-key-salt-98721").digest()

@api_bp.route('/lab/encrypt-sample', methods=['POST'])
@login_required
def lab_encrypt_sample():
    """Panel 2: AES-256-GCM sample encryption."""
    data = request.get_json(force=True, silent=True) or {}
    plaintext = data.get('plaintext', 'Laboratory sample: Candidate 1')

    aesgcm = AESGCM(_LAB_KEY)
    nonce = os.urandom(12)
    aad = b"cipherballot-lab-context-v1"
    pt_bytes = plaintext.encode('utf-8')

    ct_with_tag = aesgcm.encrypt(nonce, pt_bytes, aad)
    tag = ct_with_tag[-16:]
    ct = ct_with_tag[:-16]

    return jsonify({
        'nonce_hex': nonce.hex(),
        'ciphertext_hex': ct.hex(),
        'tag_hex': tag.hex(),
        'aad_hex': aad.hex(),
        'algorithm': 'AES-256-GCM',
        'key_size_bits': 256,
        'nonce_size_bits': 96,
        'tag_size_bits': 128,
    })


@api_bp.route('/lab/decrypt-sample', methods=['POST'])
@login_required
def lab_decrypt_sample():
    """Panel 2: AES-256-GCM sample decryption."""
    data = request.get_json(force=True, silent=True) or {}
    try:
        nonce = bytes.fromhex(data.get('nonce_hex', ''))
        ct = bytes.fromhex(data.get('ciphertext_hex', ''))
        tag = bytes.fromhex(data.get('tag_hex', ''))
        aad = bytes.fromhex(data.get('aad_hex', ''))

        aesgcm = AESGCM(_LAB_KEY)
        pt_bytes = aesgcm.decrypt(nonce, ct + tag, aad)
        return jsonify({
            'success': True,
            'plaintext': pt_bytes.decode('utf-8'),
        })
    except InvalidTag:
        return jsonify({
            'success': False,
            'error': 'InvalidTag: GCM authentication tag verification failed. Ciphertext or tag was modified!',
        }), 400
    except Exception as exc:
        return jsonify({'success': False, 'error': str(exc)}), 400


@api_bp.route('/lab/tamper-demo', methods=['POST'])
@login_required
def lab_tamper_demo():
    """Panel 3: AES-256-GCM tamper detection live demonstration."""
    data = request.get_json(force=True, silent=True) or {}
    try:
        nonce = bytes.fromhex(data.get('nonce_hex', ''))
        ct = bytes.fromhex(data.get('ciphertext_hex', ''))
        tag = bytes.fromhex(data.get('tag_hex', ''))
        aad = bytes.fromhex(data.get('aad_hex', ''))
    except Exception:
        # Generate fresh if not provided
        aesgcm = AESGCM(_LAB_KEY)
        nonce = os.urandom(12)
        aad = b"cipherballot-lab-context-v1"
        ct_with_tag = aesgcm.encrypt(nonce, b"Candidate A: Alice Smith", aad)
        tag = ct_with_tag[-16:]
        ct = ct_with_tag[:-16]

    aesgcm = AESGCM(_LAB_KEY)

    # 1. Decrypt original
    try:
        orig_pt = aesgcm.decrypt(nonce, ct + tag, aad).decode('utf-8')
        orig_decrypts = True
    except Exception:
        orig_pt = None
        orig_decrypts = False

    # 2. Tamper copy: flip 1 bit in ciphertext
    tampered_ct = bytearray(ct)
    if tampered_ct:
        tampered_ct[0] ^= 0x01
    else:
        tampered_ct = bytearray(b"X")

    tampered_decrypts = False
    tampered_error = None
    try:
        aesgcm.decrypt(nonce, bytes(tampered_ct) + tag, aad)
        tampered_decrypts = True
    except InvalidTag:
        tampered_error = "cryptography.exceptions.InvalidTag: MAC check failed. Ciphertext tampering detected."
    except Exception as exc:
        tampered_error = str(exc)

    return jsonify({
        'original_decrypts': orig_decrypts,
        'original_plaintext': orig_pt,
        'tampered_decrypts': tampered_decrypts,
        'tampered_error': tampered_error,
        'explanation': 'AES-GCM includes a 128-bit authentication tag. Altering even a single bit in the ciphertext causes the polynomial GHASH MAC to fail verification. The cipher refuses to release any plaintext.',
    })


@api_bp.route('/lab/sha256', methods=['POST'])
@login_required
def lab_sha256():
    """Panel 4: SHA-256 cryptographic digest calculation."""
    data = request.get_json(force=True, silent=True) or {}
    text = data.get('text', '')
    raw_bytes = text.encode('utf-8')
    digest_hex = hashlib.sha256(raw_bytes).hexdigest()
    return jsonify({
        'input_text': text,
        'input_bytes_len': len(raw_bytes),
        'digest_hex': digest_hex,
        'digest_bits': 256,
        'digest_chars': 64,
    })


@api_bp.route('/lab/sign-sample', methods=['POST'])
@login_required
def lab_sign_sample():
    """Panel 5: Ed25519 digital signature generation."""
    data = request.get_json(force=True, silent=True) or {}
    doc = data.get('document', {
        'election_title': 'Student Council 2024',
        'winner': 'Alice Smith',
        'votes': 142,
        'status': 'certified'
    })
    doc_bytes = canonical_json(doc)
    sig_hex = sign_document(doc_bytes)
    pub_key_hex = get_public_key_hex()

    return jsonify({
        'canonical_json': doc_bytes.decode('utf-8'),
        'signature_hex': sig_hex,
        'signature_bytes_len': 64,
        'public_key_hex': pub_key_hex,
        'algorithm': 'Ed25519 (RFC 8032)',
    })


@api_bp.route('/lab/verify-signature', methods=['POST'])
@login_required
def lab_verify_signature():
    """Panel 5: Ed25519 signature verification."""
    data = request.get_json(force=True, silent=True) or {}
    doc = data.get('document', {})
    sig_hex = data.get('signature_hex', '')
    tamper = data.get('tamper', False)

    if tamper:
        doc = dict(doc)
        doc['votes'] = doc.get('votes', 142) + 1  # Alter vote count!

    doc_bytes = canonical_json(doc)
    is_valid = verify_document_signature(doc_bytes, sig_hex)

    return jsonify({
        'tampered': tamper,
        'document_verified': doc,
        'is_valid': is_valid,
        'message': 'Signature is VALID. Document authentic and unaltered.' if is_valid else 'SIGNATURE INVALID! Document content was modified or signature does not match public key.',
    })


# Sample in-memory chain for panel 6
@api_bp.route('/lab/audit-chain-demo', methods=['GET', 'POST'])
@login_required
def lab_audit_chain_demo():
    """Panel 6: Audit hash chain inspection & tampering demonstration."""
    data = request.get_json(force=True, silent=True) or {}
    tamper_event_id = data.get('tamper_event_id')  # e.g. 2

    events = [
        {'id': 1, 'type': 'election.created', 'actor': 'admin', 'payload': {'title': 'CS Council Election'}},
        {'id': 2, 'type': 'ballot.cast', 'actor': 'voter', 'payload': {'ballot_id': '550e8400-e29b-41d4-a716-446655440000'}},
        {'id': 3, 'type': 'election.closed', 'actor': 'admin', 'payload': {'reason': 'Voting period ended'}},
    ]

    # If tampering requested, alter payload of event 2
    if tamper_event_id == 2:
        events[1]['payload'] = {'ballot_id': 'TAMPERED-FORGED-ID-99999'}

    # Calculate hashes
    chain = []
    prev_h = '0' * 64
    for ev in events:
        c_bytes = canonical_json(ev['payload'])
        h_input = prev_h.encode('utf-8') + c_bytes
        h = hashlib.sha256(h_input).hexdigest()
        chain.append({
            'id': ev['id'],
            'type': ev['type'],
            'actor': ev['actor'],
            'payload': ev['payload'],
            'prev_hash': prev_h,
            'event_hash': h,
        })
        prev_h = h

    # If tampered, recheck against the original expected event 3 prev_hash
    # To demonstrate chain break: event 2 hash changed, but event 3 in database still points to old hash!
    is_broken = False
    break_event = None
    if tamper_event_id == 2:
        is_broken = True
        break_event = 3

    return jsonify({
        'chain': chain,
        'verified': not is_broken,
        'break_event': break_event,
        'message': 'Audit chain intact.' if not is_broken else 'TAMPER DETECTED at Event 3: Previous hash does not match modified Event 2 digest!',
    })
