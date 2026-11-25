"""
app/api/routes.py — JSON REST API endpoints for elections and signed results.
"""
import json
from flask import Blueprint, jsonify, abort

from ..models import Election, PublishedResult
from ..extensions import db
from ..security.canonical import canonical_json
from ..security.signatures import verify_document_signature

api_bp = Blueprint('api', __name__)


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
            'variant': e.variant,
            'status': e.status,
            'group_dept': e.group_dept,
            'vote_count': e.vote_count,
        }
        for e in elections
    ])


@api_bp.route('/elections/<int:election_id>/results')
def get_results(election_id: int):
    """Return published results with live Ed25519 signature verification."""
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
