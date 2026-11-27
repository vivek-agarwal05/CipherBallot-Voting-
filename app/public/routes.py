"""
app/public/routes.py — Public routes (no authentication required).
"""
from datetime import datetime, timezone
from flask import Blueprint, render_template, request, abort, jsonify, redirect, url_for, flash
from ..extensions import db
from ..models import Election, Receipt, EncryptedBallot, PublishedResult, Candidate
from ..services.receipts import verify_receipt
from ..services.voting import _check_election_timing, cast_vote_with_token
from ..security.signatures import verify_document_signature
from ..security.canonical import canonical_json
import json

public_bp = Blueprint('public', __name__)


@public_bp.route('/')
def index():
    """Landing page showing overview, feature highlights, and active/published elections."""
    open_elections = (
        db.session.query(Election)
        .filter_by(status='open')
        .order_by(Election.start_dt.asc())
        .all()
    )
    published_elections = (
        db.session.query(Election)
        .filter_by(status='published')
        .order_by(Election.updated_at.desc())
        .all()
    )
    return render_template(
        'public/index.html',
        open_elections=open_elections,
        published_elections=published_elections,
    )


@public_bp.route('/bulletin-board')
@public_bp.route('/bulletin-board/<int:election_id>')
def bulletin_board(election_id: int | None = None):
    """
    Public Bulletin Board listing receipt digests for transparency.
    Zero voter identification and zero candidate choices are displayed.
    """
    elections = db.session.query(Election).filter(Election.status.in_(['open', 'closed', 'published'])).order_by(Election.created_at.desc()).all()
    
    selected_election = None
    receipts = []
    
    if election_id:
        selected_election = (
            db.session.query(Election)
            .filter(Election.id == election_id, Election.status.in_(['open', 'closed', 'published']))
            .first()
        )
        if selected_election is None:
            abort(404)
    elif elections:
        selected_election = elections[0]

    if selected_election:
        receipts = (
            db.session.query(Receipt)
            .filter_by(election_id=selected_election.id)
            .order_by(Receipt.created_at.asc())
            .all()
        )

    return render_template(
        'public/bulletin_board.html',
        elections=elections,
        selected_election=selected_election,
        receipts=receipts,
    )


@public_bp.route('/verify-receipt', methods=['GET', 'POST'])
def receipt_verifier():
    """
    Public receipt verification portal.
    A voter enters their receipt code to check if their encrypted ballot digest
    is recorded and uncorrupted on the bulletin board.
    """
    receipt_code = request.args.get('code', '').strip()
    result = None

    if request.method == 'POST':
        receipt_code = request.form.get('receipt_code', '').strip()

    if receipt_code:
        result = verify_receipt(receipt_code)

    return render_template(
        'public/verify_receipt.html',
        receipt_code=receipt_code,
        result=result,
    )


@public_bp.route('/receipt/<receipt_code>')
def view_single_receipt(receipt_code: str):
    """Redirect to the main receipt verification portal with the code pre-filled."""
    return redirect(url_for('public.receipt_verifier', code=receipt_code))


@public_bp.route('/results/<int:election_id>')
def election_results(election_id: int):
    """Display verified, Ed25519-signed results for a published election."""
    election = db.session.get(Election, election_id)
    if election is None:
        abort(404)
    published = db.session.query(PublishedResult).filter_by(election_id=election_id).first()
    
    result_data = None
    signature_valid = False
    if published:
        try:
            result_data = json.loads(published.result_json)
            canonical_bytes = canonical_json(result_data)
            signature_valid = verify_document_signature(canonical_bytes, published.signature_hex)
        except Exception:
            signature_valid = False

    return render_template(
        'public/results.html',
        election=election,
        published=published,
        result_data=result_data,
        signature_valid=signature_valid,
    )


@public_bp.route('/anonymous-cast/<int:election_id>', methods=['GET', 'POST'])
def anonymous_cast(election_id: int):
    """
    Variant C Phase 2: Unauthenticated anonymous ballot submission using a one-time token.
    Allows redeeming a claimed Variant C token without any active user session.
    """
    election = db.session.get(Election, election_id)
    if election is None:
        abort(404)
    if (election.variant or 'B').upper() != 'C':
        flash('Anonymous token casting is only supported for Variant C elections.', 'warning')
        return redirect(url_for('public.index'))
    is_open, is_expired = _check_election_timing(election)
    if election.status != 'open' or not is_open or is_expired:
        flash('This election is not open for voting.', 'warning')
        return redirect(url_for('public.index'))

    candidates = [c for c in election.candidates if c.is_active]

    if request.method == 'POST':
        raw_token = request.form.get('anonymous_token', '').strip()
        candidate_id_str = request.form.get('candidate_id', '').strip()
        if not candidate_id_str or not candidate_id_str.isdigit():
            flash('Please select a candidate before submitting.', 'danger')
        else:
            ok, receipt_code, err_msg = cast_vote_with_token(
                election_id=election_id,
                raw_token=raw_token,
                candidate_id=int(candidate_id_str),
            )
            if ok:
                flash('Anonymous ballot cast successfully! Copy your verifiable receipt below.', 'success')
                return redirect(url_for('public.receipt_verifier', code=receipt_code))
            flash(err_msg or 'Anonymous ballot submission failed.', 'danger')

    return render_template(
        'voter/cast_vote_variant_c.html',
        election=election,
        candidates=candidates,
        status_info=None,
        issued_token=None,
    )


@public_bp.route('/variants')
def variant_comparison():
    """Public side-by-side comparison of Variants A, B, and C."""
    return render_template('admin/variant_comparison.html')


@public_bp.route('/privacy')
def privacy_guide():
    """Educational Security & Privacy Guide explaining cryptography and prototype trade-offs."""
    return render_template('public/privacy_guide.html')


@public_bp.route('/health')
def health_check():
    """System health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'app': 'CipherBallot',
        'variant': 'A/B/C'
    })
