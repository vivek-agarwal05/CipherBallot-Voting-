"""
app/voter/routes.py — Voter blueprint routes (role='voter').
"""
from flask import Blueprint, render_template, abort, redirect, url_for, flash, request
from flask_login import login_required, current_user
from ..extensions import db
from ..models import Election, Candidate, ElectionEligibility, Participation, EncryptedBallot, Receipt
from ..services.voting import (
    _check_election_timing,
    check_voter_eligibility,
    cast_vote_atomic,
    issue_anonymous_token,
    cast_vote_with_token,
)
from ..services.elections import list_voter_elections

voter_bp = Blueprint('voter', __name__)


def _require_voter():
    """Abort with 403 if user is not a voter."""
    if not current_user.is_authenticated or current_user.role != 'voter':
        abort(403)


@voter_bp.route('/')
@login_required
def dashboard():
    """Voter Dashboard: overview cards and eligible active elections."""
    _require_voter()
    elections_data = list_voter_elections(current_user.id)
    
    total_eligible = sum(1 for e in elections_data if e['is_eligible'])
    total_voted = sum(1 for e in elections_data if e['already_voted'])
    action_required = sum(1 for e in elections_data if e['can_vote'])
    
    return render_template(
        'voter/dashboard.html',
        elections_data=elections_data,
        total_eligible=total_eligible,
        total_voted=total_voted,
        action_required=action_required,
    )


@voter_bp.route('/elections')
@login_required
def elections():
    """List all available elections with status and eligibility badge."""
    _require_voter()
    elections_data = list_voter_elections(current_user.id)
    return render_template(
        'voter/elections.html',
        elections_data=elections_data,
    )


@voter_bp.route('/elections/<int:election_id>')
@login_required
def election_detail(election_id: int):
    """View election details and candidates."""
    _require_voter()
    election = db.session.get(Election, election_id)
    if not election:
        abort(404)
    status_info = check_voter_eligibility(election_id, current_user.id)
    candidates = [c for c in election.candidates if c.is_active]
    return render_template(
        'voter/election_detail.html',
        election=election,
        status_info=status_info,
        candidates=candidates,
    )


@voter_bp.route('/vote/<int:election_id>', methods=['GET', 'POST'])
@voter_bp.route('/elections/<int:election_id>/vote', methods=['GET', 'POST'])
@login_required
def cast_vote(election_id: int):
    """
    Cast a ballot according to the election's architectural variant (A, B, or C).
      - Variant A: Single-class hybrid encryption, no public receipt.
      - Variant B: Department poll with eligibility roster + verifiable SHA-256 receipt.
      - Variant C: Two-phase anonymous token issuance + unlinked token redemption.
    """
    _require_voter()
    election = db.session.get(Election, election_id)
    if not election:
        abort(404)

    variant = (election.variant or 'B').upper()
    status_info = check_voter_eligibility(election_id, current_user.id)
    candidates = [c for c in election.candidates if c.is_active]

    if variant == 'C':
        is_open, is_expired = _check_election_timing(election)
        if not status_info['eligible']:
            flash(status_info['reason'], 'warning')
            return redirect(url_for('voter.election_detail', election_id=election_id))
        if not is_open or is_expired:
            flash(status_info['reason'] if status_info['can_vote'] is False else 'This election is not open for voting.', 'warning')
            return redirect(url_for('voter.election_detail', election_id=election_id))

        issued_token = None
        if request.method == 'POST':
            action = request.form.get('action', '').strip()
            if action == 'claim_token':
                ok, raw_token, err_msg = issue_anonymous_token(election_id, current_user.id)
                if ok:
                    issued_token = raw_token
                    status_info = check_voter_eligibility(election_id, current_user.id)
                    flash(
                        'Phase 1 Complete: Anonymous voting token issued! Save or redeem it in Phase 2 below — '
                        'no voter ID will be attached when your ballot is cast.',
                        'success',
                    )
                else:
                    flash(err_msg or 'Failed to issue anonymous token.', 'danger')
            elif action == 'cast_with_token':
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
                        flash('Phase 2 Complete: Anonymous ballot sealed with Hybrid RSA-OAEP + AES-256-GCM!', 'success')
                        return redirect(url_for('voter.show_receipt', receipt_code=receipt_code))
                    flash(err_msg or 'Anonymous ballot submission failed.', 'danger')

        return render_template(
            'voter/cast_vote_variant_c.html',
            election=election,
            candidates=candidates,
            status_info=status_info,
            issued_token=issued_token,
        )

    if not status_info['can_vote']:
        flash(status_info['reason'], 'warning')
        return redirect(url_for('voter.election_detail', election_id=election_id))

    if request.method == 'POST':
        candidate_id_str = request.form.get('candidate_id', '').strip()
        if not candidate_id_str or not candidate_id_str.isdigit():
            flash('Please select a candidate before submitting.', 'danger')
            return render_template('voter/cast_vote.html', election=election, candidates=candidates)

        candidate_id = int(candidate_id_str)
        success, receipt_code, err_msg = cast_vote_atomic(
            election_id=election_id,
            voter_id=current_user.id,
            candidate_id=candidate_id,
        )

        if not success:
            flash(err_msg or 'Vote submission failed.', 'danger')
            return render_template('voter/cast_vote.html', election=election, candidates=candidates)

        if receipt_code:
            flash('Your ballot has been sealed with Hybrid RSA-OAEP + AES-256-GCM encryption!', 'success')
            return redirect(url_for('voter.show_receipt', receipt_code=receipt_code))

        flash(
            'Your ballot has been encrypted and recorded (Variant A single-class mode: no public receipt issued).',
            'success',
        )
        return redirect(url_for('voter.election_detail', election_id=election_id))

    return render_template('voter/cast_vote.html', election=election, candidates=candidates)


@voter_bp.route('/receipt/<receipt_code>')
@login_required
def show_receipt(receipt_code: str):
    """Post-vote verifiable receipt view."""
    _require_voter()
    receipt = db.session.query(Receipt).filter_by(receipt_code=receipt_code).first()
    if not receipt:
        abort(404)
    return render_template('voter/receipt.html', receipt=receipt)


@voter_bp.route('/status')
@login_required
def voting_status():
    """My Voting Status across all institutional elections."""
    _require_voter()
    elections_data = list_voter_elections(current_user.id)
    return render_template('voter/voting_status.html', elections_data=elections_data)
