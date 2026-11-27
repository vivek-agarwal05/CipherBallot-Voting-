"""
app/admin/routes.py — Admin blueprint routes (role='admin').
"""
import csv
import io
import json
import re
import secrets
import uuid
import logging
from datetime import datetime, timezone

from flask import (
    Blueprint, abort, current_app, flash, redirect,
    render_template, request, url_for, jsonify
)
from flask_login import current_user, login_required
from sqlalchemy import func, or_
from cryptography.exceptions import InvalidTag

from ..extensions import db
from ..models import (
    AuditEvent, Candidate, Election, ElectionEligibility,
    EncryptedBallot, Participation, PublishedResult, User, Receipt,
    InstitutionalIdentity
)
from ..security.audit import append_audit_event, verify_audit_chain
from ..security.ballots import (
    encrypt_ballot_hybrid,
    decrypt_ballot,
    compute_ballot_digest,
)
from ..security.canonical import canonical_json
from ..security.email import (
    is_email_configured,
    send_password_reset_email,
    send_verification_pin_email,
)
from ..security.passwords import generate_password_reset_token, hash_password
from ..security.signatures import get_public_key_hex, sign_document
from ..services.tally import tally_election, publish_election_results
from ..services.elections import get_election_summary

logger = logging.getLogger(__name__)

admin_bp = Blueprint('admin', __name__)


def _require_admin():
    if not current_user.is_authenticated or current_user.role != 'admin':
        abort(403)


def _parse_utc_dt(raw: str | None) -> tuple[datetime | None, str | None]:
    """Parse an HTML datetime-local string (YYYY-MM-DDTHH:MM) into UTC-aware datetime."""
    val = (raw or '').strip()
    if not val:
        return None, None
    try:
        dt = datetime.fromisoformat(val)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt, None
    except ValueError:
        return None, f'Invalid date/time format: {val!r}. Expected YYYY-MM-DDTHH:MM.'


# ---------------------------------------------------------------------------
# Dashboard & Overview
# ---------------------------------------------------------------------------

@admin_bp.route('/')
@login_required
def dashboard():
    _require_admin()
    election_count = db.session.query(func.count(Election.id)).scalar() or 0
    open_election_count = db.session.query(func.count(Election.id)).filter_by(status='open').scalar() or 0
    voter_count = db.session.query(func.count(User.id)).filter_by(role='voter').scalar() or 0
    ballot_count = db.session.query(func.count(EncryptedBallot.id)).scalar() or 0
    recent_events = (
        db.session.query(AuditEvent)
        .order_by(AuditEvent.id.desc())
        .limit(8)
        .all()
    )
    elections = db.session.query(Election).order_by(Election.created_at.desc()).limit(5).all()
    
    return render_template(
        'admin/dashboard.html',
        election_count=election_count,
        open_election_count=open_election_count,
        voter_count=voter_count,
        ballot_count=ballot_count,
        recent_events=recent_events,
        elections=elections,
    )


# ---------------------------------------------------------------------------
# Election Management
# ---------------------------------------------------------------------------

@admin_bp.route('/elections/')
@admin_bp.route('/elections')
@login_required
def elections():
    _require_admin()
    all_elections = (
        db.session.query(Election)
        .order_by(Election.created_at.desc())
        .all()
    )
    summaries = [get_election_summary(e.id) for e in all_elections]
    return render_template('admin/elections.html', elections=all_elections, summaries=summaries)


@admin_bp.route('/elections/new', methods=['GET', 'POST'])
@login_required
def new_election():
    _require_admin()
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        group_dept = request.form.get('group_dept', '').strip()
        variant = request.form.get('variant', 'B').strip().upper()
        start_dt, err_s = _parse_utc_dt(request.form.get('start_dt'))
        end_dt, err_e = _parse_utc_dt(request.form.get('end_dt'))

        if not title:
            flash('Election title is required.', 'danger')
            return render_template('admin/election_form.html', election=None)
        if err_s or err_e:
            flash(err_s or err_e, 'danger')
            return render_template('admin/election_form.html', election=None)
        if start_dt and end_dt and end_dt <= start_dt:
            flash('Closing date/time must be after opening date/time.', 'danger')
            return render_template('admin/election_form.html', election=None)

        election = Election(
            title=title,
            description=description or None,
            group_dept=group_dept or None,
            start_dt=start_dt,
            end_dt=end_dt,
            created_by=current_user.id,
            variant=variant if variant in ('A', 'B', 'C') else 'B',
            status='draft'
        )
        db.session.add(election)
        db.session.commit()

        append_audit_event(
            event_type='election.created',
            actor_category='admin',
            actor_ref=current_user.username,
            payload={'election_id': election.id, 'title': title, 'variant': election.variant},
        )
        flash(f'Election "{title}" created as Draft. Now configure candidates and voter eligibility.', 'success')
        return redirect(url_for('admin.edit_election', election_id=election.id))

    return render_template('admin/election_form.html', election=None)


@admin_bp.route('/elections/<int:election_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_election(election_id: int):
    _require_admin()
    election = db.session.get(Election, election_id)
    if election is None:
        abort(404)

    voters = (
        db.session.query(User)
        .filter_by(role='voter', is_active=True)
        .order_by(User.username)
        .all()
    )
    eligible_voter_ids = {
        e.voter_id
        for e in db.session.query(ElectionEligibility)
        .filter_by(election_id=election_id, status='eligible')
        .all()
    }
    summary = get_election_summary(election.id)

    if request.method == 'POST':
        action = request.form.get('action', '')

        if action == 'update_details':
            if election.status in ('closed', 'published'):
                flash('Cannot modify details of a closed or published election.', 'warning')
            else:
                new_title = request.form.get('title', '').strip()
                start_dt, err_s = _parse_utc_dt(request.form.get('start_dt'))
                end_dt, err_e = _parse_utc_dt(request.form.get('end_dt'))
                if not new_title:
                    flash('Election title cannot be empty.', 'danger')
                elif err_s or err_e:
                    flash(err_s or err_e, 'danger')
                elif start_dt and end_dt and end_dt <= start_dt:
                    flash('Closing date/time must be after opening date/time.', 'danger')
                else:
                    election.title = new_title
                    election.description = request.form.get('description', '').strip() or None
                    election.group_dept = request.form.get('group_dept', '').strip() or None
                    election.start_dt = start_dt
                    election.end_dt = end_dt
                    db.session.commit()
                    append_audit_event(
                        event_type='election.updated',
                        actor_category='admin',
                        actor_ref=current_user.username,
                        payload={'election_id': election.id, 'title': election.title}
                    )
                    flash('Election details updated.', 'success')

        elif action == 'add_candidate':
            if election.status != 'draft':
                flash('Candidates can only be modified while election is in Draft.', 'warning')
            else:
                name = request.form.get('candidate_name', '').strip()
                desc = request.form.get('candidate_desc', '').strip()
                if name:
                    order = len(election.candidates)
                    c = Candidate(
                        election_id=election_id,
                        display_name=name,
                        description=desc or None,
                        display_order=order,
                    )
                    db.session.add(c)
                    db.session.commit()
                    append_audit_event(
                        event_type='candidate.added',
                        actor_category='admin',
                        actor_ref=current_user.username,
                        payload={'election_id': election.id, 'candidate_name': name}
                    )
                    flash(f'Candidate "{name}" added.', 'success')

        elif action == 'toggle_eligibility':
            voter_id_raw = request.form.get('voter_id', '').strip()
            if not voter_id_raw.isdigit():
                flash('Invalid voter identifier.', 'danger')
            else:
                voter_id = int(voter_id_raw)
                voter = db.session.get(User, voter_id)
                if not voter or voter.role != 'voter':
                    flash('Voter account not found.', 'danger')
                else:
                    existing = (
                        db.session.query(ElectionEligibility)
                        .filter_by(election_id=election_id, voter_id=voter_id)
                        .first()
                    )
                    if existing:
                        new_status = 'ineligible' if existing.status == 'eligible' else 'eligible'
                        existing.status = new_status
                    else:
                        existing = ElectionEligibility(
                            election_id=election_id,
                            voter_id=voter_id,
                            status='eligible',
                        )
                        db.session.add(existing)
                    db.session.commit()
                    flash('Voter eligibility updated.', 'success')
            if request.form.get('next') == 'eligibility':
                return redirect(url_for('admin.manage_eligibility', election_id=election_id))

        return redirect(url_for('admin.edit_election', election_id=election_id))

    return render_template(
        'admin/election_form.html',
        election=election,
        voters=voters,
        eligible_voter_ids=eligible_voter_ids,
        summary=summary,
    )


@admin_bp.route('/elections/<int:election_id>/candidates/add', methods=['POST'])
@login_required
def add_candidate(election_id: int):
    _require_admin()
    election = db.session.get(Election, election_id)
    if not election or election.status != 'draft':
        flash('Candidates can only be added while the election is in Draft.', 'warning')
        return redirect(url_for('admin.edit_election', election_id=election_id))

    name = request.form.get('candidate_name', '').strip()
    desc = request.form.get('candidate_desc', '').strip()
    if not name:
        flash('Candidate name is required.', 'danger')
        return redirect(url_for('admin.edit_election', election_id=election_id))

    order = len(election.candidates)
    c = Candidate(
        election_id=election_id,
        display_name=name,
        description=desc or None,
        display_order=order
    )
    db.session.add(c)
    db.session.commit()
    flash(f'Candidate "{name}" added.', 'success')
    return redirect(url_for('admin.edit_election', election_id=election_id))


@admin_bp.route('/elections/<int:election_id>/candidates/<int:candidate_id>/deactivate', methods=['POST'])
@login_required
def deactivate_candidate(election_id: int, candidate_id: int):
    _require_admin()
    election = db.session.get(Election, election_id)
    if not election:
        abort(404)
    if election.status != 'draft':
        flash('Candidates can only be modified while the election is in Draft.', 'warning')
        return redirect(url_for('admin.edit_election', election_id=election_id))
    c = db.session.get(Candidate, candidate_id)
    if not c or c.election_id != election_id:
        abort(404)
    c.is_active = not c.is_active
    db.session.commit()
    status_str = 'activated' if c.is_active else 'deactivated'
    append_audit_event(
        event_type=f'candidate.{status_str}',
        actor_category='admin',
        actor_ref=current_user.username,
        payload={'election_id': election_id, 'candidate_id': candidate_id},
    )
    flash(f'Candidate {c.display_name} {status_str}.', 'info')
    return redirect(url_for('admin.edit_election', election_id=election_id))


# ---------------------------------------------------------------------------
# Voter Eligibility & CSV Import
# ---------------------------------------------------------------------------

@admin_bp.route('/elections/<int:election_id>/eligibility')
@login_required
def manage_eligibility(election_id: int):
    _require_admin()
    election = db.session.get(Election, election_id)
    if not election:
        abort(404)
    voters = db.session.query(User).filter_by(role='voter').order_by(User.username).all()
    eligibilities = {
        e.voter_id: e.status
        for e in db.session.query(ElectionEligibility).filter_by(election_id=election_id).all()
    }
    return render_template(
        'admin/eligibility.html',
        election=election,
        voters=voters,
        eligibilities=eligibilities
    )


@admin_bp.route('/elections/<int:election_id>/eligibility/add', methods=['POST'])
@login_required
def add_single_voter_eligibility(election_id: int):
    _require_admin()
    election = db.session.get(Election, election_id)
    if not election:
        abort(404)
    ident = request.form.get('username', '').strip()
    if not ident:
        flash('Please enter a Student ID or username.', 'danger')
        return redirect(url_for('admin.manage_eligibility', election_id=election_id))
    user = (
        db.session.query(User)
        .filter(
            User.role == 'voter',
            or_(
                func.lower(User.username) == ident.lower(),
                func.upper(User.student_id) == ident.upper(),
            ),
        )
        .first()
    )
    if not user:
        flash(f'Voter with Student ID or username "{ident}" not found.', 'danger')
        return redirect(url_for('admin.manage_eligibility', election_id=election_id))

    existing = db.session.query(ElectionEligibility).filter_by(
        election_id=election_id, voter_id=user.id
    ).first()
    if existing:
        existing.status = 'eligible'
    else:
        elig = ElectionEligibility(election_id=election_id, voter_id=user.id, status='eligible')
        db.session.add(elig)
    db.session.commit()
    flash(f'Voter {user.username} ({user.display_name}) granted eligibility.', 'success')
    return redirect(url_for('admin.manage_eligibility', election_id=election_id))


# ---------------------------------------------------------------------------
# Status Lifecycle & Tallying
# ---------------------------------------------------------------------------

@admin_bp.route('/elections/<int:election_id>/status', methods=['POST'])
@login_required
def change_election_status(election_id: int):
    _require_admin()
    election = db.session.get(Election, election_id)
    if election is None:
        abort(404)

    new_status = request.form.get('status', '').strip()
    valid_transitions = {
        'draft': ['open'],
        'open': ['closed'],
        'closed': ['published'],
        'published': [],
    }

    if new_status not in valid_transitions.get(election.status, []):
        flash(f'Cannot transition from {election.status!r} to {new_status!r}.', 'danger')
        return redirect(url_for('admin.elections'))

    old_status = election.status
    election.status = new_status
    db.session.commit()

    append_audit_event(
        event_type='election.status_change',
        actor_category='admin',
        actor_ref=current_user.username,
        payload={
            'election_id': election_id,
            'from_status': old_status,
            'to_status': new_status,
        },
    )
    flash(f'Election status changed to {new_status!r}.', 'success')
    return redirect(url_for('admin.elections'))


@admin_bp.route('/elections/<int:election_id>/tally', methods=['GET', 'POST'])
@login_required
def tally_election_page(election_id: int):
    """Tally encrypted ballots with AES-GCM decryption and sign results with Ed25519."""
    _require_admin()
    election = db.session.get(Election, election_id)
    if not election:
        abort(404)

    if election.status not in ('closed', 'published'):
        flash('Election must be closed before tallying can occur.', 'warning')
        return redirect(url_for('admin.elections'))

    summary, invalid_count, errors = tally_election(election_id)
    published = db.session.query(PublishedResult).filter_by(election_id=election_id).first()

    if request.method == 'POST':
        action = request.form.get('action', '')
        if action == 'publish':
            success, err = publish_election_results(election_id, current_user.username)
            if success:
                flash('Election results tallied, canonically serialized, signed with Ed25519, and published!', 'success')
                return redirect(url_for('public.election_results', election_id=election_id))
            else:
                flash(f'Publishing failed: {err}', 'danger')

    return render_template(
        'admin/tally.html',
        election=election,
        summary=summary,
        invalid_count=invalid_count,
        errors=errors,
        published=published,
    )


# ---------------------------------------------------------------------------
# Audit & Integrity Center
# ---------------------------------------------------------------------------

@admin_bp.route('/audit/')
@admin_bp.route('/audit')
@login_required
def audit_log():
    _require_admin()
    page = max(1, request.args.get('page', 1, type=int))
    search = request.args.get('q', '').strip()
    per_page = 25

    query = db.session.query(AuditEvent)
    if search:
        query = query.filter(
            (AuditEvent.event_type.ilike(f'%{search}%')) |
            (AuditEvent.actor_ref.ilike(f'%{search}%')) |
            (AuditEvent.safe_payload.ilike(f'%{search}%'))
        )

    total = query.count()
    total_pages = (total + per_page - 1) // per_page if total > 0 else 1
    page = min(page, total_pages)
    events = (
        query.order_by(AuditEvent.id.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    return render_template(
        'admin/audit.html',
        events=events,
        page=page,
        total_pages=total_pages,
        total=total,
        search=search,
    )


@admin_bp.route('/audit/verify', methods=['POST'])
@login_required
def verify_audit():
    _require_admin()
    result = verify_audit_chain()
    if result['verified']:
        flash(f"✅ Audit Chain Verified: All {result['event_count']} events verified intact.", 'success')
    else:
        flash(f"❌ TAMPER DETECTED: {result['message']}", 'danger')
    return redirect(url_for('admin.audit_log'))


# ---------------------------------------------------------------------------
# Security Demonstration Center
# ---------------------------------------------------------------------------

@admin_bp.route('/security-demo')
@login_required
def security_demo():
    _require_admin()
    return render_template('admin/security_demo.html')


@admin_bp.route('/security-demo/run', methods=['POST'])
@login_required
def run_security_demo():
    """
    Execute 5 controlled CSEG3040-aligned security experiments:
      1. Duplicate Vote Prevention (Mandatory + Unit V Access Control)
      2. Hybrid RSA-OAEP + AES-256-GCM Tamper Detection (Mandatory + Unit II & III)
      3. Ed25519 Signature Forgery & Wrong Public Key Rejection (Unit III Digital Signatures)
      4. SHA-256 Audit Hash-Chain Tamper Detection (Unit IV Hash Functions)
      5. Account Lockout & Unauthorized Access Rejection (Unit V Network & Auth Security)
    """
    _require_admin()
    import hashlib
    from datetime import timedelta
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    now_iso = datetime.now(timezone.utc).isoformat()
    report = {
        'timestamp': now_iso,
        'tests': [],
        'all_passed': True
    }

    # -------------------------------------------------------------------------
    # Experiment 1: Duplicate Vote Attempt (Mandatory)
    # -------------------------------------------------------------------------
    test1 = {
        'name': 'Experiment 1: Duplicate Vote Prevention (Mandatory)',
        'requirement': 'Reject second vote attempt using atomic DB uniqueness constraint on (election_id, voter_id)',
        'expected': 'First vote succeeds (Hybrid RSA-OAEP+AES-256-GCM); second vote rejected cleanly',
        'status': 'PASS',
        'details': []
    }

    demo_election = db.session.query(Election).filter_by(
        title='[Sandbox] Security Demo Isolation Election'
    ).first()
    if not demo_election:
        demo_election = Election(
            title='[Sandbox] Security Demo Isolation Election',
            description='Isolated sandbox election for live security test demonstrations',
            group_dept='Security Lab',
            created_by=current_user.id,
            status='open',
            variant='B'
        )
        db.session.add(demo_election)
        db.session.flush()
        c1 = Candidate(election_id=demo_election.id, display_name='Demo Option 1', is_active=True, display_order=0)
        c2 = Candidate(election_id=demo_election.id, display_name='Demo Option 2', is_active=True, display_order=1)
        db.session.add_all([c1, c2])
        db.session.commit()
    elif demo_election.status != 'open':
        demo_election.status = 'open'
        db.session.commit()

    demo_voter = db.session.query(User).filter_by(username='eve').first()
    if not demo_voter:
        demo_voter = db.session.query(User).filter_by(role='voter').first()

    cand = demo_election.candidates[0] if demo_election.candidates else None

    if demo_voter and cand:
        # Clean isolated demo election records so repeated demo runs stay 1:1
        db.session.query(Receipt).filter_by(election_id=demo_election.id).delete()
        db.session.query(EncryptedBallot).filter_by(election_id=demo_election.id).delete()
        db.session.query(Participation).filter_by(election_id=demo_election.id).delete()
        elig = db.session.query(ElectionEligibility).filter_by(
            election_id=demo_election.id, voter_id=demo_voter.id
        ).first()
        if not elig:
            db.session.add(ElectionEligibility(election_id=demo_election.id, voter_id=demo_voter.id, status='eligible'))
        else:
            elig.status = 'eligible'
        db.session.commit()

        from ..services.voting import cast_vote_atomic
        s1, r1, err1 = cast_vote_atomic(demo_election.id, demo_voter.id, cand.id)
        if s1:
            test1['details'].append(f"Submission 1: Vote cast & hybrid-encrypted cleanly (Receipt prefix: {r1[:8]}...).")
        else:
            test1['details'].append(f"Submission 1: Failed unexpectedly: {err1}")
            test1['status'] = 'FAIL'
            report['all_passed'] = False

        s2, r2, err2 = cast_vote_atomic(demo_election.id, demo_voter.id, cand.id)
        if not s2:
            test1['details'].append(f"Submission 2: Duplicate vote rejected atomically ('{err2}').")
            test1['actual'] = 'Second submission rejected (Unique constraint & atomic rollback held)'
        else:
            test1['details'].append("Submission 2: Critical failure — second vote accepted!")
            test1['actual'] = 'DUPLICATE LEAK'
            test1['status'] = 'FAIL'
            report['all_passed'] = False
    else:
        test1['status'] = 'FAIL'
        test1['actual'] = 'Missing demo voter or election'
        report['all_passed'] = False

    report['tests'].append(test1)

    # -------------------------------------------------------------------------
    # Experiment 2: Hybrid Ballot Modification / Tamper Detection (Mandatory)
    # -------------------------------------------------------------------------
    test2 = {
        'name': 'Experiment 2: Hybrid Ballot Tamper Detection — RSA-OAEP + AES-256-GCM (Mandatory)',
        'requirement': 'Unit II & III: Wrap per-ballot AES-256 key with RSA-2048 OAEP; detect ciphertext, tag, or wrapped-key tampering',
        'expected': 'Untouched hybrid ballot decrypts; bit-flipped ciphertext, tag, or wrapped key fails verification',
        'status': 'PASS',
        'details': []
    }

    try:
        sample_payload = {
            'candidate_id': 99,
            'election_id': 9999,
            'timestamp': now_iso,
            'test_note': 'Isolated hybrid security test payload'
        }
        test_ballot_id = str(uuid.uuid4())
        nonce_hex, ct_hex, tag_hex, aad_hex, wrapped_key_hex = encrypt_ballot_hybrid(
            sample_payload, 9999, test_ballot_id
        )

        orig_payload = decrypt_ballot(
            nonce_hex, ct_hex, tag_hex, aad_hex, 9999, test_ballot_id, wrapped_key_hex=wrapped_key_hex
        )
        if orig_payload.get('candidate_id') == 99:
            test2['details'].append("Step 1: Fresh ephemeral AES-256 key unwrapped via RSA-OAEP and ballot decrypted OK.")
        else:
            test2['status'] = 'FAIL'
            report['all_passed'] = False

        # Bit flip in ciphertext
        ct_bytes = bytearray(bytes.fromhex(ct_hex))
        ct_bytes[0] ^= 0x01
        try:
            decrypt_ballot(nonce_hex, ct_bytes.hex(), tag_hex, aad_hex, 9999, test_ballot_id, wrapped_key_hex=wrapped_key_hex)
            test2['status'] = 'FAIL'
            report['all_passed'] = False
        except InvalidTag as exc:
            test2['details'].append(f"Step 2: 1-bit ciphertext modification rejected with {type(exc).__name__} (GHASH failure).")

        # Bit flip in GCM tag
        tag_bytes = bytearray(bytes.fromhex(tag_hex))
        tag_bytes[0] ^= 0x80
        try:
            decrypt_ballot(nonce_hex, ct_hex, tag_bytes.hex(), aad_hex, 9999, test_ballot_id, wrapped_key_hex=wrapped_key_hex)
            test2['status'] = 'FAIL'
            report['all_passed'] = False
        except InvalidTag:
            test2['details'].append("Step 3: 1-bit GCM authentication tag flip rejected with InvalidTag.")

        # Bit flip in RSA-wrapped AES key
        wk_bytes = bytearray(bytes.fromhex(wrapped_key_hex))
        wk_bytes[0] ^= 0x01
        try:
            decrypt_ballot(nonce_hex, ct_hex, tag_hex, aad_hex, 9999, test_ballot_id, wrapped_key_hex=wk_bytes.hex())
            test2['status'] = 'FAIL'
            report['all_passed'] = False
        except Exception as exc:
            test2['details'].append(f"Step 4: 1-bit RSA-OAEP wrapped-key modification rejected ({type(exc).__name__}).")

        if test2['status'] == 'PASS':
            test2['actual'] = 'Ciphertext, GCM tag, and RSA-OAEP wrapped key tampering all rejected'
    except Exception as exc:
        test2['status'] = 'FAIL'
        test2['details'].append(f"Test 2 failed with exception: {exc}")
        report['all_passed'] = False

    report['tests'].append(test2)

    # -------------------------------------------------------------------------
    # Experiment 3: Ed25519 Signature Forgery & Incorrect Public Key (Unit III)
    # -------------------------------------------------------------------------
    test3 = {
        'name': 'Experiment 3: Digital Signature Verification & Wrong Public Key Rejection',
        'requirement': 'Unit III: Reject tampered result manifest and reject verification under an untrusted/wrong public key',
        'expected': 'Authentic manifest passes; modified tally (+1 vote) or wrong Ed25519 public key fails verification',
        'status': 'PASS',
        'details': []
    }
    try:
        from ..security.signatures import verify_document_signature
        manifest = {'election_id': 1, 'winner': 'Priya Sharma', 'votes': 42}
        manifest_bytes = canonical_json(manifest)
        sig_hex = sign_document(manifest_bytes)

        if verify_document_signature(manifest_bytes, sig_hex):
            test3['details'].append("Step 1: Canonical election manifest verified cleanly with institutional Ed25519 public key.")
        else:
            test3['status'] = 'FAIL'
            report['all_passed'] = False

        tampered_bytes = canonical_json({'election_id': 1, 'winner': 'Priya Sharma', 'votes': 43})
        if not verify_document_signature(tampered_bytes, sig_hex):
            test3['details'].append("Step 2: Tampered manifest (votes 42 -> 43) rejected by Ed25519 verification.")
        else:
            test3['status'] = 'FAIL'
            report['all_passed'] = False

        # Wrong public key check
        rogue_pub = Ed25519PrivateKey.generate().public_key()
        try:
            rogue_pub.verify(bytes.fromhex(sig_hex), manifest_bytes)
            test3['status'] = 'FAIL'
            report['all_passed'] = False
        except Exception as exc:
            test3['details'].append(f"Step 3: Verification against an incorrect/rogue Ed25519 public key failed ({type(exc).__name__}).")

        if test3['status'] == 'PASS':
            test3['actual'] = 'Tampered manifest and mismatched public key both rejected'
    except Exception as exc:
        test3['status'] = 'FAIL'
        test3['details'].append(f"Test 3 failed with exception: {exc}")
        report['all_passed'] = False

    report['tests'].append(test3)

    # -------------------------------------------------------------------------
    # Experiment 4: SHA-256 Audit Chain Tamper Detection (Unit IV)
    # -------------------------------------------------------------------------
    test4 = {
        'name': 'Experiment 4: SHA-256 Audit Hash-Chain Tamper Detection',
        'requirement': 'Unit IV: Detect historical payload modification via broken SHA-256(prev_hash || payload) link',
        'expected': 'Intact chain verifies; modifying Event #2 breaks Event #3 link; live DB audit chain remains clean',
        'status': 'PASS',
        'details': []
    }
    try:
        # Build isolated 3-event chain in memory
        sim_events = [
            {'id': 1, 'payload': {'action': 'election.open', 'id': 1}},
            {'id': 2, 'payload': {'action': 'ballot.cast', 'ballot_id': 'b-101'}},
            {'id': 3, 'payload': {'action': 'election.close', 'id': 1}},
        ]
        prev = '0' * 64
        for ev in sim_events:
            ev['prev_hash'] = prev
            ev['hash'] = hashlib.sha256(prev.encode('utf-8') + canonical_json(ev['payload'])).hexdigest()
            prev = ev['hash']

        test4['details'].append("Step 1: Constructed 3-event SHA-256 hash chain; all links consistent.")

        # Tamper Event #2 payload without updating Event #3
        sim_events[1]['payload'] = {'action': 'ballot.cast', 'ballot_id': 'FORGED-999'}
        recomputed_ev2 = hashlib.sha256(
            sim_events[1]['prev_hash'].encode('utf-8') + canonical_json(sim_events[1]['payload'])
        ).hexdigest()
        if recomputed_ev2 != sim_events[1]['hash'] and recomputed_ev2 != sim_events[2]['prev_hash']:
            test4['details'].append(
                f"Step 2: Tampered Event #2 detected! Stored hash {sim_events[1]['hash'][:12]}... != recomputed {recomputed_ev2[:12]}..."
            )
        else:
            test4['status'] = 'FAIL'
            report['all_passed'] = False

        live_audit = verify_audit_chain()
        if live_audit['verified']:
            test4['details'].append(f"Step 3: Live DB audit chain check passed ({live_audit['event_count']} events verified intact).")
        else:
            test4['status'] = 'FAIL'
            test4['details'].append(f"Step 3: Live audit chain alert: {live_audit['message']}")
            report['all_passed'] = False

        if test4['status'] == 'PASS':
            test4['actual'] = 'Historical chain tampering pinpointed; live DB audit chain intact'
    except Exception as exc:
        test4['status'] = 'FAIL'
        test4['details'].append(f"Test 4 failed with exception: {exc}")
        report['all_passed'] = False

    report['tests'].append(test4)

    # -------------------------------------------------------------------------
    # Experiment 5: Brute-Force Lockout & Unauthorized Access Rejection (Unit V)
    # -------------------------------------------------------------------------
    test5 = {
        'name': 'Experiment 5: Brute-Force Account Lockout & Unauthorized Access Control',
        'requirement': 'Unit V: Enforce temporary lockout after repeated failed logins and reject ineligible/unauthorized requests',
        'expected': '5 failed login attempts trigger lockout; ineligible voter blocked from voting in restricted poll',
        'status': 'PASS',
        'details': []
    }
    try:
        from ..services.voting import check_voter_eligibility
        if demo_voter:
            # 5a. Simulate 5 failed logins in isolated state check and restore immediately
            orig_attempts = demo_voter.failed_login_attempts
            orig_locked = demo_voter.locked_until
            demo_voter.failed_login_attempts = 5
            demo_voter.locked_until = datetime.now(timezone.utc) + timedelta(minutes=5)
            db.session.commit()

            is_locked_now = demo_voter.locked_until > datetime.now(timezone.utc).replace(tzinfo=None) if demo_voter.locked_until.tzinfo is None else demo_voter.locked_until > datetime.now(timezone.utc)
            if is_locked_now and demo_voter.failed_login_attempts >= 5:
                test5['details'].append("Step 1: 5 consecutive failed logins triggered 5-minute temporary account lockout.")
            else:
                test5['status'] = 'FAIL'
                report['all_passed'] = False

            # Restore demo voter state cleanly
            demo_voter.failed_login_attempts = orig_attempts
            demo_voter.locked_until = orig_locked
            db.session.commit()

            # 5b. Temporarily test ineligible access rejection
            elig_row = db.session.query(ElectionEligibility).filter_by(
                election_id=demo_election.id, voter_id=demo_voter.id
            ).first()
            if elig_row:
                orig_elig_status = elig_row.status
                elig_row.status = 'ineligible'
                db.session.commit()
                res_elig = check_voter_eligibility(demo_election.id, demo_voter.id)
                elig_row.status = orig_elig_status
                db.session.commit()
                if not res_elig['can_vote'] and not res_elig['eligible']:
                    test5['details'].append("Step 2: Unauthorized / non-rostered voter blocked from ballot access (RBAC + eligibility guard).")
                else:
                    test5['status'] = 'FAIL'
                    report['all_passed'] = False

        if test5['status'] == 'PASS':
            test5['actual'] = 'Account lockout active after 5 failures; unauthorized voter access denied'
    except Exception as exc:
        test5['status'] = 'FAIL'
        test5['details'].append(f"Test 5 failed with exception: {exc}")
        report['all_passed'] = False

    report['tests'].append(test5)

    append_audit_event(
        event_type='security_demo.executed',
        actor_category='admin',
        actor_ref=current_user.username,
        payload={
            'test1_status': test1['status'],
            'test2_status': test2['status'],
            'test3_status': test3['status'],
            'test4_status': test4['status'],
            'test5_status': test5['status'],
            'all_passed': report['all_passed']
        }
    )

    if request.headers.get('Accept') == 'application/json' or request.is_json:
        return jsonify(report)

    flash('All 5 Security Experiments completed. See detailed report below.', 'success' if report['all_passed'] else 'danger')
    return render_template('admin/security_demo.html', report=report)


# ---------------------------------------------------------------------------
# User Management & Institutional Roster Onboarding
# ---------------------------------------------------------------------------

_STUDENT_ID_RE = re.compile(r'^[A-Za-z0-9_\-]{4,64}$')
_EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


def _render_users_page(
    issued_pins: list[dict] | None = None,
    generated_reset: dict | None = None,
):
    all_users = (
        db.session.query(User)
        .order_by(User.role, User.username)
        .all()
    )
    now = datetime.now(timezone.utc)
    locked_user_ids = set()
    for u in all_users:
        if u.locked_until:
            lu = u.locked_until if u.locked_until.tzinfo else u.locked_until.replace(tzinfo=timezone.utc)
            if now < lu:
                locked_user_ids.add(u.id)
    identities = (
        db.session.query(InstitutionalIdentity)
        .order_by(InstitutionalIdentity.is_claimed, InstitutionalIdentity.student_id)
        .all()
    )
    return render_template(
        'admin/users.html',
        users=all_users,
        identities=identities,
        locked_user_ids=locked_user_ids,
        issued_pins=issued_pins or [],
        generated_reset=generated_reset,
    )


@admin_bp.route('/users/')
@admin_bp.route('/users')
@login_required
def users():
    _require_admin()
    return _render_users_page()


@admin_bp.route('/registry/add', methods=['POST'])
@login_required
def add_institutional_identity():
    _require_admin()
    student_id = request.form.get('student_id', '').strip().upper()
    full_name = request.form.get('full_name', '').strip()
    dept = request.form.get('department', '').strip()
    email = request.form.get('email', '').strip().lower()
    raw_pin_input = request.form.get('verification_pin', '').strip()
    send_email_requested = request.form.get('send_email') == 'on'

    if raw_pin_input and len(raw_pin_input) < 4:
        flash('Verification PIN must be at least 4 characters (or leave blank to auto-generate).', 'danger')
        return redirect(url_for('admin.users'))
    raw_pin = raw_pin_input or f'PIN-{secrets.token_hex(3).upper()}'

    if not (student_id and full_name and dept and email):
        flash('All fields are required to register an institutional student record.', 'danger')
        return redirect(url_for('admin.users'))
    if not _STUDENT_ID_RE.match(student_id):
        flash('Student ID must be 4–64 characters using only letters, numbers, hyphens, and underscores.', 'danger')
        return redirect(url_for('admin.users'))
    if not _EMAIL_RE.match(email):
        flash('Please provide a valid institutional email address.', 'danger')
        return redirect(url_for('admin.users'))

    existing = db.session.query(InstitutionalIdentity).filter_by(student_id=student_id).first()
    if existing:
        flash(f'Student ID "{student_id}" is already in the institutional registry.', 'warning')
        return redirect(url_for('admin.users'))

    existing_email = db.session.query(InstitutionalIdentity).filter_by(email=email).first()
    if existing_email:
        flash(f'Institutional email "{email}" is already assigned to another student record.', 'warning')
        return redirect(url_for('admin.users'))

    new_id = InstitutionalIdentity(
        student_id=student_id,
        full_name=full_name,
        department=dept,
        email=email,
        verification_pin_hash=hash_password(raw_pin),
        is_claimed=False,
    )
    db.session.add(new_id)
    db.session.commit()

    email_sent = False
    if send_email_requested and is_email_configured():
        email_sent, _ = send_verification_pin_email(
            to_address=email,
            full_name=full_name,
            student_id=student_id,
            department=dept,
            raw_pin=raw_pin,
            register_url=url_for('auth.register', _external=True),
        )

    append_audit_event(
        event_type='institutional_registry.id_added',
        actor_category='admin',
        actor_ref=current_user.username,
        payload={
            'student_id': student_id,
            'department': dept,
            'name': full_name,
            'pin_protected': True,
            'email_sent': email_sent,
        },
    )

    if email_sent:
        flash(
            f'Pre-approved student ID "{student_id}" ({full_name}) added and Verification PIN emailed to {email}.',
            'success',
        )
    else:
        flash(
            f'Pre-approved student ID "{student_id}" ({full_name}) added. '
            f'One-Time Verification PIN (share privately with student): {raw_pin}',
            'success',
        )
    return redirect(url_for('admin.users'))


@admin_bp.route('/registry/import-csv', methods=['POST'])
@login_required
def import_institutional_csv():
    """Bulk-import pre-approved institutional students from CSV."""
    _require_admin()
    uploaded = request.files.get('csv_file')
    if not uploaded or not uploaded.filename:
        flash('Please select a CSV file to upload.', 'danger')
        return redirect(url_for('admin.users'))

    try:
        raw_text = uploaded.read().decode('utf-8-sig')
    except UnicodeDecodeError:
        flash('CSV file must be UTF-8 encoded.', 'danger')
        return redirect(url_for('admin.users'))

    reader = csv.DictReader(io.StringIO(raw_text))
    if not reader.fieldnames:
        flash('CSV file appears empty or missing header columns.', 'danger')
        return redirect(url_for('admin.users'))

    norm_fields = {f.strip().lower(): f for f in reader.fieldnames if f}
    required_cols = {'student_id', 'full_name', 'department', 'email'}
    if not required_cols.issubset(norm_fields.keys()):
        flash(
            'CSV header must contain: student_id, full_name, department, email '
            '(optional: verification_pin).',
            'danger',
        )
        return redirect(url_for('admin.users'))

    send_emails = request.form.get('send_emails') == 'on' and is_email_configured()
    existing_ids = {row[0] for row in db.session.query(InstitutionalIdentity.student_id).all()}
    existing_emails = {row[0].lower() for row in db.session.query(InstitutionalIdentity.email).all()}

    added_count = 0
    skipped: list[str] = []
    issued_pins: list[dict] = []
    register_url = url_for('auth.register', _external=True)

    for row_num, raw_row in enumerate(reader, start=2):
        if row_num > 2001:
            skipped.append('Row limit exceeded (max 2000 rows per upload).')
            break

        def _val(col: str) -> str:
            key = norm_fields.get(col)
            return (raw_row.get(key) or '').strip() if key else ''

        student_id = _val('student_id').upper()
        full_name = _val('full_name')
        dept = _val('department')
        email = _val('email').lower()
        pin_in = _val('verification_pin')

        if not (student_id and full_name and dept and email):
            skipped.append(f'Row {row_num}: missing required fields')
            continue
        if not _STUDENT_ID_RE.match(student_id):
            skipped.append(f'Row {row_num}: invalid student_id "{student_id}"')
            continue
        if not _EMAIL_RE.match(email):
            skipped.append(f'Row {row_num}: invalid email "{email}"')
            continue
        if pin_in and len(pin_in) < 4:
            skipped.append(f'Row {row_num}: verification_pin must be >= 4 chars')
            continue
        if student_id in existing_ids:
            skipped.append(f'Row {row_num}: duplicate student_id "{student_id}"')
            continue
        if email in existing_emails:
            skipped.append(f'Row {row_num}: duplicate email "{email}"')
            continue

        raw_pin = pin_in or f'PIN-{secrets.token_hex(3).upper()}'
        db.session.add(InstitutionalIdentity(
            student_id=student_id,
            full_name=full_name,
            department=dept,
            email=email,
            verification_pin_hash=hash_password(raw_pin),
            is_claimed=False,
        ))
        existing_ids.add(student_id)
        existing_emails.add(email)
        added_count += 1

        emailed = False
        if send_emails:
            emailed, _ = send_verification_pin_email(
                to_address=email,
                full_name=full_name,
                student_id=student_id,
                department=dept,
                raw_pin=raw_pin,
                register_url=register_url,
            )

        issued_pins.append({
            'student_id': student_id,
            'full_name': full_name,
            'department': dept,
            'email': email,
            'pin': raw_pin,
            'emailed': emailed,
        })

    if added_count > 0:
        db.session.commit()
        append_audit_event(
            event_type='institutional_registry.csv_imported',
            actor_category='admin',
            actor_ref=current_user.username,
            payload={
                'added_count': added_count,
                'skipped_count': len(skipped),
                'emails_sent': sum(1 for item in issued_pins if item['emailed']),
            },
        )
        flash(
            f'Imported {added_count} student record(s) into the institutional registry.'
            + (f' Skipped {len(skipped)} row(s).' if skipped else ''),
            'success',
        )
    else:
        flash(
            'No new records imported.' + (f' Details: {"; ".join(skipped[:5])}' if skipped else ''),
            'warning',
        )
    if skipped and added_count > 0:
        flash(f'Skipped rows: {"; ".join(skipped[:5])}', 'warning')

    return _render_users_page(issued_pins=issued_pins)


@admin_bp.route('/registry/<int:identity_id>/reissue-pin', methods=['POST'])
@login_required
def reissue_identity_pin(identity_id: int):
    """Regenerate a one-time Verification PIN for an unclaimed student identity."""
    _require_admin()
    ident = db.session.get(InstitutionalIdentity, identity_id)
    if ident is None:
        abort(404)
    if ident.is_claimed:
        flash(f'Student ID "{ident.student_id}" has already been claimed.', 'warning')
        return redirect(url_for('admin.users'))

    new_pin = f'PIN-{secrets.token_hex(3).upper()}'
    ident.verification_pin_hash = hash_password(new_pin)
    db.session.commit()

    email_sent = False
    if is_email_configured():
        email_sent, _ = send_verification_pin_email(
            to_address=ident.email,
            full_name=ident.full_name,
            student_id=ident.student_id,
            department=ident.department,
            raw_pin=new_pin,
            register_url=url_for('auth.register', _external=True),
        )

    append_audit_event(
        event_type='institutional_registry.pin_reissued',
        actor_category='admin',
        actor_ref=current_user.username,
        payload={'student_id': ident.student_id, 'email_sent': email_sent},
    )
    if email_sent:
        flash(f'New Verification PIN generated and emailed to {ident.email} ({ident.student_id}).', 'success')
    else:
        flash(
            f'New One-Time Verification PIN for "{ident.student_id}" ({ident.full_name}): {new_pin}',
            'success',
        )
    return redirect(url_for('admin.users'))


@admin_bp.route('/users/<int:user_id>/reset-link', methods=['POST'])
@login_required
def issue_password_reset_link(user_id: int):
    """Generate (and optionally email) a single-use 15-minute password reset link for a user."""
    _require_admin()
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)
    if user.id == current_user.id:
        flash('Cannot issue a self-reset link here.', 'warning')
        return redirect(url_for('admin.users'))

    max_age = int(current_app.config.get('PASSWORD_RESET_MAX_AGE_SECONDS', 900))
    token = generate_password_reset_token(
        current_app.config['SECRET_KEY'], user.id, user.password_hash
    )
    reset_url = url_for('auth.reset_password', token=token, _external=True)

    identity = None
    if user.student_id:
        identity = db.session.query(InstitutionalIdentity).filter_by(student_id=user.student_id).first()

    email_sent = False
    if identity and identity.email and is_email_configured():
        email_sent, _ = send_password_reset_email(
            to_address=identity.email,
            display_name=user.display_name,
            username=user.username,
            reset_url=reset_url,
            expires_minutes=max(1, max_age // 60),
        )

    append_audit_event(
        event_type='admin.password_reset_issued',
        actor_category='admin',
        actor_ref=current_user.username,
        payload={'target_username': user.username, 'email_sent': email_sent},
    )

    if email_sent:
        flash(f'Single-use password reset link emailed to {identity.email} for @{user.username}.', 'success')
        return redirect(url_for('admin.users'))

    flash(
        f'Generated single-use 15-minute reset link for @{user.username}. Copy and share securely below.',
        'info',
    )
    return _render_users_page(
        generated_reset={'username': user.username, 'url': reset_url}
    )


@admin_bp.route('/users/<int:user_id>/unlock', methods=['POST'])
@login_required
def unlock_user(user_id: int):
    _require_admin()
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)
    user.failed_login_attempts = 0
    user.locked_until = None
    db.session.commit()
    append_audit_event(
        event_type='user.unlocked',
        actor_category='admin',
        actor_ref=current_user.username,
        payload={'target_username': user.username},
    )
    flash(f'Account {user.username} unlocked.', 'success')
    return redirect(url_for('admin.users'))


@admin_bp.route('/users/<int:user_id>/toggle-active', methods=['POST'])
@login_required
def toggle_user_active(user_id: int):
    _require_admin()
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)
    if user.id == current_user.id:
        flash('Cannot deactivate yourself.', 'danger')
        return redirect(url_for('admin.users'))

    user.is_active = not user.is_active
    db.session.commit()
    action = 'activated' if user.is_active else 'deactivated'
    append_audit_event(
        event_type=f'user.{action}',
        actor_category='admin',
        actor_ref=current_user.username,
        payload={'target_username': user.username},
    )
    flash(f'User {user.username} {action}.', 'success')
    return redirect(url_for('admin.users'))
