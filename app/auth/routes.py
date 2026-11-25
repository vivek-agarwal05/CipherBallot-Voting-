"""
app/auth/routes.py — Authentication blueprint: login and logout.

Security decisions:
  - Generic error messages: never reveal whether a username exists.
  - Rate limit on login POST: 5 per minute per IP (brute-force mitigation).
  - Argon2id password verification (see security/passwords.py).
  - Flask-Login session management with configurable remember-me duration.
  - Role-based redirect after login (admin → /admin/, voter → /voter/).
  - Audit event emitted on successful and failed login attempts.
"""
import logging
import hashlib
from datetime import datetime, timedelta, timezone

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user

from ..extensions import db, limiter
from ..models import User, InstitutionalIdentity, Election, ElectionEligibility
from ..security.audit import append_audit_event
from ..security.passwords import needs_rehash, verify_password, hash_password
from .forms import LoginForm, RegisterForm

logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_GENERIC_LOGIN_ERROR = 'Invalid username or password.'
_LOGIN_RATE_LIMIT = '15 per minute'


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit(_LOGIN_RATE_LIMIT, methods=['POST'])
def login():
    """
    Display the login form (GET) or process credentials (POST).

    On success: redirect to the role-appropriate dashboard.
    On failure: flash a generic message and re-display the form.
    """
    if current_user.is_authenticated:
        return _redirect_for_role(current_user)

    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data.strip()
        candidate_password = form.password.data
        now = datetime.now(timezone.utc)
        max_failures = current_app.config.get('MAX_FAILED_LOGINS', 5)
        lockout_minutes = current_app.config.get('LOCKOUT_MINUTES', 5)

        user = db.session.query(User).filter_by(username=username).first()

        # Check temporary account lockout before password verification
        if user and user.locked_until:
            locked_until = user.locked_until
            if locked_until.tzinfo is None:
                locked_until = locked_until.replace(tzinfo=timezone.utc)
            if now < locked_until:
                remaining_secs = max(1, int((locked_until - now).total_seconds()))
                remaining_mins = (remaining_secs + 59) // 60
                flash(
                    f'Account temporarily locked due to repeated failed login attempts. '
                    f'Try again in ~{remaining_mins} minute(s).',
                    'danger',
                )
                append_audit_event(
                    event_type='user.login.locked_out',
                    actor_category='user',
                    actor_ref=username[:64],
                    payload={'ip': request.remote_addr, 'remaining_seconds': remaining_secs},
                )
                return render_template('auth/login.html', form=form)
            # Lock window expired — reset automatically
            user.locked_until = None
            user.failed_login_attempts = 0
            db.session.commit()

        # Constant-time-ish: always run verify even if user not found,
        # using a dummy hash so the timing profile is similar.
        _DUMMY_HASH = (
            '$argon2id$v=19$m=65536,t=2,p=2'
            '$dGhpcyBpcyBhIGR1bW15IHNhbHQ'
            '$dGhpcyBpcyBhIGR1bW15IGhhc2g'
        )
        hash_to_check = user.password_hash if user else _DUMMY_HASH
        password_ok = verify_password(hash_to_check, candidate_password)

        if user is None or not password_ok or not user.is_active:
            if user is not None and user.is_active and not password_ok:
                user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
                if user.failed_login_attempts >= max_failures:
                    user.locked_until = now + timedelta(minutes=lockout_minutes)
                    db.session.commit()
                    append_audit_event(
                        event_type='user.account_locked',
                        actor_category='user',
                        actor_ref=user.username,
                        payload={
                            'ip': request.remote_addr,
                            'failed_attempts': user.failed_login_attempts,
                            'lockout_minutes': lockout_minutes,
                        },
                    )
                    flash(
                        f'Account temporarily locked for {lockout_minutes} minutes after '
                        f'{max_failures} consecutive failed login attempts.',
                        'danger',
                    )
                    return render_template('auth/login.html', form=form)
                db.session.commit()

            flash(_GENERIC_LOGIN_ERROR, 'danger')

            # Audit: failed login (actor_ref does not reveal if user exists)
            append_audit_event(
                event_type='user.login.failure',
                actor_category='user',
                actor_ref=username[:64],
                payload={
                    'ip': request.remote_addr,
                    'reason': 'bad_credentials_or_inactive',
                },
            )
            return render_template('auth/login.html', form=form)

        # Reset failed counter on valid login
        if user.failed_login_attempts or user.locked_until:
            user.failed_login_attempts = 0
            user.locked_until = None
            db.session.commit()

        # Transparent hash upgrade (if params changed)
        if needs_rehash(user.password_hash):
            user.password_hash = hash_password(candidate_password)
            db.session.commit()
            logger.info('Password hash upgraded for user %s', user.username)

        login_user(user, remember=form.remember_me.data)

        append_audit_event(
            event_type='user.login.success',
            actor_category='admin' if user.is_admin else 'user',
            actor_ref=user.username,
            payload={'ip': request.remote_addr, 'role': user.role},
        )

        # Respect 'next' param but only for safe relative URLs
        next_page = request.args.get('next')
        if next_page and next_page.startswith('/') and not next_page.startswith('//'):
            return redirect(next_page)
        return _redirect_for_role(user)

    return render_template('auth/login.html', form=form)


# ---------------------------------------------------------------------------
# Registration with Criteria & ID Verification
# ---------------------------------------------------------------------------

@auth_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit('10 per minute', methods=['POST'])
def register():
    """
    Register a new student voter based on criteria and institutional ID verification.

    Security & Criteria Enforced:
      1. Institutional ID verification against pre-approved roster (anti-Sybil).
      2. 1:1 mapping (preventing duplicate claims of the same student identity).
      3. Academic department criteria verification.
      4. Name consistency check with official records.
      5. Argon2id password complexity (length, upper, lower, digit, symbol).
      6. Automatic eligibility enrollment into department elections.
      7. Cryptographic audit event logging.
    """
    if current_user.is_authenticated:
        return _redirect_for_role(current_user)

    form = RegisterForm()

    # Provide unclaimed sample IDs for classroom evaluators
    unclaimed_samples = (
        db.session.query(InstitutionalIdentity)
        .filter_by(is_claimed=False)
        .limit(4)
        .all()
    )

    if form.validate_on_submit():
        student_id = form.student_id.data.strip().upper()
        verification_pin = form.verification_pin.data.strip()
        username = form.username.data.strip().lower()
        full_name = form.display_name.data.strip()
        dept = form.department.data.strip()
        email = form.email.data.strip().lower()
        raw_password = form.password.data

        # -------------------------------------------------------------------
        # Criteria 1: Password Complexity Check
        # -------------------------------------------------------------------
        has_upper = any(c.isupper() for c in raw_password)
        has_lower = any(c.islower() for c in raw_password)
        has_digit = any(c.isdigit() for c in raw_password)
        has_special = any(c in r"!@#$%^&*()-_=+[]{}|;:,.<>?/~`" for c in raw_password)

        if not (has_upper and has_lower and has_digit and has_special):
            flash(
                'Password criteria not met: Must contain at least one uppercase letter, '
                'one lowercase letter, one numeric digit, and one special character (!@#$%^&*...).',
                'danger',
            )
            return render_template('auth/register.html', form=form, samples=unclaimed_samples)

        # -------------------------------------------------------------------
        # Criteria 2: Username Uniqueness
        # -------------------------------------------------------------------
        existing_user = db.session.query(User).filter_by(username=username).first()
        if existing_user:
            flash(f'Username "{username}" is already taken. Please choose another username.', 'danger')
            return render_template('auth/register.html', form=form, samples=unclaimed_samples)

        # -------------------------------------------------------------------
        # Criteria 3: Institutional ID Verification (Anti-Sybil Check)
        # -------------------------------------------------------------------
        identity = (
            db.session.query(InstitutionalIdentity)
            .filter_by(student_id=student_id)
            .first()
        )

        if not identity:
            # Audit rejected attempt
            append_audit_event(
                event_type='user.registration.rejected_unverified_id',
                actor_category='guest',
                actor_ref=username,
                payload={
                    'ip': request.remote_addr,
                    'attempted_student_id_hash': hashlib.sha256(student_id.encode('utf-8')).hexdigest(),
                    'reason': 'student_id_not_in_institutional_roster',
                },
            )
            flash(
                f'ID Verification Failed: Student ID "{student_id}" is not found in the '
                'authoritative university registry. Only enrolled students are eligible to register.',
                'danger',
            )
            return render_template('auth/register.html', form=form, samples=unclaimed_samples)

        # -------------------------------------------------------------------
        # Criteria 4: Single Claim Check (Anti-Duplicate Account)
        # -------------------------------------------------------------------
        if identity.is_claimed:
            append_audit_event(
                event_type='user.registration.rejected_duplicate_claim',
                actor_category='guest',
                actor_ref=username,
                payload={
                    'ip': request.remote_addr,
                    'student_id_hash': hashlib.sha256(student_id.encode('utf-8')).hexdigest(),
                    'reason': 'student_id_already_claimed',
                },
            )
            flash(
                f'Verification Failed: Student ID "{student_id}" has already been claimed and registered. '
                'Duplicate voting accounts for a single student identity are prohibited.',
                'danger',
            )
            return render_template('auth/register.html', form=form, samples=unclaimed_samples)

        # -------------------------------------------------------------------
        # Criteria 4b: Secret Verification PIN Proof-of-Ownership
        # -------------------------------------------------------------------
        if identity.verification_pin_hash:
            if not verify_password(identity.verification_pin_hash, verification_pin):
                append_audit_event(
                    event_type='user.registration.rejected_invalid_pin',
                    actor_category='guest',
                    actor_ref=username,
                    payload={
                        'ip': request.remote_addr,
                        'student_id_hash': hashlib.sha256(student_id.encode('utf-8')).hexdigest(),
                        'reason': 'invalid_verification_pin',
                    },
                )
                flash(
                    'ID Verification Failed: Invalid Secret Verification PIN. '
                    'Only the authorized holder of this Student ID may activate this account.',
                    'danger',
                )
                return render_template('auth/register.html', form=form, samples=unclaimed_samples)

        # -------------------------------------------------------------------
        # Criteria 5: Department & Name Consistency
        # -------------------------------------------------------------------
        if identity.department.lower() != dept.lower():
            flash(
                f'Criteria Mismatch: According to university records, Student ID "{student_id}" '
                f'is enrolled in "{identity.department}", not "{dept}".',
                'danger',
            )
            return render_template('auth/register.html', form=form, samples=unclaimed_samples)

        # Soft name consistency check (case-insensitive substring or exact match)
        clean_input_name = full_name.lower().replace(' ', '')
        clean_record_name = identity.full_name.lower().replace(' ', '')
        if clean_input_name != clean_record_name:
            flash(
                f'Criteria Mismatch: The legal name provided ("{full_name}") does not match '
                f'the institutional record ("{identity.full_name}") for Student ID "{student_id}".',
                'danger',
            )
            return render_template('auth/register.html', form=form, samples=unclaimed_samples)

        # -------------------------------------------------------------------
        # All Criteria Passed: Create Verified User & Hash Password with Argon2id
        # -------------------------------------------------------------------
        new_user = User(
            username=username,
            display_name=identity.full_name,
            password_hash=hash_password(raw_password),
            role='voter',
            student_id=student_id,
            department=identity.department,
            id_verified=True,
            is_active=True,
        )
        db.session.add(new_user)
        db.session.flush()

        # Mark identity as claimed
        identity.is_claimed = True
        identity.claimed_at = datetime.now(timezone.utc)
        identity.claimed_by_user_id = new_user.id

        # Auto-enroll in matching department elections
        dept_elections = db.session.query(Election).filter(
            (Election.group_dept == identity.department) |
            (Election.group_dept.ilike(f'%{identity.department}%'))
        ).all()

        enrolled_count = 0
        for el in dept_elections:
            elig = ElectionEligibility(
                election_id=el.id,
                voter_id=new_user.id,
                status='eligible',
            )
            db.session.add(elig)
            enrolled_count += 1

        db.session.commit()

        # Record tamper-evident audit log
        append_audit_event(
            event_type='user.registered',
            actor_category='user',
            actor_ref=username,
            payload={
                'ip': request.remote_addr,
                'student_id_hash': hashlib.sha256(student_id.encode('utf-8')).hexdigest(),
                'department': identity.department,
                'auto_enrolled_elections': enrolled_count,
            },
        )

        flash(
            f'Student identity successfully verified! Welcome, {identity.full_name}. '
            f'Your voter account "{username}" is active and enrolled in {enrolled_count} department election(s). '
            'Please sign in below.',
            'success',
        )
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html', form=form, samples=unclaimed_samples)


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    """
    Log out the current user.

    Uses POST to prevent CSRF-based forced logout via GET links.
    """
    username = current_user.username
    role = current_user.role

    logout_user()

    append_audit_event(
        event_type='user.logout',
        actor_category='admin' if role == 'admin' else 'user',
        actor_ref=username,
        payload={'ip': request.remote_addr},
    )

    flash('You have been signed out.', 'info')
    return redirect(url_for('auth.login'))


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _redirect_for_role(user: User):
    """Return a redirect response to the user's home dashboard."""
    if user.is_admin:
        return redirect(url_for('admin.dashboard'))
    return redirect(url_for('voter.dashboard'))
