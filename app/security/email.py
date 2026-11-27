"""
app/security/email.py — Optional SMTP email delivery for PINs and password resets.

Uses Python's standard library smtplib + ssl so no extra third-party mail API
keys are required. When MAIL_SERVER/MAIL_USERNAME/MAIL_PASSWORD are not set,
send_email() returns (False, reason) cleanly so callers can fall back to manual
admin distribution.
"""
import logging
import smtplib
import ssl
from email.message import EmailMessage

from flask import current_app

logger = logging.getLogger(__name__)


def is_email_configured() -> bool:
    """Return True if minimum SMTP settings are configured."""
    cfg = current_app.config
    return bool(
        cfg.get('MAIL_SERVER')
        and cfg.get('MAIL_USERNAME')
        and cfg.get('MAIL_PASSWORD')
    )


def send_email(to_address: str, subject: str, body_text: str) -> tuple[bool, str | None]:
    """
    Send a plain-text email over TLS/SSL SMTP.

    Returns:
        (sent_ok: bool, error_message: str | None)
    """
    if not is_email_configured():
        return False, 'SMTP email is not configured.'

    cfg = current_app.config
    server_host: str = cfg['MAIL_SERVER']
    port: int = int(cfg.get('MAIL_PORT', 587))
    use_ssl: bool = bool(cfg.get('MAIL_USE_SSL', False))
    use_tls: bool = bool(cfg.get('MAIL_USE_TLS', True))
    username: str = cfg['MAIL_USERNAME']
    password: str = cfg['MAIL_PASSWORD']
    sender: str = cfg.get('MAIL_DEFAULT_SENDER') or username

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = to_address
    msg.set_content(body_text)

    context = ssl.create_default_context()
    try:
        if use_ssl:
            with smtplib.SMTP_SSL(server_host, port, timeout=10, context=context) as smtp:
                smtp.login(username, password)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(server_host, port, timeout=10) as smtp:
                if use_tls:
                    smtp.starttls(context=context)
                smtp.login(username, password)
                smtp.send_message(msg)
        return True, None
    except Exception as exc:
        logger.warning('SMTP delivery failed to %s: %s', to_address, exc)
        return False, str(exc)


def send_verification_pin_email(
    to_address: str,
    full_name: str,
    student_id: str,
    department: str,
    raw_pin: str,
    register_url: str,
) -> tuple[bool, str | None]:
    """Send a student's one-time registration Verification PIN via email."""
    subject = 'CipherBallot — Your Student Voter Verification PIN'
    body = (
        f"Hello {full_name},\n\n"
        f"Your student identity has been authorized for CipherBallot voter registration.\n\n"
        f"  Student ID:       {student_id}\n"
        f"  Department:       {department}\n"
        f"  Verification PIN: {raw_pin}\n\n"
        f"Register your voter account at:\n"
        f"  {register_url}\n\n"
        f"Keep your Verification PIN confidential; it can only be used once.\n"
    )
    return send_email(to_address, subject, body)


def send_password_reset_email(
    to_address: str,
    display_name: str,
    username: str,
    reset_url: str,
    expires_minutes: int = 15,
) -> tuple[bool, str | None]:
    """Send a single-use password reset link to a verified voter email."""
    subject = 'CipherBallot — Password Reset Request'
    body = (
        f"Hello {display_name} (@{username}),\n\n"
        f"We received a request to reset your CipherBallot password.\n"
        f"Use the single-use link below within {expires_minutes} minutes:\n\n"
        f"  {reset_url}\n\n"
        f"If you did not request this, you can safely ignore this email.\n"
    )
    return send_email(to_address, subject, body)
