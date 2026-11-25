from app.security.audit import append_audit_event, verify_audit_chain
from app.models import AuditEvent


def test_audit_chain_verifies_intact(app, db):
    """An unaltered sequence of audit events verifies successfully."""
    with app.app_context():
        append_audit_event('election.create', 'admin', 'admin', {'election_id': 1})
        append_audit_event('ballot.cast', 'voter', 'alice', {'ballot_id': 'uuid-1'})
        append_audit_event('election.close', 'admin', 'admin', {'election_id': 1})

        report = verify_audit_chain()
        assert report['verified'] is True
        assert report['event_count'] == 3
        assert report['first_failing_id'] is None


def test_audit_chain_detects_tampered_event(app, db):
    """Modifying an audit event's payload breaks the hash chain."""
    with app.app_context():
        append_audit_event('event.alpha', 'system', 'sys', {'data': 100})
        append_audit_event('event.beta', 'system', 'sys', {'data': 200})
        append_audit_event('event.gamma', 'system', 'sys', {'data': 300})

        # Tamper with event 2 in the database
        ev2 = db.session.query(AuditEvent).filter_by(id=2).first()
        ev2.safe_payload = '{"data": 99999}'  # Tampered!
        db.session.commit()

        report = verify_audit_chain()
        assert report['verified'] is False
        assert report['first_failing_id'] == 2
        assert 'tamper' in report['message'].lower() or 'chain broken' in report['message'].lower()
