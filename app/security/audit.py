"""
app/security/audit.py — Hash-chained append-only audit log.

The audit chain provides tamper-evidence: each AuditEvent commits to the
hash of its predecessor.  Altering any event invalidates every subsequent
hash, making post-hoc tampering detectable by verify_audit_chain().

Hash construction:
    event_hash = SHA-256(prev_hash_bytes + canonical_json(safe_payload))

where prev_hash_bytes is the hex string encoded as UTF-8 bytes (not raw bytes),
keeping the input deterministic and human-readable.

Actor privacy:
  actor_ref stores an opaque string such as a username or "system".
  It NEVER stores raw user IDs to avoid linking audit rows to deleted accounts.
  Callers should pass, e.g., current_user.username or "system".
"""
import hashlib
import json
import logging
from typing import Optional

from .canonical import canonical_json

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Append an event
# ---------------------------------------------------------------------------

def append_audit_event(
    event_type: str,
    actor_category: str,
    actor_ref: str,
    payload: dict,
) -> 'AuditEvent':  # type: ignore[name-defined]
    """
    Append a new AuditEvent to the hash chain and flush it to the database.

    Args:
        event_type:     Dot-separated category, e.g. "user.login", "ballot.cast",
                        "election.status_change", "result.published".
        actor_category: Broad category — "user", "admin", or "system".
        actor_ref:      Opaque actor identifier (username, "system", etc.).
        payload:        Non-sensitive metadata dict stored verbatim as JSON.
                        MUST NOT contain passwords, keys, or PII beyond what is
                        necessary for audit purposes.

    Returns:
        The newly created and committed AuditEvent instance.

    Raises:
        SQLAlchemyError: On database write failure (caller should handle).
    """
    # Import here to avoid circular imports at module load time
    from ..models import AuditEvent
    from ..extensions import db

    # Determine prev_hash: last event's hash or genesis sentinel
    last_event: Optional[AuditEvent] = (
        db.session.query(AuditEvent)
        .order_by(AuditEvent.id.desc())
        .first()
    )
    prev_hash: str = last_event.event_hash if last_event else '0' * 64

    # Compute event hash
    canonical_payload: bytes = canonical_json(payload)
    hash_input: bytes = prev_hash.encode('utf-8') + canonical_payload
    event_hash: str = hashlib.sha256(hash_input).hexdigest()

    event = AuditEvent(
        event_type=event_type,
        actor_category=actor_category,
        actor_ref=actor_ref,
        safe_payload=json.dumps(payload, sort_keys=True),
        prev_hash=prev_hash,
        event_hash=event_hash,
    )

    db.session.add(event)
    db.session.commit()

    logger.debug(
        'AuditEvent appended: id=%s type=%s actor=%s hash=%s',
        event.id, event_type, actor_ref, event_hash[:16],
    )

    return event


# ---------------------------------------------------------------------------
# Verify the chain
# ---------------------------------------------------------------------------

def verify_audit_chain() -> dict:
    """
    Walk every AuditEvent in insertion order and verify the hash chain.

    Returns:
        dict with keys:
          verified (bool)         — True if all hashes are consistent.
          event_count (int)       — Total number of events inspected.
          first_failing_id (int?) — ID of the first event that fails, or None.
          message (str)           — Human-readable summary.

    This function is intentionally read-only and never modifies the database.
    It can be called by the admin dashboard or a CLI command to detect tampering.
    """
    from ..models import AuditEvent
    from ..extensions import db

    events = (
        db.session.query(AuditEvent)
        .order_by(AuditEvent.id.asc())
        .all()
    )

    if not events:
        return {
            'verified': True,
            'event_count': 0,
            'first_failing_id': None,
            'message': 'Audit chain is empty — nothing to verify.',
        }

    expected_prev_hash = '0' * 64

    for event in events:
        # Check prev_hash linkage
        if event.prev_hash != expected_prev_hash:
            return {
                'verified': False,
                'event_count': len(events),
                'first_failing_id': event.id,
                'message': (
                    f'Chain broken at event id={event.id}: '
                    f'expected prev_hash={expected_prev_hash[:16]}... '
                    f'got {event.prev_hash[:16]}...'
                ),
            }

        # Recompute event_hash
        try:
            payload_dict = json.loads(event.safe_payload)
        except (json.JSONDecodeError, TypeError) as exc:
            return {
                'verified': False,
                'event_count': len(events),
                'first_failing_id': event.id,
                'message': f'Failed to parse payload for event id={event.id}: {exc}',
            }

        canonical_payload = canonical_json(payload_dict)
        hash_input = event.prev_hash.encode('utf-8') + canonical_payload
        recomputed_hash = hashlib.sha256(hash_input).hexdigest()

        if recomputed_hash != event.event_hash:
            return {
                'verified': False,
                'event_count': len(events),
                'first_failing_id': event.id,
                'message': (
                    f'Tamper detected: Hash mismatch at event id={event.id}: '
                    f'stored={event.event_hash[:16]}... '
                    f'recomputed={recomputed_hash[:16]}...'
                ),
            }

        expected_prev_hash = event.event_hash

    return {
        'verified': True,
        'event_count': len(events),
        'first_failing_id': None,
        'message': f'Audit chain verified OK — {len(events)} event(s) checked.',
    }
