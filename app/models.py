"""
app/models.py — CipherBallot database models.

Privacy design decisions (documented intentionally):
- Participation has NO candidate_id and NO ballot_id: it only records that
  a voter cast a ballot, never which candidate they chose.
- EncryptedBallot has NO voter_id: once stored, ciphertexts cannot be linked
  back to any individual.
- Receipt has NO voter_id: the receipt code is the only link between a voter
  and their encrypted ballot digest, and even that reveals nothing about the
  vote choice.
- AuditEvent forms a hash-chain (append-only integrity log).
"""

import uuid
from datetime import datetime, timezone

from flask_login import UserMixin
from sqlalchemy import (
    Boolean, Column, DateTime, Enum, ForeignKey, Index,
    Integer, String, Text, UniqueConstraint,
)
from sqlalchemy.orm import relationship

from .extensions import db, login_manager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_utc() -> datetime:
    """Return timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def _uuid_str() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# User loader (required by Flask-Login)
# ---------------------------------------------------------------------------

@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))


# ---------------------------------------------------------------------------
# User
# ---------------------------------------------------------------------------

class User(UserMixin, db.Model):
    """
    Application user.  Can be an admin or a voter.

    Passwords are stored as Argon2id hashes (see security/passwords.py).
    The ``role`` column gates access to admin routes.
    """
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    display_name = Column(String(128), nullable=False)
    password_hash = Column(String(256), nullable=False)
    role = Column(
        Enum('admin', 'voter', name='user_role'),
        nullable=False,
        default='voter',
    )
    student_id = Column(String(64), unique=True, nullable=True, index=True)
    department = Column(String(128), nullable=True)
    id_verified = Column(Boolean, nullable=False, default=True)
    is_active = Column(Boolean, nullable=False, default=True)
    failed_login_attempts = Column(Integer, nullable=False, default=0)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_now_utc)

    # Relationships
    elections_created = relationship(
        'Election', back_populates='creator', foreign_keys='Election.created_by',
        lazy='dynamic',
    )
    eligibilities = relationship('ElectionEligibility', back_populates='voter', lazy='dynamic')
    participations = relationship('Participation', back_populates='voter', lazy='dynamic')

    def __repr__(self) -> str:
        return f'<User id={self.id} username={self.username!r} role={self.role}>'

    @property
    def is_admin(self) -> bool:
        return self.role == 'admin'


# ---------------------------------------------------------------------------
# Election
# ---------------------------------------------------------------------------

class Election(db.Model):
    """
    An election or poll managed by an admin.

    Lifecycle: draft → open → closed → published
    ``variant`` mirrors the global PROJECT_VARIANT so the UI can display the
    correct cryptographic variant label for each election.
    """
    __tablename__ = 'elections'

    id = Column(Integer, primary_key=True)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    group_dept = Column(String(128), nullable=True)   # e.g. "CS Department"
    start_dt = Column(DateTime(timezone=True), nullable=True)
    end_dt = Column(DateTime(timezone=True), nullable=True)
    status = Column(
        Enum('draft', 'open', 'closed', 'published', name='election_status'),
        nullable=False,
        default='draft',
        index=True,
    )
    variant = Column(String(8), nullable=False, default='B')
    created_by = Column(Integer, ForeignKey('users.id'), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_now_utc)
    updated_at = Column(
        DateTime(timezone=True), nullable=False, default=_now_utc, onupdate=_now_utc,
    )

    # Relationships
    creator = relationship('User', back_populates='elections_created', foreign_keys=[created_by])
    candidates = relationship(
        'Candidate', back_populates='election',
        order_by='Candidate.display_order', cascade='all, delete-orphan',
    )
    eligibilities = relationship(
        'ElectionEligibility', back_populates='election', cascade='all, delete-orphan',
    )
    participations = relationship(
        'Participation', back_populates='election', cascade='all, delete-orphan',
    )
    encrypted_ballots = relationship(
        'EncryptedBallot', back_populates='election', cascade='all, delete-orphan',
    )
    receipts = relationship(
        'Receipt', back_populates='election', cascade='all, delete-orphan',
    )
    published_result = relationship(
        'PublishedResult', back_populates='election',
        uselist=False, cascade='all, delete-orphan',
    )
    anonymous_tokens = relationship(
        'AnonymousToken', back_populates='election', cascade='all, delete-orphan',
    )

    def __repr__(self) -> str:
        return f'<Election id={self.id} title={self.title!r} status={self.status}>'

    @property
    def is_open(self) -> bool:
        return self.status == 'open'

    @property
    def vote_count(self) -> int:
        return len(self.encrypted_ballots)


# ---------------------------------------------------------------------------
# Candidate
# ---------------------------------------------------------------------------

class Candidate(db.Model):
    """
    A candidate (or option) within an election.
    ``display_order`` controls presentation order on the ballot.
    """
    __tablename__ = 'candidates'

    id = Column(Integer, primary_key=True)
    election_id = Column(Integer, ForeignKey('elections.id'), nullable=False, index=True)
    display_name = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    display_order = Column(Integer, nullable=False, default=0)

    # Relationships
    election = relationship('Election', back_populates='candidates')

    def __repr__(self) -> str:
        return f'<Candidate id={self.id} name={self.display_name!r} election_id={self.election_id}>'


# ---------------------------------------------------------------------------
# ElectionEligibility
# ---------------------------------------------------------------------------

class ElectionEligibility(db.Model):
    """
    Records whether a specific voter is eligible to vote in a specific election.

    The admin explicitly grants or revokes eligibility.  An eligible voter who
    has not yet cast a ballot does NOT appear in Participation.
    """
    __tablename__ = 'election_eligibilities'
    __table_args__ = (
        UniqueConstraint('election_id', 'voter_id', name='uq_eligibility_election_voter'),
        Index('ix_eligibility_election', 'election_id'),
        Index('ix_eligibility_voter', 'voter_id'),
    )

    id = Column(Integer, primary_key=True)
    election_id = Column(Integer, ForeignKey('elections.id'), nullable=False)
    voter_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    status = Column(
        Enum('eligible', 'ineligible', name='eligibility_status'),
        nullable=False,
        default='eligible',
    )
    added_at = Column(DateTime(timezone=True), nullable=False, default=_now_utc)

    # Relationships
    election = relationship('Election', back_populates='eligibilities')
    voter = relationship('User', back_populates='eligibilities')

    def __repr__(self) -> str:
        return (
            f'<ElectionEligibility election_id={self.election_id} '
            f'voter_id={self.voter_id} status={self.status}>'
        )


# ---------------------------------------------------------------------------
# Participation
# ---------------------------------------------------------------------------

class Participation(db.Model):
    """
    Records that a voter has cast a ballot in an election.

    Privacy guarantee: intentionally stores NO candidate_id and NO ballot_id.
    This prevents linking the participation record to any vote choice.
    The only information stored is *that* the voter participated, not *how*.
    """
    __tablename__ = 'participations'
    __table_args__ = (
        UniqueConstraint('election_id', 'voter_id', name='uq_participation_election_voter'),
        Index('ix_participation_election', 'election_id'),
        Index('ix_participation_voter', 'voter_id'),
    )

    id = Column(Integer, primary_key=True)
    election_id = Column(Integer, ForeignKey('elections.id'), nullable=False)
    voter_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    cast_at = Column(DateTime(timezone=True), nullable=False, default=_now_utc)
    status = Column(
        Enum('voted', 'token_issued', name='participation_status'),
        nullable=False,
        default='voted',
    )

    # Relationships
    election = relationship('Election', back_populates='participations')
    voter = relationship('User', back_populates='participations')

    def __repr__(self) -> str:
        return (
            f'<Participation election_id={self.election_id} '
            f'voter_id={self.voter_id} cast_at={self.cast_at}>'
        )


# ---------------------------------------------------------------------------
# EncryptedBallot
# ---------------------------------------------------------------------------

class EncryptedBallot(db.Model):
    """
    An AES-256-GCM encrypted ballot ciphertext.

    Privacy guarantee: intentionally stores NO voter_id and NO candidate_id.
    The ballot_id (UUID) is randomly generated at cast time and is NOT stored
    anywhere that can be linked back to the voter.

    Fields:
      nonce_hex      — 12-byte GCM nonce, hex-encoded (never reused)
      ciphertext_hex — Encrypted ballot payload, hex-encoded
      tag_hex        — 16-byte GCM authentication tag, hex-encoded
      aad_hex        — Additional Authenticated Data, hex-encoded
                       (binds ciphertext to election_id + ballot_id)
      algorithm      — Cipher identifier, e.g. "AES-256-GCM"
      version        — Schema version for future migration
    """
    __tablename__ = 'encrypted_ballots'

    id = Column(String(36), primary_key=True, default=_uuid_str)
    election_id = Column(Integer, ForeignKey('elections.id'), nullable=False, index=True)
    nonce_hex = Column(String(24), nullable=False)      # 12 bytes → 24 hex chars
    ciphertext_hex = Column(Text, nullable=False)
    tag_hex = Column(String(32), nullable=False)        # 16 bytes → 32 hex chars
    aad_hex = Column(Text, nullable=False)
    wrapped_key_hex = Column(Text, nullable=True)       # RSA-OAEP encrypted per-ballot AES key
    algorithm = Column(String(32), nullable=False, default='RSA-OAEP+AES-256-GCM')
    version = Column(Integer, nullable=False, default=2)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_now_utc)

    # Relationships
    election = relationship('Election', back_populates='encrypted_ballots')
    receipt = relationship('Receipt', back_populates='ballot', uselist=False)

    def __repr__(self) -> str:
        return f'<EncryptedBallot id={self.id} election_id={self.election_id}>'


# ---------------------------------------------------------------------------
# Receipt
# ---------------------------------------------------------------------------

class Receipt(db.Model):
    """
    A verifiable receipt given to a voter after casting.

    Privacy guarantee: intentionally stores NO voter_id.
    The receipt_code is a random token the voter can use to verify their
    ballot was recorded; it reveals nothing about the vote choice.

    ballot_digest_hex: SHA-256 of (election_id || ballot_id || nonce || ciphertext || tag)
    """
    __tablename__ = 'receipts'

    id = Column(Integer, primary_key=True)
    receipt_code = Column(String(64), unique=True, nullable=False, index=True)
    election_id = Column(Integer, ForeignKey('elections.id'), nullable=False, index=True)
    ballot_id = Column(String(36), ForeignKey('encrypted_ballots.id'), nullable=False)
    ballot_digest_hex = Column(String(64), nullable=False)  # SHA-256 hex
    created_at = Column(DateTime(timezone=True), nullable=False, default=_now_utc)

    # Relationships
    election = relationship('Election', back_populates='receipts')
    ballot = relationship('EncryptedBallot', back_populates='receipt')

    def __repr__(self) -> str:
        return f'<Receipt id={self.id} code={self.receipt_code[:8]}... election_id={self.election_id}>'


# ---------------------------------------------------------------------------
# AuditEvent
# ---------------------------------------------------------------------------

class AuditEvent(db.Model):
    """
    An append-only, hash-chained audit log event.

    Each event records:
      event_type    — Semantic category, e.g. "user.login", "ballot.cast"
      actor_category— "user", "admin", "system"
      actor_ref     — Opaque string identifying the actor (username or "system")
                      Never stores raw user IDs to avoid linking audit events to
                      deleted accounts.
      safe_payload  — JSON dict of non-sensitive metadata for the event
      prev_hash     — Hash of the immediately preceding AuditEvent (or '0'*64)
      event_hash    — SHA-256(prev_hash + canonical_json(safe_payload))

    The hash chain makes post-hoc tampering detectable: altering any event
    invalidates the hash of every subsequent event.
    """
    __tablename__ = 'audit_events'

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_type = Column(String(64), nullable=False, index=True)
    actor_category = Column(String(32), nullable=False)
    actor_ref = Column(String(128), nullable=False)
    safe_payload = Column(Text, nullable=False)        # JSON string
    prev_hash = Column(String(64), nullable=False)
    event_hash = Column(String(64), nullable=False, unique=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_now_utc, index=True)

    def __repr__(self) -> str:
        return (
            f'<AuditEvent id={self.id} type={self.event_type!r} '
            f'actor={self.actor_ref!r}>'
        )


# ---------------------------------------------------------------------------
# PublishedResult
# ---------------------------------------------------------------------------

class PublishedResult(db.Model):
    """
    The final, cryptographically signed tally for a closed election.

    result_json  — JSON string of {candidate_id: vote_count, ...}
    signature_hex— Ed25519 signature over the canonical result bytes
    public_key_id— Identifier/fingerprint of the signing public key
                   (allows key rotation without ambiguity)
    """
    __tablename__ = 'published_results'

    id = Column(Integer, primary_key=True)
    election_id = Column(Integer, ForeignKey('elections.id'), nullable=False, unique=True)
    result_json = Column(Text, nullable=False)
    signature_hex = Column(String(128), nullable=False)   # Ed25519 sig → 64 bytes → 128 hex
    public_key_id = Column(String(128), nullable=False)
    published_at = Column(DateTime(timezone=True), nullable=False, default=_now_utc)

    # Relationships
    election = relationship('Election', back_populates='published_result')

    def __repr__(self) -> str:
        return f'<PublishedResult election_id={self.election_id} published_at={self.published_at}>'


# ---------------------------------------------------------------------------
# AnonymousToken (Variant C — Unlinked One-Time Blind-Style Voting Tokens)
# ---------------------------------------------------------------------------

class AnonymousToken(db.Model):
    """
    One-time anonymous ballot authorization token for Variant C elections.

    Privacy guarantee:
      - Stores ONLY SHA-256(raw_token), NEVER voter_id or username.
      - Issued during Phase 1 after checking eligibility & marking Participation.
      - Redeemed during Phase 2 anonymously to submit an EncryptedBallot.
    """
    __tablename__ = 'anonymous_tokens'

    id = Column(Integer, primary_key=True)
    election_id = Column(Integer, ForeignKey('elections.id'), nullable=False, index=True)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)
    is_spent = Column(Boolean, nullable=False, default=False)
    issued_at = Column(DateTime(timezone=True), nullable=False, default=_now_utc)
    spent_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    election = relationship('Election', back_populates='anonymous_tokens')

    def __repr__(self) -> str:
        return f'<AnonymousToken id={self.id} election_id={self.election_id} spent={self.is_spent}>'


# ---------------------------------------------------------------------------
# InstitutionalIdentity (Pre-verified University Registry for Criteria & ID Check)
# ---------------------------------------------------------------------------

class InstitutionalIdentity(db.Model):
    """
    Authoritative institutional student identity roster.
    
    Used to enforce ID verification and eligibility criteria prior to account creation:
      - Prevents Sybil attacks and arbitrary unregistered accounts.
      - Requires a one-time secret Verification PIN (Argon2id hashed) to prove ownership.
      - Enforces 1:1 mapping between institutional Student ID and voting account.
      - Guarantees voter belongs to an authorized department and degree cohort.
    """
    __tablename__ = 'institutional_identities'

    id = Column(Integer, primary_key=True)
    student_id = Column(String(64), unique=True, nullable=False, index=True)
    full_name = Column(String(128), nullable=False)
    department = Column(String(128), nullable=False)
    email = Column(String(128), unique=True, nullable=False)
    verification_pin_hash = Column(String(256), nullable=True)
    is_claimed = Column(Boolean, nullable=False, default=False)
    claimed_at = Column(DateTime(timezone=True), nullable=True)
    claimed_by_user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_now_utc)

    # Relationships
    claimed_by = relationship('User', foreign_keys=[claimed_by_user_id])

    def __repr__(self) -> str:
        return f'<InstitutionalIdentity student_id={self.student_id!r} claimed={self.is_claimed}>'
