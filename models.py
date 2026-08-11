"""
SentinelLog - Database Models
Defines what gets saved permanently to disk (sessions, alerts, the admin user).
"""
import os
import json
from datetime import datetime
from cryptography.fernet import Fernet, InvalidToken
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy.types import TypeDecorator, String

db = SQLAlchemy()


def _get_fernet():
    key = os.environ.get('ENCRYPTION_KEY')
    if not key:
        raise RuntimeError(
            "ENCRYPTION_KEY is missing from your .env file. "
            "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\" "
            "and add it as ENCRYPTION_KEY=... in .env"
        )
    return Fernet(key.encode())


class EncryptedString(TypeDecorator):
    """
    A column type that encrypts values before they hit the database and decrypts
    them automatically when read back. Used for anything sensitive — Telegram tokens,
    email passwords — so a copy of the .db file alone isn't enough to read them.
    """
    impl = String
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None or value == '':
            return value
        return _get_fernet().encrypt(value.encode()).decode()

    def process_result_value(self, value, dialect):
        if value is None or value == '':
            return value
        try:
            return _get_fernet().decrypt(value.encode()).decode()
        except InvalidToken:
            # Value predates encryption being added — treat it as legacy plaintext
            # rather than crashing. Re-saving the row will encrypt it going forward.
            return value


class IPBlock(db.Model):
    """Audit trail of every automated block — active or expired."""
    __tablename__ = 'ip_block'
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(64), nullable=False)
    session_id = db.Column(db.String(16))
    alert_id = db.Column(db.String(64))
    blocked_at = db.Column(db.String(40))
    unblock_at = db.Column(db.String(40))
    duration_seconds = db.Column(db.Integer)
    block_count = db.Column(db.Integer, default=1)
    active = db.Column(db.Boolean, default=True)
    note = db.Column(db.Text, default='')

    def to_dict(self):
        return {
            'id': self.id,
            'ip': self.ip,
            'session_id': self.session_id,
            'alert_id': self.alert_id,
            'blocked_at': self.blocked_at,
            'unblock_at': self.unblock_at,
            'duration_seconds': self.duration_seconds,
            'block_count': self.block_count,
            'active': self.active,
            'note': self.note,
        }


class AdminUser(UserMixin, db.Model):
    """There's only ever one row in this table — the single dashboard login."""
    __tablename__ = 'admin_user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)


class MonitorSession(db.Model):
    __tablename__ = 'monitor_session'
    id = db.Column(db.String(16), primary_key=True)
    target_name = db.Column(db.String(200), default='Unnamed')
    server_ip = db.Column(db.String(100), default='')
    log_type = db.Column(db.String(20), default='auth')
    filepath = db.Column(db.String(500), default='')
    mode = db.Column(db.String(20), default='replay')  # 'replay' or 'tail'
    delay = db.Column(db.Float, default=0.15)
    started_at = db.Column(db.String(40))
    running = db.Column(db.Boolean, default=False)

    # Alert channel credentials — encrypted at rest, see EncryptedString above
    telegram_token = db.Column(EncryptedString(500), default='')
    telegram_chat_id = db.Column(EncryptedString(200), default='')
    email_username = db.Column(EncryptedString(300), default='')
    email_password = db.Column(EncryptedString(300), default='')
    email_to = db.Column(EncryptedString(300), default='')

    lines_processed = db.Column(db.Integer, default=0)
    auth_failures = db.Column(db.Integer, default=0)
    auth_successes = db.Column(db.Integer, default=0)
    alerts_fired = db.Column(db.Integer, default=0)

    def stats_dict(self):
        return {
            'lines_processed': self.lines_processed,
            'auth_failures': self.auth_failures,
            'auth_successes': self.auth_successes,
            'alerts_fired': self.alerts_fired,
        }


class BehaviorBaseline(db.Model):
    """
    What 'normal' looks like for a specific username or IP, built up over time
    from real events, not reset when a session ends. This is what makes real
    behavioral detection possible instead of just fixed-threshold rules.
    """
    __tablename__ = 'behavior_baseline'
    id = db.Column(db.String(160), primary_key=True)  # f"{log_type}:{identity}"
    log_type = db.Column(db.String(20))
    identity = db.Column(db.String(200))
    known_ips_json = db.Column(db.Text, default='[]')
    login_hours_json = db.Column(db.Text, default='[]')
    commands_json = db.Column(db.Text, default='[]')
    event_count = db.Column(db.Integer, default=0)
    first_seen = db.Column(db.String(40))
    last_seen = db.Column(db.String(40))

    def to_profile(self):
        return {
            'known_ips': json.loads(self.known_ips_json or '[]'),
            'login_hours': json.loads(self.login_hours_json or '[]'),
            'commands': json.loads(self.commands_json or '[]'),
            'event_count': self.event_count or 0,
        }

    def apply_profile(self, profile):
        self.known_ips_json = json.dumps(profile.get('known_ips', []))
        self.login_hours_json = json.dumps(profile.get('login_hours', []))
        self.commands_json = json.dumps(profile.get('commands', []))
        self.event_count = profile.get('event_count', 0)


class AlertRecord(db.Model):
    __tablename__ = 'alert_record'
    id = db.Column(db.String(64), primary_key=True)
    session_id = db.Column(db.String(16), db.ForeignKey('monitor_session.id'), nullable=False)
    rule = db.Column(db.String(50))
    severity = db.Column(db.String(20))
    title = db.Column(db.String(300))
    description = db.Column(db.Text)
    source_ip = db.Column(db.String(100))
    username = db.Column(db.String(100))
    event_count = db.Column(db.Integer, default=0)
    first_seen = db.Column(db.String(40))
    last_seen = db.Column(db.String(40))
    timestamp = db.Column(db.String(40))
    evidence_json = db.Column(db.Text, default='[]')  # list of raw log lines, stored as JSON text
    ai_verdict = db.Column(db.Text, default='')  # plain-language triage from the AI, if configured

    @property
    def evidence(self):
        try:
            return json.loads(self.evidence_json)
        except (TypeError, ValueError):
            return []

    def to_dict(self):
        return {
            'id': self.id,
            'session_id': self.session_id,
            'rule': self.rule,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'source_ip': self.source_ip,
            'username': self.username,
            'event_count': self.event_count,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'timestamp': self.timestamp,
            'evidence': self.evidence,
            'ai_verdict': self.ai_verdict,
        }

    @classmethod
    def from_alert(cls, alert, session_id, ai_verdict=''):
        """Build a row from the existing Alert dataclass produced by core/detection.py."""
        return cls(
            id=alert.id,
            session_id=session_id,
            rule=alert.rule,
            severity=alert.severity,
            title=alert.title,
            description=alert.description,
            source_ip=alert.source_ip,
            username=alert.username,
            event_count=alert.event_count,
            first_seen=alert.first_seen,
            last_seen=alert.last_seen,
            timestamp=alert.timestamp,
            evidence_json=json.dumps(alert.evidence or []),
            ai_verdict=ai_verdict or '',
        )
