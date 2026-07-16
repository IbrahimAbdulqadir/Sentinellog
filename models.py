"""
SentinelLog - Database Models
Defines what gets saved permanently to disk (sessions, alerts, the admin user).
"""
import json
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()


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

    # Alert channel credentials — see note below on encryption
    telegram_token = db.Column(db.String(200), default='')
    telegram_chat_id = db.Column(db.String(100), default='')
    email_username = db.Column(db.String(200), default='')
    email_password = db.Column(db.String(200), default='')
    email_to = db.Column(db.String(200), default='')

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
        }

    @classmethod
    def from_alert(cls, alert, session_id):
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
        )
