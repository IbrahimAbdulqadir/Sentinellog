"""Tests for core/detection.py — auth.log parsing, brute force, suspicious time."""
from datetime import datetime, timedelta

from core.detection import (
    parse_log_line, BruteForceDetector, SuspiciousTimeDetector, LogEvent,
)


def make_event(event_type='auth_failure', source_ip='1.2.3.4', username='root',
                timestamp=None, raw_line='synthetic'):
    return LogEvent(
        raw_line=raw_line, timestamp=timestamp or datetime(2026, 1, 15, 10, 0, 0),
        hostname='webserver', process='sshd', pid='123',
        event_type=event_type, username=username, source_ip=source_ip, source_port='51234',
    )


# ─── parse_log_line ─────────────────────────────────────────────────────────

def test_parses_failed_password():
    event = parse_log_line("Jan 15 02:14:01 webserver sshd[12453]: Failed password for root from 1.2.3.4 port 51234 ssh2")
    assert event.event_type == 'auth_failure'
    assert event.username == 'root'
    assert event.source_ip == '1.2.3.4'
    assert event.source_port == '51234'


def test_parses_failed_password_invalid_user():
    event = parse_log_line("Jan 15 02:14:01 webserver sshd[12453]: Failed password for invalid user bob from 5.6.7.8 port 4000 ssh2")
    assert event.event_type == 'auth_failure'
    assert event.username == 'bob'


def test_parses_accepted_password():
    event = parse_log_line("Jan 15 02:14:01 webserver sshd[12453]: Accepted password for ibrahim from 9.9.9.9 port 4000 ssh2")
    assert event.event_type == 'auth_success'
    assert event.username == 'ibrahim'
    assert event.source_ip == '9.9.9.9'


def test_parses_session_opened():
    event = parse_log_line("Jan 15 02:14:01 webserver sshd[12453]: pam_unix(sshd:session): session opened for user root by (uid=0)")
    assert event.event_type == 'session_open'
    assert event.username == 'root'


def test_unrecognized_message_still_parses_with_unknown_type():
    event = parse_log_line("Jan 15 02:14:01 webserver sshd[12453]: some unrelated message")
    assert event.event_type == 'unknown'


def test_line_not_matching_syslog_format_returns_none():
    assert parse_log_line("this is not a syslog line at all") is None


def test_empty_line_returns_none():
    assert parse_log_line("") is None
    assert parse_log_line("   ") is None


# ─── BruteForceDetector ─────────────────────────────────────────────────────

def test_brute_force_ignores_non_failure_events():
    det = BruteForceDetector(threshold=3, window_seconds=60)
    assert det.process_event(make_event(event_type='auth_success')) is None


def test_brute_force_fires_once_threshold_reached():
    det = BruteForceDetector(threshold=3, window_seconds=60)
    base = datetime(2026, 1, 15, 10, 0, 0)
    assert det.process_event(make_event(timestamp=base)) is None
    assert det.process_event(make_event(timestamp=base + timedelta(seconds=1))) is None
    alert = det.process_event(make_event(timestamp=base + timedelta(seconds=2)))
    assert alert is not None
    assert alert.rule == 'brute_force'
    assert alert.source_ip == '1.2.3.4'
    assert alert.event_count == 3


def test_brute_force_does_not_realert_every_attempt():
    det = BruteForceDetector(threshold=3, window_seconds=60)
    base = datetime(2026, 1, 15, 10, 0, 0)
    for i in range(3):
        det.process_event(make_event(timestamp=base + timedelta(seconds=i)))
    # 4th attempt: past threshold but not a multiple of it — should stay quiet
    alert = det.process_event(make_event(timestamp=base + timedelta(seconds=3)))
    assert alert is None


def test_brute_force_realerts_at_next_multiple_with_higher_severity():
    det = BruteForceDetector(threshold=3, window_seconds=60)
    base = datetime(2026, 1, 15, 10, 0, 0)
    for i in range(5):
        alert = det.process_event(make_event(timestamp=base + timedelta(seconds=i)))
    # 6th attempt: attempt_count=6, 6 % 3 == 0 -> re-alert, and 6 >= 2*threshold -> critical
    alert = det.process_event(make_event(timestamp=base + timedelta(seconds=5)))
    assert alert is not None
    assert alert.severity == 'critical'


def test_brute_force_sliding_window_evicts_old_attempts():
    det = BruteForceDetector(threshold=3, window_seconds=10)
    base = datetime(2026, 1, 15, 10, 0, 0)
    # three attempts, 20s apart — each one falls outside the 10s window of the next
    for i in range(3):
        alert = det.process_event(make_event(timestamp=base + timedelta(seconds=20 * i)))
        assert alert is None


def test_brute_force_separates_by_ip():
    det = BruteForceDetector(threshold=2, window_seconds=60)
    base = datetime(2026, 1, 15, 10, 0, 0)
    assert det.process_event(make_event(source_ip='1.1.1.1', timestamp=base)) is None
    assert det.process_event(make_event(source_ip='2.2.2.2', timestamp=base)) is None
    alert = det.process_event(make_event(source_ip='1.1.1.1', timestamp=base + timedelta(seconds=1)))
    assert alert is not None
    assert alert.source_ip == '1.1.1.1'


# ─── SuspiciousTimeDetector ─────────────────────────────────────────────────

def test_suspicious_time_ignores_non_success_events():
    det = SuspiciousTimeDetector(min_history=3)
    assert det.process_event(make_event(event_type='auth_failure')) is None


def test_suspicious_time_stays_quiet_during_learning_period():
    det = SuspiciousTimeDetector(min_history=3)
    base = datetime(2026, 1, 15, 10, 0, 0)
    # only 2 daytime logins on record — below min_history, so a night login shouldn't fire yet
    det.process_event(make_event(event_type='auth_success', username='ibrahim', timestamp=base))
    det.process_event(make_event(event_type='auth_success', username='ibrahim', timestamp=base))
    night = base.replace(hour=2)
    alert = det.process_event(make_event(event_type='auth_success', username='ibrahim', timestamp=night))
    assert alert is None


def test_suspicious_time_flags_first_ever_night_login_after_baseline():
    det = SuspiciousTimeDetector(min_history=3)
    base = datetime(2026, 1, 15, 10, 0, 0)
    for _ in range(3):
        det.process_event(make_event(event_type='auth_success', username='ibrahim', timestamp=base))
    night = datetime(2026, 1, 16, 2, 47, 0)
    alert = det.process_event(make_event(event_type='auth_success', username='ibrahim', source_ip='9.9.9.9', timestamp=night))
    assert alert is not None
    assert alert.rule == 'suspicious_time'
    assert alert.username == 'ibrahim'


def test_suspicious_time_does_not_flag_account_with_prior_night_history():
    det = SuspiciousTimeDetector(min_history=3)
    base = datetime(2026, 1, 15, 10, 0, 0)
    det.process_event(make_event(event_type='auth_success', username='ibrahim', timestamp=base))
    det.process_event(make_event(event_type='auth_success', username='ibrahim', timestamp=base.replace(hour=3)))
    det.process_event(make_event(event_type='auth_success', username='ibrahim', timestamp=base))
    night = datetime(2026, 1, 16, 2, 0, 0)
    alert = det.process_event(make_event(event_type='auth_success', username='ibrahim', timestamp=night))
    assert alert is None
