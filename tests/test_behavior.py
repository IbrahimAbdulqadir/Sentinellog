"""Tests for core/behavior.py — per-account behavioral baselines."""
from core.behavior import check_login_behavior, check_command_behavior, MIN_HISTORY_BEFORE_FLAGGING


def empty_login_profile():
    return {'known_ips': [], 'login_hours': [], 'event_count': 0}


def empty_command_profile():
    return {'commands': [], 'event_count': 0}


# ─── check_login_behavior ───────────────────────────────────────────────────

def test_login_behavior_learns_silently_before_min_history():
    profile = empty_login_profile()
    for i in range(MIN_HISTORY_BEFORE_FLAGGING):
        profile, alert = check_login_behavior(profile, 'ibrahim', '102.89.23.11', 10, '2026-01-15T10:00:00', 'line')
        assert alert is None
    assert profile['event_count'] == MIN_HISTORY_BEFORE_FLAGGING
    assert '102.89.23.11' in profile['known_ips']
    assert 10 in profile['login_hours']


def test_login_behavior_stays_quiet_for_a_familiar_pattern():
    profile = empty_login_profile()
    for _ in range(MIN_HISTORY_BEFORE_FLAGGING):
        profile, _ = check_login_behavior(profile, 'ibrahim', '102.89.23.11', 10, '2026-01-15T10:00:00', 'line')
    # same IP, same hour, now past the learning period — should not be flagged
    profile, alert = check_login_behavior(profile, 'ibrahim', '102.89.23.11', 10, '2026-01-16T10:00:00', 'line')
    assert alert is None


def test_login_behavior_flags_new_ip_and_hour_after_baseline():
    profile = empty_login_profile()
    for _ in range(MIN_HISTORY_BEFORE_FLAGGING):
        profile, _ = check_login_behavior(profile, 'ibrahim', '102.89.23.11', 10, '2026-01-15T10:00:00', 'line')
    profile, alert = check_login_behavior(profile, 'ibrahim', '197.210.54.19', 2, '2026-01-16T02:47:00', 'evidence line')
    assert alert is not None
    assert alert.rule == 'behavior_anomaly'
    assert alert.username == 'ibrahim'
    assert '197.210.54.19' in alert.description
    assert 'evidence line' in alert.evidence


def test_login_behavior_caps_known_ips_at_50():
    profile = empty_login_profile()
    for i in range(80):
        profile, _ = check_login_behavior(profile, 'ibrahim', f'10.0.0.{i}', 10, '2026-01-15T10:00:00', 'line')
    assert len(profile['known_ips']) <= 50


# ─── check_command_behavior ─────────────────────────────────────────────────

def test_command_behavior_learns_silently_before_min_history():
    profile = empty_command_profile()
    for _ in range(MIN_HISTORY_BEFORE_FLAGGING):
        profile, alert = check_command_behavior(profile, 'ibrahim', 'ls -la', '2026-01-15T10:00:00', 'line')
        assert alert is None
    assert 'ls' in profile['commands']


def test_command_behavior_flags_unfamiliar_command_after_baseline():
    profile = empty_command_profile()
    for _ in range(MIN_HISTORY_BEFORE_FLAGGING):
        profile, _ = check_command_behavior(profile, 'ibrahim', 'ls -la', '2026-01-15T10:00:00', 'line')
    profile, alert = check_command_behavior(profile, 'ibrahim', '/bin/cat /etc/shadow', '2026-01-16T02:00:00', 'evidence')
    assert alert is not None
    assert alert.rule == 'behavior_anomaly'
    assert '/bin/cat' in alert.description


def test_command_behavior_caps_commands_at_100():
    profile = empty_command_profile()
    for i in range(150):
        profile, _ = check_command_behavior(profile, 'ibrahim', f'cmd{i} arg', '2026-01-15T10:00:00', 'line')
    assert len(profile['commands']) <= 100
