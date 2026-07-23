"""
SentinelLog — Behavioral Detection

The difference between this and the rest of core/detection.py: those detectors
match fixed patterns (5 failed logins in 60 seconds, a path containing '../').
This one has no fixed pattern at all — it compares a new event against what a
specific username or IP has actually done before, and flags it when something
genuinely doesn't match their own history. That's what makes it behavioral
rather than rule-based.

It needs a few real events before it has anything to compare against, so the
first few events for any new identity just get absorbed into the baseline
silently — that quiet learning period is inherent to the idea, not a bug.
"""
import uuid
from datetime import datetime
from core.detection import Alert

MIN_HISTORY_BEFORE_FLAGGING = 3


def _new_alert(username, source_ip, title, description, event_count, timestamp_iso, evidence_line):
    return Alert(
        id=f"behavior_{username or source_ip}_{int(datetime.now().timestamp())}_{uuid.uuid4().hex[:6]}",
        rule='behavior_anomaly',
        severity='medium',
        title=title,
        description=description,
        source_ip=source_ip,
        username=username,
        event_count=event_count,
        first_seen=timestamp_iso,
        last_seen=timestamp_iso,
        timestamp=timestamp_iso,
        evidence=[evidence_line] if evidence_line else [],
    )


def check_login_behavior(profile: dict, username: str, source_ip: str, login_hour: int,
                          timestamp_iso: str, evidence_line: str):
    """
    profile: {'known_ips': [...], 'login_hours': [...], 'event_count': N}
    Returns (updated_profile, alert_or_None).
    """
    known_ips = set(profile.get('known_ips', []))
    login_hours = set(profile.get('login_hours', []))
    event_count = profile.get('event_count', 0)

    alert = None
    if event_count >= MIN_HISTORY_BEFORE_FLAGGING:
        reasons = []
        if source_ip and source_ip not in known_ips:
            reasons.append(f"logging in from a location ({source_ip}) never seen on this account before")
        if login_hour not in login_hours:
            reasons.append(f"logging in at {login_hour:02d}:00, an hour this account has never used before")
        if reasons:
            alert = _new_alert(
                username, source_ip,
                title=f"Behavior change — {username}",
                description=f"{username} is " + " and ".join(reasons) + f", based on {event_count} previous logins on record for this account.",
                event_count=event_count + 1, timestamp_iso=timestamp_iso, evidence_line=evidence_line,
            )

    if source_ip:
        known_ips.add(source_ip)
    login_hours.add(login_hour)
    return {
        'known_ips': list(known_ips)[-50:],  # cap so this can't grow unbounded on a long-lived install
        'login_hours': list(login_hours),
        'event_count': event_count + 1,
    }, alert


def check_command_behavior(profile: dict, username: str, command: str,
                            timestamp_iso: str, evidence_line: str):
    """
    profile: {'commands': [...], 'event_count': N}
    Returns (updated_profile, alert_or_None).
    """
    commands = set(profile.get('commands', []))
    event_count = profile.get('event_count', 0)
    base_command = (command or '').strip().split()[0] if command else ''

    alert = None
    if event_count >= MIN_HISTORY_BEFORE_FLAGGING and base_command and base_command not in commands:
        alert = _new_alert(
            username, None,
            title=f"Unfamiliar command — {username}",
            description=f"{username} just ran '{base_command}', a command they haven't run in {event_count} previous recorded sudo actions.",
            event_count=event_count + 1, timestamp_iso=timestamp_iso, evidence_line=evidence_line,
        )

    if base_command:
        commands.add(base_command)
    return {
        'commands': list(commands)[-100:],
        'event_count': event_count + 1,
    }, alert
