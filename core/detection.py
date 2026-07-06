"""
SentinelLog — Core Detection Engine
Week 1: Linux auth.log parsing, brute force detection, suspicious login time detection
"""

import re
import time
import threading
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from collections import defaultdict, deque
from typing import Optional


# ─── Data Models ───────────────────────────────────────────────────────────────

@dataclass
class LogEvent:
    raw_line: str
    timestamp: datetime
    hostname: str
    process: str
    pid: Optional[str]
    event_type: str          # 'auth_failure', 'auth_success', 'session_open', 'unknown'
    username: Optional[str]
    source_ip: Optional[str]
    source_port: Optional[str]


@dataclass
class Alert:
    id: str
    rule: str                 # 'brute_force', 'suspicious_time', 'distributed_brute_force'
    severity: str              # 'critical', 'high', 'medium', 'low'
    title: str
    description: str
    source_ip: Optional[str]
    username: Optional[str]
    event_count: int
    first_seen: str
    last_seen: str
    timestamp: str
    evidence: list = field(default_factory=list)  # list of raw log lines


# ─── Log Line Parser ───────────────────────────────────────────────────────────

# Matches: "Jan 15 02:14:01 webserver sshd[12453]: Failed password for root from 1.2.3.4 port 51234 ssh2"
LOG_LINE_PATTERN = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+(?P<process>\w+)\[(?P<pid>\d+)\]:\s+(?P<message>.*)$'
)

FAILED_PASSWORD_PATTERN = re.compile(
    r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)'
)

ACCEPTED_PASSWORD_PATTERN = re.compile(
    r'Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)'
)

SESSION_OPENED_PATTERN = re.compile(
    r'session opened for user (?P<user>\S+)'
)

MONTH_MAP = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
}


def parse_log_line(line: str, assumed_year: int = None) -> Optional[LogEvent]:
    """Parse a single syslog/auth.log line into a structured LogEvent."""
    line = line.strip()
    if not line:
        return None

    match = LOG_LINE_PATTERN.match(line)
    if not match:
        return None

    g = match.groupdict()
    year = assumed_year or datetime.now().year
    month = MONTH_MAP.get(g['month'], 1)

    try:
        timestamp = datetime.strptime(
            f"{year}-{month}-{g['day'].strip()} {g['time']}",
            "%Y-%m-%d %H:%M:%S"
        )
    except ValueError:
        timestamp = datetime.now()

    message = g['message']
    hostname = g['hostname']
    process = g['process']
    pid = g['pid']

    # Classify event type
    event_type = 'unknown'
    username = None
    source_ip = None
    source_port = None

    fail_match = FAILED_PASSWORD_PATTERN.search(message)
    accept_match = ACCEPTED_PASSWORD_PATTERN.search(message)
    session_match = SESSION_OPENED_PATTERN.search(message)

    if fail_match:
        event_type = 'auth_failure'
        username = fail_match.group('user')
        source_ip = fail_match.group('ip')
        source_port = fail_match.group('port')
    elif accept_match:
        event_type = 'auth_success'
        username = accept_match.group('user')
        source_ip = accept_match.group('ip')
        source_port = accept_match.group('port')
    elif session_match:
        event_type = 'session_open'
        username = session_match.group('user')

    return LogEvent(
        raw_line=line,
        timestamp=timestamp,
        hostname=hostname,
        process=process,
        pid=pid,
        event_type=event_type,
        username=username,
        source_ip=source_ip,
        source_port=source_port
    )


# ─── Detection Rules ───────────────────────────────────────────────────────────

class BruteForceDetector:
    """
    Detects brute force patterns: N+ failed auth attempts from the same IP
    within a sliding time window.
    """

    def __init__(self, threshold: int = 5, window_seconds: int = 60):
        self.threshold = threshold
        self.window_seconds = window_seconds
        # ip -> deque of (timestamp, LogEvent)
        self.attempts: dict[str, deque] = defaultdict(deque)
        self.alerted_ips: set[str] = set()

    def process_event(self, event: LogEvent) -> Optional[Alert]:
        if event.event_type != 'auth_failure' or not event.source_ip:
            return None

        ip = event.source_ip
        window = self.attempts[ip]
        window.append(event)

        # Drop events outside the sliding window
        cutoff = event.timestamp - timedelta(seconds=self.window_seconds)
        while window and window[0].timestamp < cutoff:
            window.popleft()

        if len(window) >= self.threshold:
            # Re-alert only every `threshold` additional attempts to avoid spam
            attempt_count = len(window)
            if ip not in self.alerted_ips or attempt_count % self.threshold == 0:
                self.alerted_ips.add(ip)
                usernames = list(set(e.username for e in window if e.username))
                severity = 'critical' if attempt_count >= self.threshold * 2 else 'high'

                return Alert(
                    id=f"bf_{ip}_{int(event.timestamp.timestamp())}",
                    rule='brute_force',
                    severity=severity,
                    title=f"Brute force attack detected from {ip}",
                    description=(
                        f"{attempt_count} failed login attempts from {ip} "
                        f"within {self.window_seconds}s, targeting "
                        f"{len(usernames)} account(s): {', '.join(usernames[:5])}"
                    ),
                    source_ip=ip,
                    username=', '.join(usernames[:5]),
                    event_count=attempt_count,
                    first_seen=window[0].timestamp.isoformat(),
                    last_seen=window[-1].timestamp.isoformat(),
                    timestamp=datetime.utcnow().isoformat(),
                    evidence=[e.raw_line for e in list(window)[-10:]]
                )
        return None


class SuspiciousTimeDetector:
    """
    Detects successful logins at unusual hours for a given account,
    based on a learned baseline of normal login hours per user.
    """

    def __init__(self, night_start: int = 0, night_end: int = 5, min_history: int = 3):
        self.night_start = night_start  # 00:00
        self.night_end = night_end      # 05:00
        self.min_history = min_history
        # username -> list of historical login hours
        self.login_history: dict[str, list[int]] = defaultdict(list)
        self.alerted_events: set[str] = set()

    def process_event(self, event: LogEvent) -> Optional[Alert]:
        if event.event_type != 'auth_success' or not event.username:
            return None

        hour = event.timestamp.hour
        username = event.username
        history = self.login_history[username]

        is_night = self.night_start <= hour < self.night_end
        has_baseline = len(history) >= self.min_history
        # Check if this user has ever logged in during night hours before
        ever_logged_at_night = any(self.night_start <= h < self.night_end for h in history)

        alert = None
        if is_night and has_baseline and not ever_logged_at_night:
            key = f"{username}_{event.source_ip}_{event.timestamp.isoformat()}"
            if key not in self.alerted_events:
                self.alerted_events.add(key)
                alert = Alert(
                    id=f"st_{username}_{int(event.timestamp.timestamp())}",
                    rule='suspicious_time',
                    severity='medium',
                    title=f"Unusual login time for {username}",
                    description=(
                        f"User '{username}' logged in at {event.timestamp.strftime('%H:%M')} "
                        f"from {event.source_ip} — outside their normal login hours. "
                        f"This account has never authenticated during night hours "
                        f"({self.night_start:02d}:00-{self.night_end:02d}:00) before."
                    ),
                    source_ip=event.source_ip,
                    username=username,
                    event_count=1,
                    first_seen=event.timestamp.isoformat(),
                    last_seen=event.timestamp.isoformat(),
                    timestamp=datetime.utcnow().isoformat(),
                    evidence=[event.raw_line]
                )

        history.append(hour)
        if len(history) > 100:
            history.pop(0)

        return alert


# ─── Log Monitor (live tail simulation + file watch) ──────────────────────────

class LogMonitor:
    """
    Watches a log file/source, parses new lines as they arrive,
    runs them through detection rules, and emits alerts live.
    """

    def __init__(self, event_callback=None, alert_callback=None):
        self.event_callback = event_callback
        self.alert_callback = alert_callback

        self.brute_force = BruteForceDetector(threshold=5, window_seconds=60)
        self.suspicious_time = SuspiciousTimeDetector()

        self.stats = {
            'lines_processed': 0,
            'events_parsed': 0,
            'auth_failures': 0,
            'auth_successes': 0,
            'alerts_fired': 0,
        }

        self._running = False
        self._thread = None

    def _emit_event(self, event: LogEvent):
        if self.event_callback:
            self.event_callback(event)

    def _emit_alert(self, alert: Alert):
        self.stats['alerts_fired'] += 1
        if self.alert_callback:
            self.alert_callback(alert)

    def process_line(self, line: str, assumed_year: int = None):
        self.stats['lines_processed'] += 1
        event = parse_log_line(line, assumed_year)
        if not event:
            return

        self.stats['events_parsed'] += 1
        if event.event_type == 'auth_failure':
            self.stats['auth_failures'] += 1
        elif event.event_type == 'auth_success':
            self.stats['auth_successes'] += 1

        self._emit_event(event)

        # Run through detection rules
        for detector in (self.brute_force, self.suspicious_time):
            alert = detector.process_event(event)
            if alert:
                self._emit_alert(alert)

    def replay_file(self, filepath: str, delay: float = 0.05, assumed_year: int = None):
        """
        Replay a log file line-by-line with a small delay between lines,
        simulating live tail for demo/testing purposes.
        """
        self._running = True
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    if not self._running:
                        break
                    self.process_line(line, assumed_year)
                    time.sleep(delay)
        finally:
            self._running = False

    def start_replay_async(self, filepath: str, delay: float = 0.05, assumed_year: int = None):
        self._thread = threading.Thread(
            target=self.replay_file, args=(filepath, delay, assumed_year), daemon=True
        )
        self._thread.start()

    def stop(self):
        self._running = False

    def tail_file(self, filepath: str, poll_interval: float = 1.0):
        """
        True live tail — watches a real log file (e.g. /var/log/auth.log)
        and processes new lines as they're appended.
        """
        self._running = True
        with open(filepath, 'r') as f:
            f.seek(0, 2)  # seek to end
            while self._running:
                line = f.readline()
                if line:
                    self.process_line(line)
                else:
                    time.sleep(poll_interval)

    def start_tail_async(self, filepath: str, poll_interval: float = 1.0):
        self._thread = threading.Thread(
            target=self.tail_file, args=(filepath, poll_interval), daemon=True
        )
        self._thread.start()

    def get_stats(self) -> dict:
        return dict(self.stats)
