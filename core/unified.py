"""
SentinelLog — Unified Detection Engine

Previously, a monitor session had to be told up front which single rule set to
run — 'auth' (brute force + suspicious login time), 'nginx' (404 flood +
traversal), or 'sudo' (privilege escalation) — because each was a separate
branch in app.py wired to exactly one parser and one detector set. That meant a
session watching auth.log for brute force attempts would never catch privilege
escalation even when the sudo activity was sitting in that same file, and a
demo covering multiple attack types required guessing the right category ahead
of time instead of just watching and detecting everything that happens.

This module removes that requirement. Every line is classified by what it
actually looks like — tried against the sudo, nginx, and auth/sshd formats in
that order — rather than by a pre-declared type, and every detector (brute
force, suspicious login time, 404 flood, directory traversal, privilege
escalation, plus the login/command behavioral baselines) is always active
together. One monitor session can also watch several files at once, so a
single "Start monitoring" click covers every source and every rule
simultaneously.
"""
import queue as _queue
import threading
import time

from core.detection import parse_log_line, BruteForceDetector, SuspiciousTimeDetector
from core.detection_w2 import (
    parse_nginx_line, parse_sudo_line, parse_su_line,
    NotFoundFloodDetector, DirectoryTraversalDetector, PrivilegeEscalationDetector,
    AccountSwitchDetector,
)


def classify_line(line, assumed_year=None):
    """
    Identify a log line's format by trying the most specific parsers first.
    Returns (kind, parsed_event) with kind in {'sudo', 'su', 'nginx', 'auth'}, or
    (None, None) if nothing recognizes it. su has to be checked before the
    generic auth parser: an su line also matches the generic "process[pid]:
    message" shape, so if auth ran first it would swallow su lines as boring,
    unclassified auth events and this rule would never see them.
    """
    sudo_event = parse_sudo_line(line, assumed_year)
    if sudo_event:
        return 'sudo', sudo_event

    su_event = parse_su_line(line, assumed_year)
    if su_event:
        return 'su', su_event

    nginx_event = parse_nginx_line(line, assumed_year)
    if nginx_event:
        return 'nginx', nginx_event

    auth_event = parse_log_line(line, assumed_year)
    if auth_event:
        return 'auth', auth_event

    return None, None


class UnifiedMonitor:
    """Runs every detector together against whatever lines it's given, regardless
    of which file or format they came from."""

    def __init__(self, on_event=None, on_alert=None, on_behavior=None):
        self.brute_force = BruteForceDetector(threshold=5, window_seconds=60)
        self.suspicious_time = SuspiciousTimeDetector()
        self.notfound_flood = NotFoundFloodDetector(threshold=20, window_seconds=60)
        self.traversal = DirectoryTraversalDetector()
        self.priv_esc = PrivilegeEscalationDetector()
        self.acct_switch = AccountSwitchDetector()

        self.on_event = on_event        # (kind, event) -> None
        self.on_alert = on_alert        # (Alert) -> None
        self.on_behavior = on_behavior  # (kind, event) -> None, for baseline updates

        self.stats = {
            'lines_processed': 0,
            'events_parsed': 0,
            'auth_failures': 0,
            'auth_successes': 0,
            'alerts_fired': 0,
        }

    def process_line(self, line, assumed_year=None):
        self.stats['lines_processed'] += 1
        kind, event = classify_line(line, assumed_year)
        if not event:
            return

        self.stats['events_parsed'] += 1

        if kind == 'auth':
            if event.event_type == 'auth_failure':
                self.stats['auth_failures'] += 1
            elif event.event_type == 'auth_success':
                self.stats['auth_successes'] += 1
            detectors = (self.brute_force, self.suspicious_time)
        elif kind == 'nginx':
            detectors = (self.notfound_flood, self.traversal)
        elif kind == 'sudo':
            detectors = (self.priv_esc,)
        else:  # su
            detectors = (self.acct_switch,)

        if self.on_event:
            self.on_event(kind, event)

        for det in detectors:
            alert = det.process_event(event)
            if alert:
                self.stats['alerts_fired'] += 1
                if self.on_alert:
                    self.on_alert(alert)

        if self.on_behavior:
            self.on_behavior(kind, event)

    def get_stats(self) -> dict:
        return dict(self.stats)


def _iter_single(filepath, mode, delay, is_running):
    if mode == 'tail':
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            f.seek(0, 2)  # jump to current end of file — only new lines from here on
            while is_running():
                line = f.readline()
                if line:
                    yield line
                else:
                    time.sleep(1.0)
    else:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if not is_running():
                    break
                yield line
                time.sleep(delay)


def merge_line_sources(paths, mode, delay, is_running):
    """
    Tail/replay one or more files concurrently, interleaving their lines into a
    single stream as they arrive. This is what lets one monitor session cover
    e.g. auth.log and nginx_access.log together instead of requiring a separate
    session per file.
    """
    if len(paths) == 1:
        yield from _iter_single(paths[0], mode, delay, is_running)
        return

    q = _queue.Queue()
    SENTINEL = object()

    def pump(path):
        try:
            for line in _iter_single(path, mode, delay, is_running):
                q.put(line)
        finally:
            q.put(SENTINEL)

    for p in paths:
        threading.Thread(target=pump, args=(p,), daemon=True).start()

    finished = 0
    while finished < len(paths):
        if not is_running():
            break
        try:
            item = q.get(timeout=1.0)
        except _queue.Empty:
            continue
        if item is SENTINEL:
            finished += 1
            continue
        yield item
