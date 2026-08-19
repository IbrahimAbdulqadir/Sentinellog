"""
SentinelLog — Week 2 Detection Rules
Nginx/Apache log parser, 404 flood, directory traversal, privilege escalation
"""

import posixpath
import re
import uuid
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional

from core.detection import Alert, LogEvent


# ─── Nginx/Apache Log Parser ──────────────────────────────────────────────────

# Combined log format: 1.2.3.4 - - [15/Jan/2026:09:12:01 +0000] "GET /path HTTP/1.1" 200 1234
NGINX_PATTERN = re.compile(
    r'(?P<ip>[\d.]+)\s+-\s+-\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d+)\s+(?P<size>\d+)'
)

# Sudo log format
SUDO_PATTERN = re.compile(
    r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'\S+\s+sudo:\s+(?P<user>\S+)\s+:.*COMMAND=(?P<command>.+)$'
)

# su (account switch) log formats — PAM logs a successful switch as a session-open
# line, and util-linux's su itself logs a rejected one as "FAILED SU". Both name
# actor and target explicitly, which is exactly what a horizontal-movement check
# (one account assuming another's identity) needs.
SU_SUCCESS_PATTERN = re.compile(
    r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+su(?:\[\d+\])?:\s+'
    r'pam_unix\(su(?:-l)?:session\):\s+session opened for user (?P<target>\S+)\(uid=\d+\) by (?P<actor>\S+)\(uid=\d+\)'
)
SU_FAILURE_PATTERN = re.compile(
    r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+su(?:\[\d+\])?:\s+'
    r'FAILED SU \(to (?P<target>\S+)\) (?P<actor>\S+) on'
)

MONTH_MAP = {
    'Jan':1,'Feb':2,'Mar':3,'Apr':4,'May':5,'Jun':6,
    'Jul':7,'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12
}

TRAVERSAL_PATTERNS = [
    '../', '..%2f', '..%252f', '%2e%2e/', '..../',
    '/etc/passwd', '/etc/shadow', '/windows/system32',
    '/proc/self', 'boot.ini'
]

SUSPICIOUS_COMMANDS = [
    '/bin/bash', '/bin/sh', '/bin/cat /etc/shadow',
    '/etc/shadow', 'wget', 'curl', 'chmod', 'chown',
    'nc ', 'netcat', 'python -c', 'perl -e'
]

TRUSTED_SUDO_USERS = {'root', 'ibrahim', 'admin', 'ubuntu', 'deploy'}

# Per-user filesystem scope: which absolute path prefixes each login identity is
# allowed to touch. This is only the fallback default for a ScopeViolationDetector
# built with no arguments (direct testing, or any caller that hasn't wired up real
# config) — app.py passes in the actual, dashboard-editable scopes loaded from the
# UserScope table instead. A user with no entry has nothing enforced against them
# either way — this is opt-in per account, not a default-deny for everyone.
USER_SCOPES = {
    'user1': ['/home/user1/Downloads'],
    'user2': ['/home/user2/Downloads'],
    'user3': ['/home/user3/Downloads'],
    'user4': ['/home/user4/Downloads'],
}


def _within_scope(path: str, allowed_prefixes: list) -> bool:
    """
    True if `path` falls inside one of `allowed_prefixes`. Boundary-checks on '/' so
    an allowed prefix of '/home/user1/Downloads' doesn't wrongly also match a sibling
    directory like '/home/user1/Downloads-old'.
    """
    normalized = posixpath.normpath(path)
    for prefix in allowed_prefixes:
        prefix = posixpath.normpath(prefix)
        if normalized == prefix or normalized.startswith(prefix + '/'):
            return True
    return False


@dataclass
class WebLogEvent:
    raw_line: str
    timestamp: datetime
    source_ip: str
    method: str
    path: str
    status_code: int
    response_size: int
    event_type: str  # 'normal', '404', 'traversal', 'error'


def parse_nginx_line(line: str, assumed_year: int = None) -> Optional[WebLogEvent]:
    line = line.strip()
    if not line:
        return None

    match = NGINX_PATTERN.match(line)
    if not match:
        return None

    g = match.groupdict()
    year = assumed_year or datetime.now().year

    try:
        ts = datetime.strptime(g['time'].split()[0], "%d/%b/%Y:%H:%M:%S")
    except Exception:
        ts = datetime.now()

    status = int(g['status'])
    path = g['path']

    is_traversal = any(p in path.lower() for p in TRAVERSAL_PATTERNS)
    if is_traversal:
        event_type = 'traversal'
    elif status == 404:
        event_type = '404'
    elif status >= 400:
        event_type = 'error'
    else:
        event_type = 'normal'

    return WebLogEvent(
        raw_line=line,
        timestamp=ts,
        source_ip=g['ip'],
        method=g['method'],
        path=path,
        status_code=status,
        response_size=int(g['size']),
        event_type=event_type
    )


def parse_sudo_line(line: str, assumed_year: int = None) -> Optional[dict]:
    line = line.strip()
    if not line or 'sudo:' not in line:
        return None

    match = SUDO_PATTERN.search(line)
    if not match:
        return None

    g = match.groupdict()
    year = assumed_year or datetime.now().year
    month = MONTH_MAP.get(g['month'], 1)

    try:
        ts = datetime.strptime(
            f"{year}-{month}-{g['day'].strip()} {g['time']}", "%Y-%m-%d %H:%M:%S"
        )
    except Exception:
        ts = datetime.now()

    return {
        'timestamp': ts,
        'user': g['user'],
        'command': g['command'].strip(),
        'raw_line': line
    }


def parse_audit_line(line: str) -> Optional[dict]:
    """
    Parses an auditd EXECVE record tagged with the 'rootshell_cmd' key, a rule
    that specifically watches for auid != 0 with uid == 0, i.e. a login
    identity that isn't root, currently executing as root. That's the exact
    gap sudo/su logging alone can't see: what happens once someone is already
    inside an escalated shell. Unlike the syslog-style formats above, auditd's
    own timestamp is an absolute Unix epoch, so there's no year-guessing needed.
    """
    line = line.strip()
    if not line or 'key="rootshell_cmd"' not in line:
        return None

    epoch_m = re.search(r'msg=audit\((\d+)\.\d+:\d+\)', line)
    auid_m = re.search(r'AUID="([^"]*)"', line)
    comm_m = re.search(r'\bcomm="([^"]*)"', line)
    if not (epoch_m and auid_m and comm_m):
        return None

    try:
        ts = datetime.fromtimestamp(int(epoch_m.group(1)))
    except Exception:
        ts = datetime.now()

    return {
        'timestamp': ts,
        'actor': auid_m.group(1),
        'command': comm_m.group(1),
        'raw_line': line,
    }


def parse_scope_line(line: str) -> Optional[dict]:
    """
    Parses an auditd record tagged with the 'scope_watch' key, a path watch
    (`-w /home -p rwxa -k scope_watch`) rather than a syscall-argument rule like
    'rootshell_cmd' — it fires at the VFS layer on open/read/write/exec of anything
    under the watched tree, so `ls`, `cat`, a script, and a GUI file manager all
    produce the exact same record. That's what makes tool-of-access irrelevant here.

    NOTE — simplification: real auditd splits this across a SYSCALL record (which
    carries AUID) and a separate PATH record (which carries `name=`), correlated by
    the shared serial number in `msg=audit(epoch.msec:serial)`. This parser assumes
    those two have already been merged into one line (e.g. via `ausearch -i` output,
    or a small preprocessing step upstream) so AUID and name= appear together.
    """
    line = line.strip()
    if not line or 'key="scope_watch"' not in line:
        return None

    epoch_m = re.search(r'msg=audit\((\d+)\.\d+:\d+\)', line)
    auid_m = re.search(r'AUID="([^"]*)"', line)
    name_m = re.search(r'\bname="([^"]*)"', line)
    if not (epoch_m and auid_m and name_m):
        return None

    try:
        ts = datetime.fromtimestamp(int(epoch_m.group(1)))
    except Exception:
        ts = datetime.now()

    return {
        'timestamp': ts,
        'actor': auid_m.group(1),
        'path': name_m.group(1),
        'raw_line': line,
    }


def parse_su_line(line: str, assumed_year: int = None) -> Optional[dict]:
    """Parses either a successful or a rejected `su` (account switch) attempt."""
    line = line.strip()
    if not line:
        return None

    match = SU_SUCCESS_PATTERN.search(line)
    outcome = 'success'
    if not match:
        match = SU_FAILURE_PATTERN.search(line)
        outcome = 'failure'
    if not match:
        return None

    g = match.groupdict()
    year = assumed_year or datetime.now().year
    month = MONTH_MAP.get(g['month'], 1)

    try:
        ts = datetime.strptime(
            f"{year}-{month}-{g['day'].strip()} {g['time']}", "%Y-%m-%d %H:%M:%S"
        )
    except Exception:
        ts = datetime.now()

    return {
        'timestamp': ts,
        'actor': g['actor'],
        'target': g['target'],
        'outcome': outcome,
        'raw_line': line,
    }


# ─── New Detection Rules ──────────────────────────────────────────────────────

class NotFoundFloodDetector:
    """
    Detects 404 scanning — someone mapping your site for hidden files/endpoints.
    Threshold: 20+ 404s from same IP within 60 seconds.
    """

    def __init__(self, threshold: int = 20, window_seconds: int = 60):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.attempts: dict = defaultdict(deque)
        self.alerted_ips: set = set()

    def process_event(self, event: WebLogEvent) -> Optional[Alert]:
        if event.event_type != '404':
            return None

        ip = event.source_ip
        window = self.attempts[ip]
        window.append(event)

        cutoff = event.timestamp - timedelta(seconds=self.window_seconds)
        while window and window[0].timestamp < cutoff:
            window.popleft()

        count = len(window)
        if count >= self.threshold:
            if ip not in self.alerted_ips or count % self.threshold == 0:
                self.alerted_ips.add(ip)
                paths = list(set(e.path for e in window))[:8]
                return Alert(
                    id=f"404_{ip}_{int(event.timestamp.timestamp())}_{uuid.uuid4().hex[:6]}",
                    rule='404_flood',
                    severity='high',
                    title=f"Web scanner detected — {ip}",
                    description=(
                        f"{count} requests returning 404 from {ip} in {self.window_seconds}s. "
                        f"Scanning for: {', '.join(paths[:5])}"
                    ),
                    source_ip=ip,
                    username=None,
                    event_count=count,
                    first_seen=window[0].timestamp.isoformat(),
                    last_seen=window[-1].timestamp.isoformat(),
                    timestamp=datetime.utcnow().isoformat(),
                    evidence=[e.raw_line for e in list(window)[-8:]]
                )
        return None


class DirectoryTraversalDetector:
    """
    Detects path traversal attempts — ../../../etc/passwd patterns.
    Any single attempt is flagged immediately.
    """

    def __init__(self):
        self.seen: set = set()

    def process_event(self, event: WebLogEvent) -> Optional[Alert]:
        if event.event_type != 'traversal':
            return None

        key = f"{event.source_ip}:{event.path}"
        if key in self.seen:
            return None
        self.seen.add(key)

        return Alert(
            id=f"trav_{event.source_ip}_{int(event.timestamp.timestamp())}_{uuid.uuid4().hex[:6]}",
            rule='directory_traversal',
            severity='critical',
            title=f"Directory traversal attempt — {event.source_ip}",
            description=(
                f"Path traversal pattern detected in request from {event.source_ip}: "
                f"{event.path[:100]}"
            ),
            source_ip=event.source_ip,
            username=None,
            event_count=1,
            first_seen=event.timestamp.isoformat(),
            last_seen=event.timestamp.isoformat(),
            timestamp=datetime.utcnow().isoformat(),
            evidence=[event.raw_line]
        )


class PrivilegeEscalationDetector:
    """
    Detects suspicious sudo usage — unexpected users or dangerous commands.
    """

    def __init__(self):
        self.seen: set = set()

    def process_event(self, event: dict) -> Optional[Alert]:
        if not event:
            return None

        user = event.get('user', '')
        command = event.get('command', '').lower()
        ts = event.get('timestamp', datetime.utcnow())

        is_suspicious_user = user not in TRUSTED_SUDO_USERS
        is_suspicious_command = any(s in command for s in SUSPICIOUS_COMMANDS)

        if not (is_suspicious_user or is_suspicious_command):
            return None

        key = f"{user}:{command[:50]}"
        if key in self.seen:
            return None
        self.seen.add(key)

        severity = 'critical' if is_suspicious_command else 'high'
        reason = []
        if is_suspicious_user:
            reason.append(f"unexpected user '{user}'")
        if is_suspicious_command:
            reason.append(f"suspicious command: {event['command'][:60]}")

        return Alert(
            id=f"privesc_{user}_{int(ts.timestamp())}_{uuid.uuid4().hex[:6]}",
            rule='privilege_escalation',
            severity=severity,
            title=f"Suspicious sudo usage — {user}",
            description=f"Privilege escalation detected: {', '.join(reason)}",
            source_ip=None,
            username=user,
            event_count=1,
            first_seen=ts.isoformat(),
            last_seen=ts.isoformat(),
            timestamp=datetime.utcnow().isoformat(),
            evidence=[event.get('raw_line', '')]
        )


class AccountSwitchDetector:
    """
    Detects su (account switch) attempts by an untrusted identity — one account
    directly assuming another's session rather than going through sudo. This is
    the horizontal-movement counterpart to PrivilegeEscalationDetector's vertical
    one: sudo runs a single command as another user, su hands over the whole
    session, so it's flagged as its own rule rather than folded into that one.
    """

    def __init__(self):
        self.seen: set = set()

    def process_event(self, event: dict) -> Optional[Alert]:
        if not event:
            return None

        actor = event.get('actor', '')
        target = event.get('target', '')
        outcome = event.get('outcome', '')
        ts = event.get('timestamp', datetime.utcnow())

        if actor in TRUSTED_SUDO_USERS:
            return None

        key = f"{actor}:{target}:{outcome}"
        if key in self.seen:
            return None
        self.seen.add(key)

        succeeded = outcome == 'success'
        severity = 'critical' if succeeded else 'high'
        verb = 'switched into' if succeeded else 'tried to switch into (denied)'

        return Alert(
            id=f"acctsw_{actor}_{int(ts.timestamp())}_{uuid.uuid4().hex[:6]}",
            rule='lateral_movement',
            severity=severity,
            title=f"Account switch — {actor} {'became' if succeeded else 'tried to become'} {target}",
            description=(
                f"'{actor}' {verb} the '{target}' account via su, "
                f"bypassing sudo's per-command trail entirely."
            ),
            source_ip=None,
            username=actor,
            event_count=1,
            first_seen=ts.isoformat(),
            last_seen=ts.isoformat(),
            timestamp=datetime.utcnow().isoformat(),
            evidence=[event.get('raw_line', '')]
        )


class RootShellCommandDetector:
    """
    Flags commands run as root by a login identity that isn't root, the
    activity that happens *after* a successful escalation, which sudo/su
    logging alone never sees: sudo only records the one command that opened
    the door (or the su session that started), not what's typed once someone
    is already inside. Requires the auditd rule described in the operator
    runbook (auid>0, auid!=unset, uid=0, execve) to actually be present.
    """

    def __init__(self):
        self.seen: set = set()

    def process_event(self, event: dict) -> Optional[Alert]:
        if not event:
            return None

        actor = event.get('actor', '')
        command = event.get('command', '')
        ts = event.get('timestamp', datetime.utcnow())

        if not actor or actor in TRUSTED_SUDO_USERS or actor == 'unset':
            return None

        key = f"{actor}:{command}"
        if key in self.seen:
            return None
        self.seen.add(key)

        return Alert(
            id=f"rootcmd_{actor}_{int(ts.timestamp())}_{uuid.uuid4().hex[:6]}",
            rule='rootshell_command',
            severity='critical',
            title=f"Command run as root — {actor} ran '{command}'",
            description=(
                f"'{actor}' logged in as a non-root account but executed '{command}' "
                f"while running as root, evidence of what happened inside an escalated "
                f"shell after the initial sudo/su that granted it."
            ),
            source_ip=None,
            username=actor,
            event_count=1,
            first_seen=ts.isoformat(),
            last_seen=ts.isoformat(),
            timestamp=datetime.utcnow().isoformat(),
            evidence=[event.get('raw_line', '')]
        )


class ScopeViolationDetector:
    """
    Flags a user touching anything outside their assigned filesystem scope
    (USER_SCOPES), independent of privilege level — unlike RootShellCommandDetector,
    this doesn't require escalation to fire. A user reading their own permitted
    files with their own normal account is enough to trip it if that read lands
    outside their lane. Because it's driven by an auditd path watch rather than a
    syscall-argument rule, it can't be dodged by switching tools — `ls`, a script,
    or a GUI file manager all generate the same underlying record.

    Accounts with no entry in USER_SCOPES are skipped entirely: this rule is opt-in
    per user, not a default-deny that would flag admins/trusted accounts who were
    never meant to be scoped in the first place.
    """

    def __init__(self, scopes: dict = None):
        self.scopes = scopes if scopes is not None else USER_SCOPES
        self.seen: set = set()

    def process_event(self, event: dict) -> Optional[Alert]:
        if not event:
            return None

        actor = event.get('actor', '')
        path = event.get('path', '')
        ts = event.get('timestamp', datetime.utcnow())

        allowed = self.scopes.get(actor)
        if not allowed or not path:
            return None

        if _within_scope(path, allowed):
            return None

        real_path = posixpath.normpath(path)
        key = f"{actor}:{real_path}"
        if key in self.seen:
            return None
        self.seen.add(key)

        return Alert(
            id=f"scope_{actor}_{int(ts.timestamp())}_{uuid.uuid4().hex[:6]}",
            rule='scope_violation',
            severity='high',
            title=f"Out-of-scope access — {actor} touched '{real_path}'",
            description=(
                f"'{actor}' is scoped to {', '.join(allowed)}, but accessed "
                f"'{real_path}', outside their assigned area. This was caught at "
                f"the filesystem level, so it applies whether it happened from a "
                f"shell command, a script, or a GUI file manager."
            ),
            source_ip=None,
            username=actor,
            event_count=1,
            first_seen=ts.isoformat(),
            last_seen=ts.isoformat(),
            timestamp=datetime.utcnow().isoformat(),
            evidence=[event.get('raw_line', '')]
        )
