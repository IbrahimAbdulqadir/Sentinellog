#!/usr/bin/env python3
"""
SentinelLog remote agent.

Tails a local log file on THIS machine and pushes new lines to a SentinelLog
dashboard running elsewhere, so one dashboard can watch logs across many
servers instead of only the box it's running on.

Zero third-party dependencies — stdlib only — so it runs on a bare server
with nothing but `python3` installed: no pip install, no venv.

Built to survive flaky connectivity: lines that fail to send are appended to
a local spool file and retried (oldest first) on every subsequent flush,
so a network drop doesn't lose data — it just gets sent late.

Usage:
  python3 sentinel_agent.py --url http://your-dashboard:5050 \\
      --session <session_id> --key <agent_key> --file /var/log/auth.log

Get --url/--session/--key from the "Remote agent" setup panel shown on the
Monitor page after starting a monitor in "Remote agent" mode.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

BATCH_SIZE = 200          # max lines per HTTP push
BATCH_INTERVAL = 2.0      # seconds between flushes, even if the batch isn't full
POLL_INTERVAL = 0.5       # seconds between checks for new file lines
MAX_BACKOFF = 60.0        # cap on retry backoff after repeated send failures


def log(msg):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


def spool_path(session_id):
    return f".sentinel_agent_spool_{session_id}.jsonl"


def spool_write(path, lines):
    with open(path, 'a', encoding='utf-8') as f:
        for line in lines:
            f.write(json.dumps(line) + '\n')


def spool_read_batch(path, limit):
    """Pop up to `limit` lines off the front of the spool file. Returns [] if empty."""
    if not os.path.exists(path):
        return []
    with open(path, 'r', encoding='utf-8') as f:
        all_lines = f.readlines()
    if not all_lines:
        return []
    batch_raw, rest = all_lines[:limit], all_lines[limit:]
    with open(path, 'w', encoding='utf-8') as f:
        f.writelines(rest)
    return [json.loads(l) for l in batch_raw if l.strip()]


def send_batch(url, session_id, key, lines):
    body = json.dumps({'lines': lines}).encode('utf-8')
    req = urllib.request.Request(
        f"{url.rstrip('/')}/api/ingest/{session_id}",
        data=body,
        method='POST',
        headers={'Content-Type': 'application/json', 'X-Agent-Key': key},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.status < 300


def flush(url, session_id, key, spool, pending, backoff_state):
    """Try to drain the spool first (oldest data), then send whatever's pending.
    On failure, everything gets spooled for next time and backoff increases."""
    to_send = spool_read_batch(spool, BATCH_SIZE) or pending
    came_from_spool = to_send is not pending
    if not to_send:
        return []

    try:
        send_batch(url, session_id, key, to_send)
        backoff_state['delay'] = 0
        # If we drained from the spool, the caller's `pending` batch is still unsent —
        # hand it back so it gets spooled or tried next cycle instead of being dropped.
        return pending if came_from_spool else []
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
        delay = backoff_state['delay'] = min(max(backoff_state['delay'], 1) * 2, MAX_BACKOFF)
        log(f"push failed ({e}) — spooling {len(to_send)} line(s), retrying in {delay:.0f}s")
        spool_write(spool, to_send)
        if came_from_spool and pending:
            spool_write(spool, pending)
        time.sleep(delay)
        return []


def tail(filepath):
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if line:
                yield line.rstrip('\n')
            else:
                time.sleep(POLL_INTERVAL)
                yield None


def main():
    ap = argparse.ArgumentParser(description="SentinelLog remote log-forwarding agent")
    ap.add_argument('--url', required=True, help="SentinelLog dashboard base URL, e.g. http://203.0.113.5:5050")
    ap.add_argument('--session', required=True, help="Monitor session ID (from the Remote agent setup panel)")
    ap.add_argument('--key', required=True, help="Agent key (from the Remote agent setup panel)")
    ap.add_argument('--file', required=True, help="Path to the log file on THIS machine to tail")
    ap.add_argument('--spool', default=None, help="Path to the local spool file (default: alongside this script)")
    args = ap.parse_args()

    spool = args.spool or spool_path(args.session)
    backoff_state = {'delay': 0}

    log(f"watching {args.file} -> {args.url} (session {args.session})")
    if os.path.exists(spool) and os.path.getsize(spool) > 0:
        log(f"found existing spool backlog at {spool} — will drain it alongside new lines")

    pending = []
    last_flush = time.time()

    try:
        for line in tail(args.file):
            if line is not None:
                pending.append(line)

            due = (len(pending) >= BATCH_SIZE) or (time.time() - last_flush >= BATCH_INTERVAL and pending)
            if due:
                pending = flush(args.url, args.session, args.key, spool, pending, backoff_state)
                last_flush = time.time()
    except KeyboardInterrupt:
        log("stopping — flushing any pending lines to spool")
        if pending:
            spool_write(spool, pending)
        sys.exit(0)
    except FileNotFoundError:
        log(f"ERROR: {args.file} does not exist on this machine")
        sys.exit(1)


if __name__ == '__main__':
    main()
