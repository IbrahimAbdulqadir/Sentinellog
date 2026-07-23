"""
SentinelLog behavioral detection test — two phases, run through the real app.

This walks you through the exact test used to confirm the feature works:
phase 1 teaches SentinelLog what "normal" looks like for a user, phase 2
shows it recognizing a genuine departure from that — in a completely
separate monitor session, proving the memory isn't just tied to one run.

Usage:
    python test_behavior.py                       # writes to test.log
    python test_behavior.py C:\\path\\to\\file.log   # writes to a specific file
"""
import sys
import time
from datetime import datetime

target = sys.argv[1] if len(sys.argv) > 1 else "test.log"

def line(dt, user, ip, port):
    return f"{dt.strftime('%b %d %H:%M:%S')} webserver sshd[{port}]: Accepted password for {user} from {ip} port {port} ssh2"

print(f"Target file: {target}\n")
print("=" * 60)
print("PHASE 1 — teaching SentinelLog what's normal")
print("=" * 60)
print("""
Before running this, go start a NEW monitor session in the browser:
  - Log type: SSH / Auth
  - Mode: Tail real file
  - Path: this exact file (see above)
Then come back here and press Enter.
""")
input("Press Enter once that session is live and streaming... ")

now = datetime.now().replace(hour=10, minute=0, second=0)
with open(target, "a", encoding="utf-8") as f:
    for i in range(3):
        text = line(now, "ibrahim", "102.89.23.11", 50000 + i)
        f.write(text + "\n")
        f.flush()
        print(f"  {text}")
        time.sleep(1)

print("""
Done — 3 normal logins written (same person, same IP, same time of day).
Check the Live Alerts panel: there should be NOTHING there yet.
That's correct — SentinelLog needs a few real events before it has
anything to compare against, so it stays quiet on purpose during this
learning period.
""")

print("=" * 60)
print("PHASE 2 — proving the memory survives a completely new session")
print("=" * 60)
print("""
Now, in the browser:
  1. Click Stop on the session from phase 1.
  2. Start a BRAND NEW monitor session — same log type, same file path.
This is a genuinely different session_id. If the alert below still fires,
it's coming from persisted memory, not anything tied to the old session.
""")
input("Press Enter once the NEW session is live and streaming... ")

suspicious = now.replace(hour=2, minute=47)
text = line(suspicious, "ibrahim", "197.210.54.19", 51122)
with open(target, "a", encoding="utf-8") as f:
    f.write(text + "\n")
    f.flush()
print(f"  {text}")

print("""
Done. Check the Live Alerts panel now.

Expect: a "Behavior change — ibrahim" alert, explaining that this account
is logging in from an IP it has never used, at an hour it has never used,
based on the 3 logins from phase 1 — even though phase 1 happened in a
session that's already been stopped and is gone.
""")
