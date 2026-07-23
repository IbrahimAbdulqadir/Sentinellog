import sys
import time
import random
from datetime import datetime, timedelta

target = sys.argv[1] if len(sys.argv) > 1 else "test.log"

def line(dt, process, pid, message):
    return f"{dt.strftime('%b %d %H:%M:%S')} webserver {process}[{pid}]: {message}"

now = datetime.now()
events = []

# ── Phase 1: baseline — the legitimate user 'ibrahim' logging in normally
#    during the day, on separate occasions. This builds the "normal hours"
#    history the suspicious_time detector needs before it can flag a night login.
baseline_hours = [9, 13, 16]
for h in baseline_hours:
    dt = now.replace(hour=h, minute=random.randint(0, 59), second=random.randint(0, 59))
    events.append((line(dt, 'sshd', 12100 + h, f"Accepted password for ibrahim from 102.89.23.11 port {random.randint(40000,60000)} ssh2"), 0.3))

# ── Phase 2: reconnaissance — a scanner probing a few invalid usernames,
#    low volume, not enough on its own to trip the brute-force threshold.
scanner_ip = "91.240.118.77"
for user in ("admin", "test", "oracle"):
    dt = now
    events.append((line(dt, 'sshd', 20500 + random.randint(1,90), f"Failed password for invalid user {user} from {scanner_ip} port {random.randint(40000,60000)} ssh2"), 1.2))

# ── Phase 3: the real attack — a genuine brute-force burst against root
#    from one persistent IP, 6 attempts inside well under 60 seconds.
attacker_ip = "185.220.101.45"
for i in range(6):
    dt = now
    events.append((line(dt, 'sshd', 12453, f"Failed password for root from {attacker_ip} port 51234 ssh2"), 1.5))

# ── Phase 4: the compromise — the attacker gets in.
events.append((line(now, 'sshd', 12453, f"Accepted password for root from {attacker_ip} port 51234 ssh2"), 0.5))
events.append((line(now, 'sshd', 12453, "pam_unix(sshd:session): session opened for user root"), 0.5))

# ── Phase 5: the suspicious part — the LEGITIMATE user logging in during the
#    night window (00:00-05:00) for the first time, right after having 3+
#    daytime logins on record. This is what the suspicious_time rule is for.
night_dt = now.replace(hour=2, minute=47, second=13)
events.append((line(night_dt, 'sshd', 30991, "Accepted password for ibrahim from 197.210.54.19 port 51122 ssh2"), 0.5))

# ── Write it all in real time, so a live tail session sees it unfold ──
print(f"Writing to: {target}\n")
with open(target, "a", encoding="utf-8") as f:
    for text, delay in events:
        f.write(text + "\n")
        f.flush()
        print(f"  {text}")
        time.sleep(delay)

print(f"\nDone. {len(events)} lines written to {target}")
print("Expect: 1 brute_force alert (root from the attacker IP) and 1 suspicious_time alert (ibrahim at 02:47).")