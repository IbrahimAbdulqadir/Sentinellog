import sys
import time
import random
from datetime import datetime

target = sys.argv[1] if len(sys.argv) > 1 else "nginx.log"

def line(dt, ip, method, path, status, size):
    ts = dt.strftime('%d/%b/%Y:%H:%M:%S +0000')
    return f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {size}'

now = datetime.now()
events = []

# ── Phase 1: quiet, normal traffic from a couple of real visitors ──
normal_paths = ["/", "/about", "/products", "/contact", "/images/logo.png"]
for _ in range(4):
    ip = random.choice(["102.89.23.11", "197.210.54.19"])
    events.append((line(now, ip, "GET", random.choice(normal_paths), 200, random.randint(800, 5000)), 0.5))

# ── Phase 2: the scan — a bot hammering common admin/config paths,
#    22 requests from one IP, fast, well inside the 60-second window
#    the 404_flood rule checks (threshold is 20).
scanner_ip = "45.155.205.90"
scan_paths = [
    "/wp-admin", "/wp-login.php", "/.env", "/phpmyadmin", "/admin",
    "/config.php", "/.git/config", "/backup.sql", "/.aws/credentials",
    "/administrator", "/xmlrpc.php", "/wp-content/debug.log", "/server-status",
    "/.well-known/security.txt", "/vendor/.env", "/api/v1/users", "/login.php",
    "/db_backup.sql", "/.ssh/id_rsa", "/setup.php", "/install.php", "/shell.php"
]
for path in scan_paths:
    events.append((line(now, scanner_ip, "GET", path, 404, random.randint(150, 400)), 0.15))

# ── Phase 3: the traversal attempt — same or a different attacker,
#    trying to walk out of the web root. Fires immediately, no threshold.
events.append((line(now, scanner_ip, "GET", "/../../../../etc/passwd", 403, 0), 0.4))
events.append((line(now, "185.220.101.45", "GET", "/download?file=..%2f..%2f..%2fetc%2fshadow", 403, 0), 0.4))

print(f"Writing to: {target}\n")
with open(target, "a", encoding="utf-8") as f:
    for text, delay in events:
        f.write(text + "\n")
        f.flush()
        print(f"  {text}")
        time.sleep(delay)

print(f"\nDone. {len(events)} lines written to {target}")
print("Expect: 1 404_flood alert (scanner IP) and 2 directory_traversal alerts.")
