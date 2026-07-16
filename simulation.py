import time

log_file = "test.log"
lines = [
    "Jan 15 02:14:01 webserver sshd[12453]: Failed password for root from 185.220.101.45 port 51234 ssh2",
    "Jan 15 02:14:03 webserver sshd[12453]: Failed password for root from 185.220.101.45 port 51234 ssh2",
    "Jan 15 02:14:05 webserver sshd[12453]: Failed password for root from 185.220.101.45 port 51234 ssh2",
    "Jan 15 02:14:07 webserver sshd[12453]: Failed password for root from 185.220.101.45 port 51234 ssh2",
    "Jan 15 02:14:09 webserver sshd[12453]: Failed password for root from 185.220.101.45 port 51234 ssh2",
    "Jan 15 02:14:11 webserver sshd[12453]: Failed password for root from 185.220.101.45 port 51234 ssh2",
    "Jan 15 08:32:10 webserver sshd[12890]: Accepted password for ibrahim from 102.89.23.11 port 44321 ssh2",
]

with open(log_file, "a") as f:
    for line in lines:
        f.write(line + "\n")
        f.flush()
        print(f"Written: {line[:50]}...")
        time.sleep(0.5)

print("Done — check your monitor dashboard")