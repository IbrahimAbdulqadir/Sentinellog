# SentinelLog

**Open-source SIEM-lite for small businesses — real-time log monitoring and threat detection without the enterprise price tag.**

## The problem

Enterprise SIEM tools (Splunk, QRadar, Sentinel) cost thousands of dollars monthly. Small businesses and startups — especially across Africa and other emerging markets — have zero log monitoring because of this price barrier. They are flying blind on their own infrastructure.

SentinelLog is a free, open-source alternative that watches your server logs in real time and alerts you to active threats.

## Week 1 — What's built

- **Live log monitoring** — watches Linux `auth.log` / `syslog` in real time (live tail) or replays a log file for demo/testing
- **Brute force detection** — flags 5+ failed login attempts from the same IP within a 60-second sliding window, with severity escalation for sustained attacks
- **Suspicious login time detection** — learns each user's normal login hours and flags authentication during night hours (00:00–05:00) for accounts with no prior night-time history
- **Live dashboard** — real-time event feed, alert panel, and session stats via Server-Sent Events
- **Alert evidence** — every alert captures the raw log lines that triggered it, viewable in a dedicated detail page

## Quick start

```bash
git clone <repo-url>
cd sentinellog
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5050`

## Usage

1. Go to **New Monitor**
2. Choose **Replay Sample Log** to see detection live against the bundled demo log, or **Tail Real File** to point at a real path like `/var/log/auth.log`
3. Watch alerts fire live on the dashboard
4. Click any alert to see the raw log evidence that triggered it

## Roadmap

- [x] Linux auth.log parsing + live tail
- [x] Brute force detection
- [x] Suspicious login time detection
- [ ] Web server log support (Nginx/Apache)
- [ ] Privilege escalation detection (sudo log analysis)
- [ ] Email/Telegram/Slack alerting
- [ ] Multi-client management (SaaS tier)

## Author

Ibrahim Abdulqadir — Cybersecurity researcher, BSc Cybersecurity (Bayero University Kano)

[LinkedIn](https://www.linkedin.com/in/ibrahim-abdulqadir)
