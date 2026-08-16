# SentinelLog — System Overview

_A detailed snapshot of what's actually built, as of this session. For the pitch/marketing version, see `README.md`._

---

## 1. What it is

SentinelLog is a self-hosted, open-source SIEM-lite: a Flask web app that watches server log files (SSH/auth, Nginx/Apache, sudo), runs them through detection rules and behavioral baselines, and surfaces alerts on a live dashboard — with optional AI plain-language triage, Telegram/Email alerting, and automated IP blocking. It's positioned as the log-monitoring tool small businesses and startups can actually afford, particularly in markets where Splunk/QRadar-class pricing is a non-starter.

## 2. Tech stack

| Layer | Choice |
|---|---|
| Backend | Flask, served via **Waitress** (not the Flask dev server), threaded |
| Auth | Flask-Login, single admin account, password hashed with Werkzeug |
| Database | SQLite via SQLAlchemy (`sentinellog.db`) |
| Secrets at rest | Fernet symmetric encryption (`cryptography`) for stored Telegram/email credentials |
| Live updates | Server-Sent Events (SSE) — one stream per monitor session |
| Frontend | Server-rendered Jinja2 templates + vanilla JS, no build step, no JS framework |
| AI triage | OpenAI `gpt-4o-mini` (optional — everything else works without it) |
| Active response | Shells out to `iptables` (Linux only) |

## 3. Data model (`models.py`)

- **`AdminUser`** — exactly one row, the dashboard login.
- **`MonitorSession`** — one row per "watch this log source" session: target name, log type (`auth`/`nginx`/`sudo`), file path, mode (`replay` / `tail` / **`agent`**, new), running stats (lines processed, auth failures/successes, alerts fired), and per-session alert-channel credentials (Telegram token/chat ID, email creds — all encrypted at rest). Agent-mode sessions also carry an `agent_key`.
- **`AlertRecord`** — one row per fired alert: rule, severity, title, description, source IP/username, evidence (raw log lines, JSON), and the AI's plain-language verdict if one was generated.
- **`BehaviorBaseline`** — one row per `(log_type, identity)` pair (e.g. `auth:jsmith`), holding that identity's known IPs, login hours, and sudo commands. This is what lets behavioral detection compare *today* against *that specific account's real history*, and it persists across restarts.
- **`IPBlock`** — audit trail of every automated block: which IP, which alert triggered it, when, for how long, whether it's still active.

## 4. Detection engine

Three parsers, each producing structured events that flow through rule-based and behavioral detectors:

**`core/detection.py` — auth.log**
- Parses OpenSSH-style lines (`Failed password for X from Y port Z`, `Accepted password...`, `session opened...`).
- **Brute force**: 5+ failed logins from the same IP within a 60s sliding window → `high`, escalating to `critical` at 2x threshold. Re-alerts every `threshold` additional attempts instead of spamming once per attempt.
- **Suspicious login time**: flags a successful login between 00:00–05:00 for an account that has never logged in at night before (needs 3+ prior logins on record first).

**`core/detection_w2.py` — Nginx/Apache + sudo**
- **404 flood** (`high`): 20+ 404s from one IP in 60s — site/endpoint scanning.
- **Directory traversal** (`critical`): any request path matching known traversal patterns (`../`, `%2e%2e/`, `/etc/passwd`, `/etc/shadow`, `boot.ini`, etc.) — fires immediately, deduped per IP+path.
- **Privilege escalation** (`high`/`critical`): sudo usage by a user outside a trusted allowlist, or a command matching a suspicious list (`wget`, `curl`, `/bin/bash`, `chmod`, `nc`, `python -c`, etc.).

**`core/behavior.py` — behavioral baselines**
- Not threshold-based at all — compares a new event against *that identity's own history*. First 3 events for any new user/IP are absorbed silently as baseline; after that, a login from a never-seen IP or hour, or a sudo command never run before, fires a `medium` "behavior change" alert. Baselines persist in `BehaviorBaseline` and cap at 50 known IPs / 100 known commands per identity so they can't grow unbounded.

All detectors emit the same `Alert` dataclass, so the rest of the pipeline (storage, dispatch, AI triage) doesn't need to know which rule fired it.

## 5. AI triage (`core/ai_triage.py`)

Optional (`OPENAI_API_KEY`). Takes a raw alert plus the relevant behavioral baseline context and asks `gpt-4o-mini` for a 3–5 sentence verdict aimed at a non-technical reader: what happened, how worried to be (honestly — not inflated), and one concrete next step. Failure or missing key just falls back to the raw alert; it can never break monitoring.

## 6. Alerting (`core/alerting.py`)

- **Telegram**: Markdown-formatted message via the Bot API (`urllib`, no SDK dependency), includes severity, evidence snippet.
- **Email**: Gmail (port 465, implicit SSL by default — more mobile-carrier-friendly than 587/STARTTLS) or arbitrary SMTP, styled HTML + plain-text fallback.
- Both are per-session, tested independently from the New Monitor form (`/api/telegram/test`, `/api/email/test`), and stored encrypted.

## 7. Active response (`core/active_response.py`)

Deliberately narrow: **only** fires on `brute_force` alerts (the highest-confidence rule), **never** touches whitelisted IPs (`WHITELIST_IPS` in `.env`), and blocks are always time-boxed via `iptables`, never permanent. Duration escalates for repeat offenders: 30 min → 1h → 2h..., capped at 24h. A background sweep (`_unblock_sweep`, every 60s) lifts expired blocks automatically. Blocking failure (wrong OS, no permission) is caught and logged — it never takes the monitoring session down.

## 8. Remote agent ingestion — new this session

The original design point was that SentinelLog could only watch files on the same machine it runs on. That's now fixed for the common case:

- A monitor session can be started in **`agent` mode**. On creation, the server mints a random `agent_key` (`secrets.token_hex(20)`) for that session.
- `POST /api/ingest/<session_id>` accepts batches of raw log lines, authenticated via `X-Agent-Key` header (constant-time compared, `hmac.compare_digest`) — deliberately **not** behind the admin login, since an unattended remote process can't hold a browser session.
- Ingested lines are queued in-memory and consumed by the exact same per-log-type detection loop as local tail/replay (`LogMonitor.consume()` for auth, the same nginx/sudo loops with a swapped line source) — no duplicated detection logic.
- Unlike replay/tail, an agent session starts processing **immediately** on creation rather than waiting for a browser to open the monitor page — a remote agent may start pushing before anyone's watching, and those lines mustn't be lost.
- **`static/agent/sentinel_agent.py`** — a standalone, dependency-free (stdlib-only) Python script the admin runs on the remote box. Tails a file, batches lines, pushes them to `/api/ingest`, and — the part that matters most for unreliable connections — **spools unsent lines to a local disk file and retries with exponential backoff** on failure, so a network drop delays data instead of losing it.
- The Monitor page shows a copy-paste install one-liner (`curl ... && python3 sentinel_agent.py --url ... --session ... --key ... --file ...`) once an agent-mode session is created, and its status pill flips from "waiting for agent" to "receiving data" on first ingested line.

This is additive — replay and tail modes are unchanged.

## 9. Screens / UI

Seven pages, all extending a shared `templates/base.html` except the standalone `login.html`:

1. **Login** — username/password, server-side auth only.
2. **Dashboard** (`/`) — 4 metric tiles (active monitors, critical alerts, suspicious logins, events processed), recent alerts panel, monitor sessions panel, live event feed (SSE-driven).
3. **Alerts** (`/alerts`) — every fired alert, severity-coded, click through to detail.
4. **Alert detail** (`/alerts/<id>`) — raw evidence lines, AI verdict callout (if generated), active-response outcome if a block resulted.
5. **Blocked IPs** (`/blocks`) — every automated block, active/expired, offense count, duration, link back to the triggering alert.
6. **New Monitor** (`/monitor/new`) — mode selection (**Replay sample / Tail real file / Remote agent** — third option new this session), log type, per-session Telegram/Email setup with live test buttons.
7. **Monitor session** (`/monitor/<id>`) — live terminal-style log feed, live alerts panel, stop/resume controls, and (agent mode) the setup/install panel.

### Redesign status

A visual redesign ("3D system") handed off as a static reference file (`SentinelLog-3D-reference.dc.html` + `README.md`, not executable code) has been implemented across **all seven screens** this session:

- Dark near-black palette (`#0B0D12` background), green (`#4ADE9C`, brand/primary) + cyan (`#4FC3E8`, secondary/info) accents, replacing the old gold/teal light theme — the light/dark toggle was removed since the new design is a single fixed dark theme.
- Outfit (headings) + Source Sans 3 (body), replacing Space Grotesk/Inter/JetBrains Mono.
- Signature "extruded" hard-edge box-shadow on every card/tile/panel, an isometric grid-floor background effect, and a continuously-rotating 3D shield-medallion logo (CSS-only, no image asset) at three sizes: nav bar, login mini-brand, and a 170px login hero.
- All existing CSS custom properties (`--gold`, `--teal`, `--accent`, etc.) were kept as names but repointed to the new palette, so every template re-themes automatically without per-page rewrites; only structural pieces (terminal panels' two-layer dark-well look, list-row shadow variant, a few link colors) needed direct template edits.
- **Verified so far**: login screen confirmed visually correct in-browser. **Not yet verified**: dashboard, alerts, alert detail, blocks, new monitor, and monitor screens — pending an authenticated pass through the browser.

## 10. File structure

```
app.py                    Flask app, all routes, session worker orchestration
models.py                 SQLAlchemy models + Fernet-encrypted column type
core/
  detection.py             auth.log parsing, brute force + suspicious time, LogMonitor
  detection_w2.py           nginx/sudo parsing, 404 flood, traversal, privesc
  behavior.py               behavioral baseline comparison (login + command)
  alerting.py                Telegram + Email senders, AlertDispatcher
  active_response.py          iptables blocking, whitelist, duration escalation
  ai_triage.py                 OpenAI plain-language verdicts
templates/                  Jinja2 templates (7 screens + base.html + 404.html)
static/agent/sentinel_agent.py   downloadable remote-agent script
sample_logs/                bundled demo logs for Replay mode
tests/                      pytest suite — parsers, detectors, behavior, active response (51 tests)
install_sentinellog.sh      systemd service + guided .env setup for a real Linux server
.env                        SECRET_KEY, ADMIN_PASSWORD, ENCRYPTION_KEY, OPENAI_API_KEY, WHITELIST_IPS
```

## 11. Security notes

- Dashboard access: single admin account, session cookie via Flask-Login.
- Remote agent ingestion is a **separate, narrower trust boundary** — a per-session random key, not the admin password, and it can only push lines into one specific session's pipeline, nothing else.
- Telegram tokens, email passwords, and email usernames are encrypted at rest (Fernet, key from `ENCRYPTION_KEY` in `.env`) — reading the raw `.db` file isn't enough to recover them.
- Active-response blocking respects a hard-coded whitelist and is time-boxed by design specifically so a false positive can't lock out a legitimate admin permanently.

## 12. Known gaps / where this doesn't scale yet

- **Single admin, no RBAC** — one login for the whole install, no team accounts, no per-client isolation. This is the main blocker to an MSP/consultant deployment model (one person managing several clients' installs).
- **Alerting channels** — Telegram and Email only; no WhatsApp or SMS, which matter more than either in low-connectivity or mobile-first markets.
- **Multi-tenancy** — remote agents help one dashboard watch many servers, but there's still no concept of "customer" separating whose servers/alerts belong to whom.
- **No compliance/reporting layer** — no exportable audit reports for something like NDPR/POPIA-style requirements.
- **Windows Event Log support** — currently Linux log formats only (auth.log, nginx/apache, sudo); no Windows Server/AD source.
