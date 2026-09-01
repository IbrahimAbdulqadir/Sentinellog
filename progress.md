# Progress Log

Running notes on in-progress work and investigations in this repo, kept here (rather than in Claude's memory) so context survives closing the editor between sessions. Add a dated entry per thread of work; keep resolved items but mark them done.

---

## 2026-08-20 — user4 root-escalation investigation

**Status:** open — root cause not yet identified.

**Trigger:** Yesterday (Aug 19) `user4` reportedly became root on the `Ibrahim` host, but SentinelLog's `PrivilegeEscalationDetector` (watches `sudo` lines) did not fire an alert.

**What we've confirmed from `/var/log/auth.log` and `/var/log/audit/audit.log`:**
- `user4` had failed SSH password attempts from two external IPs on Aug 19 (`100.90.132.113` at 08:16, `100.96.169.78` at 15:14–15:15).
- `ibrahim` reset `user4`'s password at 15:40 and verified access via `su user4` at 15:52.
- `user4` logged in successfully over SSH from `100.96.169.78` at 16:03 and again 16:41 (session id 290) using the new password.
- At 16:46:41, `user4` ran `sudo cd root` and was **denied** — `user4` is not in `/etc/sudoers` or the `sudo` group (only `ibrahim`, `user3` are).
- Every `key="rootshell_cmd"` audit hit tied to `user4`'s session (auid=1004, uid=0) traces to two benign root-owned helpers, not a shell `user4` controlled:
  - `env` → `run-parts` → `10-uname` (dash) → `uname`, `tty=(none)` — standard PAM dynamic-MOTD generation (`run-parts /etc/update-motd.d`) that runs as root on every login for every user.
  - `unix_chkpwd ... nullok` / `... chkexpiry`, `tty=pts3` — `sudo`'s own setuid-root password-check helper, tied to the (denied) `sudo cd root` attempt.
- `user4`'s group memberships: `user4` (primary), `maintenance` (secondary, gid 1005) — a possible escalation path independent of sudoers that hasn't been ruled out yet.

**Working theory:** if `user4` really did get root, it likely happened through a path none of SentinelLog's current five log sources (sudo, su, audit rootshell_cmd, scope, nginx/auth) watch — e.g. a SUID/SGID binary, a cron job or script writable via the `maintenance` group, or a polkit rule. That would explain why both `PrivilegeEscalationDetector` and `AccountSwitchDetector` stayed silent: neither watches that kind of vector.

**Also flagged (detector gap, separate from the root cause above):** `RootShellCommandDetector` (`core/detection_w2.py:467`) currently has no way to distinguish a genuinely escalated interactive shell from routine root-owned session-open helpers (MOTD run-parts, unix_chkpwd), so it's a likely source of noisy false "critical" alerts on ordinary logins. Worth revisiting once the actual escalation vector is confirmed.

**Next steps (commands requested, outputs not yet provided):**
1. What specifically indicated `user4` became root yesterday? (a command, a file, something in history)
2. `sudo -u user4 find / -perm -4000 -o -perm -2000 2>/dev/null` — output pending
3. `getent group maintenance` and `find / -group maintenance -perm -002 2>/dev/null`
4. `cat /etc/crontab; ls -la /etc/cron.d/ /etc/cron.daily/`
5. Full `cat /etc/sudoers.d/*` (previous grep only matched literal `user4`, would miss a `%maintenance` group rule)
6. `sudo cat /home/user4/.bash_history`, `sudo cat /root/.bash_history` (if present), `lastlog -u user4`

---

## 2026-09-01 — tester round wrap-up + what to work on next

**Context:** paused SentinelLog to pick up another project. This entry is the handoff so the thread is easy to resume.

### The four-tester exercise (done)

Ran SentinelLog against four real people on the `sentinellog-kali` VM (Tailscale-only, service running 24/7, tailing `/var/log/auth.log` + `/var/log/audit/audit.log`). One account each, briefs in `friend-access/user{1..4}.html`:

- **user1** — no privileges, no sudo, no groups. Asked to attempt escalation and lateral `su` that the OS would refuse. Goal: confirm a *denied* attempt still alerts. Held up.
- **user2** — one permitted sudo command (`find`). Asked to use it normally, then abuse it via `find -exec /bin/sh` to a real root shell. Both the everyday use and the abuse alerted; commands run *inside* the escalated shell were caught by the auditd root-shell watch. Held up.
- **user3** — ordinary staff account, not on the trusted list. Asked to run sudo commands including obviously malicious ones. Every one flagged. Held up.
- **user4** — same low access, no hints, told only that a real misconfiguration to root exists on the box. Found a route to root that SentinelLog never reported (see the Aug 20 investigation above — still open). This is the finding that matters.

Also surfaced a genuine positive: the behavioural engine flagged the operator's own repeated password retries + password change as unusual for that account — an unplanned, correct hit.

LinkedIn post drafted from this (kept in chat, not committed). Screenshots to be attached by Ibrahim.

### Priority order when work resumes

1. **Close the user4 blind spot (highest).** Blocked on box data — run the six commands in the Aug 20 entry, and just ask the tester how they did it. The deliverable is identifying the vector, then deciding which log source / detector needs to exist to see it. Everything below is secondary until this is known.
2. **Fix `RootShellCommandDetector` false positives** (`core/detection_w2.py:467`). It can't distinguish a real escalated interactive shell from routine root session helpers (MOTD run-parts, `unix_chkpwd`), so ordinary logins risk noisy "critical" alerts. Ship this before promoting the root-shell feature further.
3. **Then decide the next big push:** multi-tenancy / RBAC (the main structural blocker per `SYSTEM_OVERVIEW.md` §12 — single admin login, no per-customer separation) vs. broader detection coverage. Don't start either until the user4 vector is identified, since it may reshape what "more coverage" means.
