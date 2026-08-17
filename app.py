"""
SentinelLog - Flask Application
"""
import os, json, uuid, queue, threading, time, secrets, hmac
from datetime import datetime, timedelta
from dataclasses import asdict
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify, Response, stream_with_context, redirect, url_for
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from core.unified import UnifiedMonitor, merge_line_sources
from core.alerting import AlertDispatcher
from core.behavior import check_login_behavior, check_command_behavior
from models import db, AdminUser, MonitorSession, AlertRecord, BehaviorBaseline, IPBlock
from core.active_response import is_whitelisted, compute_duration, block_ip, unblock_ip

load_dotenv()  # reads the .env file into environment variables

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-only-fallback-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'sentinellog.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Live, in-memory state for sessions that are *currently streaming* in this process.
# Everything that needs to survive a restart (alerts, session config, stats) lives in the database instead.
active_streams = {}


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(AdminUser, int(user_id))


def init_db():
    with app.app_context():
        db.create_all()
        # Lightweight migration: create_all() only creates missing tables, it never
        # alters an existing one — so a column added after the .db file already
        # exists (like agent_key) needs to be bolted on by hand, once, here.
        existing_cols = {row[1] for row in db.session.execute(
            db.text("PRAGMA table_info(monitor_session)")
        )}
        if 'agent_key' not in existing_cols:
            db.session.execute(db.text("ALTER TABLE monitor_session ADD COLUMN agent_key VARCHAR(64) DEFAULT ''"))
            db.session.commit()
        if not AdminUser.query.first():
            username = os.environ.get('ADMIN_USERNAME', 'admin')
            password = os.environ.get('ADMIN_PASSWORD', 'change-me')
            admin = AdminUser(username=username, password_hash=generate_password_hash(password))
            db.session.add(admin)
            db.session.commit()
            print(f"\n  Created admin user '{username}' from .env\n")


# ─── Auth ────────────────────────────────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    error = None
    if request.method == 'POST':
        user = AdminUser.query.filter_by(username=request.form.get('username', '')).first()
        if user and check_password_hash(user.password_hash, request.form.get('password', '')):
            login_user(user)
            return redirect(url_for('index'))
        error = 'Invalid username or password.'
    return render_template('login.html', error=error)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# ─── Pages ───────────────────────────────────────────────────────────────────

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/monitor/new')
@login_required
def new_monitor():
    return render_template('new_monitor.html')

@app.route('/monitor/<session_id>')
@login_required
def monitor_view(session_id):
    sess = db.session.get(MonitorSession, session_id)
    if not sess:
        return render_template('404.html'), 404
    return render_template('monitor.html', session_id=session_id)

@app.route('/alerts')
@login_required
def alerts_board():
    records = AlertRecord.query.order_by(AlertRecord.timestamp.desc()).all()
    flat = [r.to_dict() for r in records]
    return render_template('alerts.html', alerts=flat)

@app.route('/alerts/<alert_id>')
@login_required
def alert_detail(alert_id):
    record = db.session.get(AlertRecord, alert_id)
    if not record:
        return render_template('404.html'), 404
    block = IPBlock.query.filter_by(alert_id=alert_id).order_by(IPBlock.id.desc()).first()
    return render_template('alert_detail.html', alert=record.to_dict(), session_id=record.session_id,
                            block=block.to_dict() if block else None)

@app.route('/blocks')
@login_required
def blocks_board():
    records = IPBlock.query.order_by(IPBlock.id.desc()).all()
    return render_template('blocks.html', blocks=[r.to_dict() for r in records])


# ─── Shared line-reading helper ─────────────────────────────────────────────

# ─── Behavioral baseline helper ─────────────────────────────────────────────

# ─── Active response (automated, scoped, whitelisted, time-boxed) ─────────

def _maybe_block_ip(alert, session_id):
    ip = alert.source_ip
    if is_whitelisted(ip):
        return f"{ip} is on the whitelist — no action taken"

    existing = IPBlock.query.filter_by(ip=ip, active=True).first()
    if existing:
        return f"{ip} is already blocked (in effect until {existing.unblock_at})"

    prior_count = IPBlock.query.filter_by(ip=ip).count()
    duration = compute_duration(prior_count)
    success, message = block_ip(ip)

    now = datetime.now()
    row = IPBlock(
        ip=ip, session_id=session_id, alert_id=alert.id,
        blocked_at=now.isoformat(),
        unblock_at=(now + timedelta(seconds=duration)).isoformat(),
        duration_seconds=duration, block_count=prior_count + 1,
        active=success, note=message,
    )
    db.session.add(row)
    db.session.commit()

    minutes = duration // 60
    return message + (f" — blocked for {minutes} minutes (offense #{prior_count + 1})" if success else "")


def _unblock_sweep():
    """Runs forever in the background, checking every 60s for any block whose
    time is up and lifting it. This is what makes the blocks temporary instead
    of accidentally permanent."""
    while True:
        time.sleep(60)
        try:
            with app.app_context():
                now_iso = datetime.now().isoformat()
                expired = IPBlock.query.filter(IPBlock.active == True, IPBlock.unblock_at <= now_iso).all()
                for row in expired:
                    success, message = unblock_ip(row.ip)
                    row.active = False
                    row.note += f" | {message}"
                    db.session.commit()
                    print(f"[Active Response] {message}")
        except Exception as e:
            print(f"[Active Response] Sweep failed, will retry in 60s: {e}")


def _get_baseline_row(log_type, identity):
    baseline_id = f"{log_type}:{identity}"
    row = db.session.get(BehaviorBaseline, baseline_id)
    if not row:
        row = BehaviorBaseline(id=baseline_id, log_type=log_type, identity=identity, event_count=0)
        db.session.add(row)
    return row


def _baseline_summary(log_type, identity):
    """Plain-text summary of a real account's history, handed to the AI so it can
    reason about deviation directly instead of only describing today's event."""
    if not identity:
        return None
    row = db.session.get(BehaviorBaseline, f"{log_type}:{identity}")
    if not row and log_type == 'auto':
        # Alerts can now come from any rule in the same session (auth, sudo, or web),
        # so a caller that doesn't know which baseline domain applies can ask for
        # 'auto' and this checks both instead of guessing wrong and finding nothing.
        row = db.session.get(BehaviorBaseline, f"auth:{identity}") or db.session.get(BehaviorBaseline, f"sudo:{identity}")
    if not row or row.event_count < 1:
        return None
    p = row.to_profile()
    parts = [f"{p['event_count']} prior recorded events for '{identity}'."]
    if p.get('known_ips'):
        parts.append(f"Usual IPs: {', '.join(p['known_ips'])}.")
    if p.get('login_hours'):
        hours = sorted(p['login_hours'])
        parts.append(f"Usual login hours: {', '.join(f'{h:02d}:00' for h in hours)}.")
    if p.get('commands'):
        parts.append(f"Usual commands: {', '.join(p['commands'])}.")
    return " ".join(parts)


def iter_agent_lines(session_id, is_running):
    """
    Yields lines pushed by a remote agent via POST /api/ingest/<session_id>, instead
    of reading a local file. Blocks on the session's ingest queue between pushes so
    this drops into the exact same processing loop as a local tail/replay.
    """
    while is_running():
        stream = active_streams.get(session_id)
        if not stream:
            break
        try:
            line = stream['ingest_queue'].get(timeout=1.0)
        except queue.Empty:
            continue
        yield line


# ─── Monitor control API ────────────────────────────────────────────────────

@app.route('/api/monitor/start', methods=['POST'])
@login_required
def api_start_monitor():
    return jsonify(_start_monitor_session(request.json))


def _start_monitor_session(data):
    """
    Shared by both starting a brand-new monitor from the form, and resuming
    a session that's no longer live (same config, new session_id, new worker).
    """
    session_id = str(uuid.uuid4())[:8]
    q = queue.Queue()
    ready = threading.Event()
    mode = data.get('mode', 'replay')
    is_agent = mode == 'agent'
    agent_key = secrets.token_hex(20) if is_agent else ''

    sess_row = MonitorSession(
        id=session_id,
        target_name=data.get('target_name', 'Unnamed'),
        server_ip=data.get('server_ip', ''),
        log_type=data.get('log_type', 'auto'),
        filepath=data.get('filepath', 'sample_logs/auth.log'),
        mode=mode,
        delay=float(data.get('delay', 0.15)),
        started_at=datetime.now().isoformat(),
        running=False,
        agent_key=agent_key,
        telegram_token=data.get('telegram_token', ''),
        telegram_chat_id=data.get('telegram_chat_id', ''),
        email_username=data.get('email_username', ''),
        email_password=data.get('email_password', ''),
        email_to=data.get('email_to', ''),
    )
    db.session.add(sess_row)
    db.session.commit()

    active_streams[session_id] = {
        'queue': q, 'ready': ready, 'running': False, 'connected': is_agent,
        'ingest_queue': queue.Queue() if is_agent else None,
    }

    def is_running():
        return active_streams.get(session_id, {}).get('running', False)

    def worker():
        # A remote agent pushes lines whenever it wants, independent of whether anyone
        # has the dashboard open — unlike replay/tail, there's no local file sitting
        # around to read whenever a browser eventually connects, so don't gate on that.
        if not is_agent:
            ready.wait(timeout=30)
            if not active_streams.get(session_id, {}).get('connected', False):
                # Either nobody connected within 30s, or a Stop request woke this up early
                # before anyone ever did — either way, there's nothing to process. Clean up
                # so this correctly shows as historical instead of looking connectable forever.
                active_streams.pop(session_id, None)
                with app.app_context():
                    row = db.session.get(MonitorSession, session_id)
                    if row:
                        row.running = False
                        db.session.commit()
                return
            time.sleep(0.3)

        with app.app_context():
            row = db.session.get(MonitorSession, session_id)
            row.running = True
            db.session.commit()

            active_streams[session_id]['running'] = True
            mode = row.mode
            filepath = row.filepath
            delay = row.delay

            dispatcher = AlertDispatcher()
            dispatcher.add_telegram(row.telegram_token, row.telegram_chat_id)
            dispatcher.add_gmail(row.email_username, row.email_password, row.email_to)

            def put(ev, d):
                q.put({'event': ev, 'data': d})

            def put_alert(alert):
                action_note = None
                if alert.rule == 'brute_force' and alert.source_ip:
                    try:
                        action_note = _maybe_block_ip(alert, session_id)
                    except Exception as e:
                        print(f"[Monitor {session_id}] Active response skipped: {e}")

                ai_verdict = None
                try:
                    from core.ai_triage import investigate
                    baseline_ctx = _baseline_summary('auto', alert.username or alert.source_ip)
                    if action_note:
                        baseline_ctx = (baseline_ctx or "") + f"\n\nAutomated action already taken: {action_note}"
                    ai_verdict = investigate(alert, baseline_context=baseline_ctx)
                except Exception as e:
                    print(f"[Monitor {session_id}] AI triage skipped: {e}")

                try:
                    row.alerts_fired += 1
                    db.session.add(AlertRecord.from_alert(alert, session_id, ai_verdict=ai_verdict))
                    db.session.commit()
                except Exception as e:
                    # A single alert failing to save should never take down the whole
                    # monitoring session — log it, reset the DB session, and keep watching.
                    print(f"[Monitor {session_id}] Failed to save alert, continuing anyway: {e}")
                    db.session.rollback()
                put('alert', {**asdict(alert), 'ai_verdict': ai_verdict})
                try:
                    dispatcher.dispatch(alert, ai_verdict=ai_verdict)
                except Exception:
                    pass

            try:
                def on_event(kind, event):
                    row.lines_processed += 1
                    if kind == 'auth':
                        if event.event_type == 'auth_failure':
                            row.auth_failures += 1
                        elif event.event_type == 'auth_success':
                            row.auth_successes += 1
                    try:
                        db.session.commit()
                    except Exception as e:
                        print(f"[Monitor {session_id}] Commit failed, continuing: {e}")
                        db.session.rollback()

                    if kind == 'auth':
                        put('log_event', {
                            'timestamp': event.timestamp.isoformat(),
                            'event_type': event.event_type,
                            'username': event.username,
                            'source_ip': event.source_ip,
                            'raw_line': event.raw_line
                        })
                    elif kind == 'nginx':
                        put('log_event', {
                            'timestamp': event.timestamp.isoformat(),
                            'event_type': event.event_type,
                            'username': None,
                            'source_ip': event.source_ip,
                            'raw_line': event.raw_line
                        })
                    else:  # sudo
                        put('log_event', {
                            'timestamp': event['timestamp'].isoformat(),
                            'event_type': 'sudo',
                            'username': event.get('user'),
                            'source_ip': None,
                            'raw_line': event.get('raw_line', '')
                        })

                def on_behavior(kind, event):
                    try:
                        if kind == 'auth' and event.event_type == 'auth_success' and event.username:
                            brow = _get_baseline_row('auth', event.username)
                            profile, behavior_alert = check_login_behavior(
                                brow.to_profile(), event.username, event.source_ip,
                                event.timestamp.hour, event.timestamp.isoformat(), event.raw_line
                            )
                            brow.apply_profile(profile)
                            brow.last_seen = event.timestamp.isoformat()
                            if not brow.first_seen:
                                brow.first_seen = event.timestamp.isoformat()
                            db.session.commit()
                            if behavior_alert:
                                put_alert(behavior_alert)
                        elif kind == 'sudo':
                            user = event.get('user')
                            command = event.get('command') or event.get('raw_line', '').split('COMMAND=')[-1]
                            if user and command:
                                brow = _get_baseline_row('sudo', user)
                                profile, behavior_alert = check_command_behavior(
                                    brow.to_profile(), user, command,
                                    event['timestamp'].isoformat(), event.get('raw_line', '')
                                )
                                brow.apply_profile(profile)
                                brow.last_seen = event['timestamp'].isoformat()
                                if not brow.first_seen:
                                    brow.first_seen = event['timestamp'].isoformat()
                                db.session.commit()
                                if behavior_alert:
                                    put_alert(behavior_alert)
                    except Exception as e:
                        print(f"[Monitor {session_id}] Behavior check failed, continuing: {e}")
                        db.session.rollback()

                # Every rule — brute force, suspicious login time, 404 flood, directory
                # traversal, privilege escalation, and both behavioral baselines — runs
                # together on every line, regardless of which format that line turns out
                # to be. No upfront "what am I watching for" choice needed.
                unified = UnifiedMonitor(on_event=on_event, on_alert=put_alert, on_behavior=on_behavior)

                if mode == 'agent':
                    for line in iter_agent_lines(session_id, is_running):
                        unified.process_line(line, assumed_year=2026)
                else:
                    paths = [p.strip() for p in filepath.replace(',', '\n').split('\n') if p.strip()]
                    for line in merge_line_sources(paths, mode, delay, is_running):
                        unified.process_line(line, assumed_year=2026)

            except Exception as e:
                put('error', {'message': str(e)})
            finally:
                put('complete', {})
                row.running = False
                db.session.commit()
                # The worker is genuinely done now — remove it so a page reload after this
                # correctly shows "historical" instead of falsely looking connectable forever.
                active_streams.pop(session_id, None)

    threading.Thread(target=worker, daemon=True).start()
    result = {'session_id': session_id, 'status': 'started'}
    if is_agent:
        result['agent_key'] = agent_key
    return result


@app.route('/api/ingest/<session_id>', methods=['POST'])
def api_ingest(session_id):
    """
    Where a remote agent pushes log lines from a server this box never opens a file
    on directly. Deliberately not @login_required — an unattended agent on another
    machine can't hold a browser session — auth is the per-session agent_key instead,
    generated once when the session was started in 'agent' mode and shown to the admin.
    """
    row = db.session.get(MonitorSession, session_id)
    if not row or row.mode != 'agent':
        return jsonify({'error': 'Unknown agent session'}), 404

    supplied = request.headers.get('X-Agent-Key', '')
    if not row.agent_key or not hmac.compare_digest(supplied, row.agent_key):
        return jsonify({'error': 'Invalid agent key'}), 403

    stream = active_streams.get(session_id)
    if not stream or not stream.get('ingest_queue'):
        return jsonify({'error': 'Session is not currently accepting lines — start a new monitor'}), 409

    lines = (request.json or {}).get('lines') or []
    if not isinstance(lines, list):
        return jsonify({'error': 'lines must be a list of strings'}), 400
    lines = [str(l) for l in lines[:1000]]  # cap a single batch — an agent should send small, frequent batches

    for line in lines:
        stream['ingest_queue'].put(line)

    return jsonify({'accepted': len(lines)})


@app.route('/api/monitor/<session_id>/resume', methods=['POST'])
@login_required
def api_resume_monitor(session_id):
    """
    Start a brand-new live session using the exact same config as an old one —
    same file, mode, log type, and alert channels. This is what 'continue
    watching' actually means: the old session_id's own worker thread is gone
    once the process restarts or it finishes, but its settings live on in the
    database, so we just start fresh with them and hand back a new session_id.
    """
    old = db.session.get(MonitorSession, session_id)
    if not old:
        return jsonify({'error': 'Original session not found'}), 404
    result = _start_monitor_session({
        'target_name': old.target_name,
        'server_ip': old.server_ip,
        'log_type': old.log_type,
        'filepath': old.filepath,
        'mode': old.mode,
        'delay': old.delay,
        'telegram_token': old.telegram_token,
        'telegram_chat_id': old.telegram_chat_id,
        'email_username': old.email_username,
        'email_password': old.email_password,
        'email_to': old.email_to,
    })
    return jsonify(result)


@app.route('/api/monitor/<session_id>/alerts')
@login_required
def api_session_alerts(session_id):
    """Historical alerts already saved for this specific session — used to
    populate the Live Alerts panel when a monitor page is opened after the
    fact, instead of only showing alerts that stream in after the page loads."""
    records = AlertRecord.query.filter_by(session_id=session_id).order_by(AlertRecord.timestamp.desc()).all()
    return jsonify([r.to_dict() for r in records])


@app.route('/api/monitor/<session_id>/stream')
@login_required
def api_stream(session_id):
    stream = active_streams.get(session_id)
    if not stream:
        return jsonify({'error': 'This session is not currently live in this process (e.g. the server restarted). Historical alerts are still saved.'}), 404
    q = stream['queue']
    stream['connected'] = True
    stream['ready'].set()

    def generate():
        while True:
            try:
                item = q.get(timeout=20)
                yield f"event: {item['event']}\ndata: {json.dumps(item['data'])}\n\n"
                if item['event'] == 'complete':
                    break
            except queue.Empty:
                yield "event: heartbeat\ndata: {}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
    )

@app.route('/api/monitor/stop/<session_id>', methods=['POST'])
@login_required
def api_stop_monitor(session_id):
    if session_id in active_streams:
        active_streams[session_id]['running'] = False
        # If nobody ever connected to this session's live view, its worker is still
        # blocked waiting for that — wake it up now instead of leaving it stuck for 30s.
        active_streams[session_id]['ready'].set()
    row = db.session.get(MonitorSession, session_id)
    if row:
        row.running = False
        db.session.commit()
    return jsonify({'status': 'stopped'})

@app.route('/api/monitor/<session_id>/status')
@login_required
def api_monitor_status(session_id):
    row = db.session.get(MonitorSession, session_id)
    if not row:
        return jsonify({'error': 'Not found'}), 404
    return jsonify({
        'target_name': row.target_name,
        'started_at': row.started_at,
        'stats': row.stats_dict(),
        'alert_count': AlertRecord.query.filter_by(session_id=session_id).count(),
        'filepath': row.filepath,
        'mode': row.mode,
        'log_type': row.log_type,
        'running': row.running,
        # True the instant a session is created, even before its first byte is processed —
        # this is what should gate "try to connect", not `running`, which only flips true
        # AFTER something connects. Gating on `running` was a chicken-and-egg deadlock.
        'live_available': session_id in active_streams,
        'agent_key': row.agent_key if row.mode == 'agent' else None,
        'ingest_url': url_for('api_ingest', session_id=session_id, _external=True) if row.mode == 'agent' else None,
    })

@app.route('/api/sessions')
@login_required
def api_sessions():
    rows = MonitorSession.query.order_by(MonitorSession.started_at.desc()).all()
    return jsonify([{
        'id': r.id,
        'target_name': r.target_name,
        'server_ip': r.server_ip,
        'started_at': r.started_at,
        'stats': r.stats_dict(),
        'alert_count': AlertRecord.query.filter_by(session_id=r.id).count()
    } for r in rows])

@app.route('/api/alerts')
@login_required
def api_all_alerts():
    records = AlertRecord.query.order_by(AlertRecord.timestamp.desc()).all()
    return jsonify([r.to_dict() for r in records])

@app.route('/api/blocks')
@login_required
def api_all_blocks():
    records = IPBlock.query.order_by(IPBlock.id.desc()).all()
    return jsonify([r.to_dict() for r in records])

@app.route('/api/telegram/test', methods=['POST'])
@login_required
def api_telegram_test():
    from core.alerting import TelegramAlerter
    data = request.json
    tg = TelegramAlerter(data.get('token', ''), data.get('chat_id', ''))
    ok = tg.test()
    return jsonify({'ok': ok, 'error': None if ok else tg.last_error})

@app.route('/api/email/test', methods=['POST'])
@login_required
def api_email_test():
    from core.alerting import EmailAlerter
    data = request.json
    if data.get('provider') == 'gmail':
        emailer = EmailAlerter.gmail(data.get('username', ''), data.get('password', ''), data.get('to', ''))
    else:
        emailer = EmailAlerter(
            data.get('smtp_host', ''), int(data.get('smtp_port', 587)),
            data.get('username', ''), data.get('password', ''),
            data.get('username', ''), data.get('to', '')
        )
    ok = emailer.test()
    return jsonify({'ok': ok, 'error': None if ok else emailer.last_error})


if __name__ == '__main__':
    init_db()
    threading.Thread(target=_unblock_sweep, daemon=True).start()
    from waitress import serve
    print("\n  SentinelLog\n  http://127.0.0.1:5050\n  (running on waitress, not the Flask dev server)\n")
    serve(app, host='0.0.0.0', port=5050, threads=8)
