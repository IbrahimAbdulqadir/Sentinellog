"""
SentinelLog - Flask Application
"""
import os, json, uuid, queue, threading, time
from datetime import datetime
from dataclasses import asdict
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify, Response, stream_with_context, redirect, url_for
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from core.detection import LogMonitor
from core.detection_w2 import (
    parse_nginx_line, parse_sudo_line,
    NotFoundFloodDetector, DirectoryTraversalDetector, PrivilegeEscalationDetector
)
from core.alerting import AlertDispatcher
from models import db, AdminUser, MonitorSession, AlertRecord

load_dotenv()  # reads the .env file into environment variables

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-only-fallback-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sentinellog.db'
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
    return AdminUser.query.get(int(user_id))


def init_db():
    with app.app_context():
        db.create_all()
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
    sess = MonitorSession.query.get(session_id)
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
    record = AlertRecord.query.get(alert_id)
    if not record:
        return render_template('404.html'), 404
    return render_template('alert_detail.html', alert=record.to_dict(), session_id=record.session_id)


# ─── Shared line-reading helper ─────────────────────────────────────────────

def iter_log_lines(filepath, mode, delay, is_running):
    """
    Yields lines from a log file.
    replay mode: reads the whole file from the top with a delay between lines (demo/replay).
    tail mode: jumps to the end of the file and only yields genuinely new lines as they're
    appended, like the real `tail -f` command. This is what makes 'watch a real log file' actually work.
    """
    if mode == 'tail':
        with open(filepath, 'r') as f:
            f.seek(0, 2)  # jump to current end of file — ignore everything already in it
            while is_running():
                line = f.readline()
                if line:
                    yield line
                else:
                    time.sleep(1.0)
    else:
        with open(filepath, 'r') as f:
            for line in f:
                if not is_running():
                    break
                yield line
                time.sleep(delay)


# ─── Monitor control API ────────────────────────────────────────────────────

@app.route('/api/monitor/start', methods=['POST'])
@login_required
def api_start_monitor():
    data = request.json
    session_id = str(uuid.uuid4())[:8]
    q = queue.Queue()
    ready = threading.Event()

    sess_row = MonitorSession(
        id=session_id,
        target_name=data.get('target_name', 'Unnamed'),
        server_ip=data.get('server_ip', ''),
        log_type=data.get('log_type', 'auth'),
        filepath=data.get('filepath', 'sample_logs/auth.log'),
        mode=data.get('mode', 'replay'),
        delay=float(data.get('delay', 0.15)),
        started_at=datetime.now().isoformat(),
        running=False,
        telegram_token=data.get('telegram_token', ''),
        telegram_chat_id=data.get('telegram_chat_id', ''),
        email_username=data.get('email_username', ''),
        email_password=data.get('email_password', ''),
        email_to=data.get('email_to', ''),
    )
    db.session.add(sess_row)
    db.session.commit()

    active_streams[session_id] = {'queue': q, 'ready': ready, 'running': False}

    def is_running():
        return active_streams.get(session_id, {}).get('running', False)

    def worker():
        ready.wait(timeout=30)
        if not ready.is_set():
            return
        time.sleep(0.3)

        with app.app_context():
            row = MonitorSession.query.get(session_id)
            row.running = True
            db.session.commit()

            active_streams[session_id]['running'] = True
            mode = row.mode
            log_type = row.log_type
            filepath = row.filepath
            delay = row.delay

            dispatcher = AlertDispatcher()
            dispatcher.add_telegram(row.telegram_token, row.telegram_chat_id)
            dispatcher.add_gmail(row.email_username, row.email_password, row.email_to)

            def put(ev, d):
                q.put({'event': ev, 'data': d})

            def put_alert(alert):
                row.alerts_fired += 1
                db.session.add(AlertRecord.from_alert(alert, session_id))
                db.session.commit()
                put('alert', asdict(alert))
                try:
                    dispatcher.dispatch(alert)
                except Exception:
                    pass

            try:
                if log_type == 'auth':
                    monitor = LogMonitor()

                    def on_event(event):
                        row.lines_processed += 1
                        if event.event_type == 'auth_failure':
                            row.auth_failures += 1
                        elif event.event_type == 'auth_success':
                            row.auth_successes += 1
                        db.session.commit()
                        put('log_event', {
                            'timestamp': event.timestamp.isoformat(),
                            'event_type': event.event_type,
                            'username': event.username,
                            'source_ip': event.source_ip,
                            'raw_line': event.raw_line
                        })

                    monitor.event_callback = on_event
                    monitor.alert_callback = put_alert
                    if mode == 'tail':
                        monitor.tail_file(filepath, poll_interval=1.0)
                    else:
                        monitor.replay_file(filepath, delay=delay, assumed_year=2026)

                elif log_type == 'nginx':
                    d404 = NotFoundFloodDetector(threshold=20, window_seconds=60)
                    dtrav = DirectoryTraversalDetector()
                    for line in iter_log_lines(filepath, mode, delay, is_running):
                        row.lines_processed += 1
                        event = parse_nginx_line(line, 2026)
                        if event:
                            put('log_event', {
                                'timestamp': event.timestamp.isoformat(),
                                'event_type': event.event_type,
                                'username': None,
                                'source_ip': event.source_ip,
                                'raw_line': event.raw_line
                            })
                            for det in (d404, dtrav):
                                alert = det.process_event(event)
                                if alert:
                                    put_alert(alert)
                        db.session.commit()

                elif log_type == 'sudo':
                    dpriv = PrivilegeEscalationDetector()
                    for line in iter_log_lines(filepath, mode, delay, is_running):
                        row.lines_processed += 1
                        event = parse_sudo_line(line, 2026)
                        if event:
                            put('log_event', {
                                'timestamp': event['timestamp'].isoformat(),
                                'event_type': 'sudo',
                                'username': event.get('user'),
                                'source_ip': None,
                                'raw_line': event.get('raw_line', '')
                            })
                            alert = dpriv.process_event(event)
                            if alert:
                                put_alert(alert)
                        db.session.commit()

            except Exception as e:
                put('error', {'message': str(e)})
            finally:
                put('complete', {})
                row.running = False
                db.session.commit()
                active_streams[session_id]['running'] = False

    threading.Thread(target=worker, daemon=True).start()
    return jsonify({'session_id': session_id, 'status': 'started'})


@app.route('/api/monitor/<session_id>/stream')
@login_required
def api_stream(session_id):
    stream = active_streams.get(session_id)
    if not stream:
        return jsonify({'error': 'This session is not currently live in this process (e.g. the server restarted). Historical alerts are still saved.'}), 404
    q = stream['queue']
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
    row = MonitorSession.query.get(session_id)
    if row:
        row.running = False
        db.session.commit()
    return jsonify({'status': 'stopped'})

@app.route('/api/monitor/<session_id>/status')
@login_required
def api_monitor_status(session_id):
    row = MonitorSession.query.get(session_id)
    if not row:
        return jsonify({'error': 'Not found'}), 404
    return jsonify({
        'target_name': row.target_name,
        'started_at': row.started_at,
        'stats': row.stats_dict(),
        'alert_count': AlertRecord.query.filter_by(session_id=session_id).count()
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

@app.route('/api/telegram/test', methods=['POST'])
@login_required
def api_telegram_test():
    from core.alerting import TelegramAlerter
    data = request.json
    tg = TelegramAlerter(data.get('token', ''), data.get('chat_id', ''))
    ok = tg.test()
    return jsonify({'ok': ok, 'error': None if ok else 'Failed'})

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
    return jsonify({'ok': ok, 'error': None if ok else 'Check credentials'})


if __name__ == '__main__':
    init_db()
    print("\n  SentinelLog\n  http://127.0.0.1:5050\n")
    app.run(debug=False, host='0.0.0.0', port=5050, threaded=True)
