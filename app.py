"""
SentinelLog - Flask Application
"""
import json, uuid, queue, threading, time
from datetime import datetime
from dataclasses import asdict
from flask import Flask, render_template, request, jsonify, Response, stream_with_context
from core.detection import LogMonitor
from core.alerting import TelegramAlerter
from core.detection_w2 import (
    parse_nginx_line, parse_sudo_line,
    NotFoundFloodDetector, DirectoryTraversalDetector, PrivilegeEscalationDetector
)

app = Flask(__name__)
app.secret_key = 'sentinellog-2024'
monitor_sessions = {}
all_alerts = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/monitor/new')
def new_monitor():
    return render_template('new_monitor.html')

@app.route('/monitor/<session_id>')
def monitor_view(session_id):
    if session_id not in monitor_sessions:
        return render_template('404.html'), 404
    return render_template('monitor.html', session_id=session_id)

@app.route('/alerts')
def alerts_board():
    flat = []
    for sid, alerts in all_alerts.items():
        for a in alerts:
            flat.append({**asdict(a), 'session_id': sid})
    flat.sort(key=lambda a: a['timestamp'], reverse=True)
    return render_template('alerts.html', alerts=flat)

@app.route('/alerts/<alert_id>')
def alert_detail(alert_id):
    for sid, alerts in all_alerts.items():
        for a in alerts:
            if a.id == alert_id:
                return render_template('alert_detail.html', alert=asdict(a), session_id=sid)
    return render_template('404.html'), 404

@app.route('/api/monitor/start', methods=['POST'])
def api_start_monitor():
    data = request.json
    session_id = str(uuid.uuid4())[:8]
    q = queue.Queue()
    all_alerts[session_id] = []
    ready = threading.Event()
    tg = TelegramAlerter(
        bot_token=data.get('telegram_token', ''),
        chat_id=data.get('telegram_chat_id', '')
    )
    sess = {
        'id': session_id,
        'target_name': data.get('target_name', 'Unnamed'),
        'log_type': data.get('log_type', 'auth'),
        'filepath': data.get('filepath', 'sample_logs/auth.log'),
        'delay': float(data.get('delay', 0.15)),
        'started_at': datetime.now().isoformat(),
        'running': False,
        'queue': q,
        'ready': ready,
        'telegram': tg,
        'stats': {'lines_processed': 0, 'auth_failures': 0, 'auth_successes': 0, 'alerts_fired': 0}
    }
    monitor_sessions[session_id] = sess

    def worker():
        ready.wait(timeout=30)
        if not ready.is_set():
            return
        time.sleep(0.3)
        sess['running'] = True
        sess['telegram'].send_startup(sess['target_name'])
        log_type = sess['log_type']
        filepath = sess['filepath']
        delay = sess['delay']

        def put(ev, d):
            q.put({'event': ev, 'data': d})

        def put_alert(alert):
            sess['stats']['alerts_fired'] += 1
            all_alerts[session_id].append(alert)
            put('alert', asdict(alert))
            sess['telegram'].send(alert)

        try:
            if log_type == 'auth':
                monitor = LogMonitor()
                def on_event(event):
                    sess['stats']['lines_processed'] += 1
                    if event.event_type == 'auth_failure':
                        sess['stats']['auth_failures'] += 1
                    elif event.event_type == 'auth_success':
                        sess['stats']['auth_successes'] += 1
                    put('log_event', {
                        'timestamp': event.timestamp.isoformat(),
                        'event_type': event.event_type,
                        'username': event.username,
                        'source_ip': event.source_ip,
                        'raw_line': event.raw_line
                    })
                monitor.event_callback = on_event
                monitor.alert_callback = put_alert
                monitor.replay_file(filepath, delay=delay, assumed_year=2026)

            elif log_type == 'nginx':
                d404 = NotFoundFloodDetector(threshold=20, window_seconds=60)
                dtrav = DirectoryTraversalDetector()
                with open(filepath, 'r') as f:
                    for line in f:
                        if not sess['running']:
                            break
                        sess['stats']['lines_processed'] += 1
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
                        time.sleep(delay)

            elif log_type == 'sudo':
                dpriv = PrivilegeEscalationDetector()
                with open(filepath, 'r') as f:
                    for line in f:
                        if not sess['running']:
                            break
                        sess['stats']['lines_processed'] += 1
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
                        time.sleep(delay)

        except Exception as e:
            put('error', {'message': str(e)})
        finally:
            put('complete', {})
            sess['running'] = False

    threading.Thread(target=worker, daemon=True).start()
    return jsonify({'session_id': session_id, 'status': 'started'})

@app.route('/api/monitor/<session_id>/stream')
def api_stream(session_id):
    sess = monitor_sessions.get(session_id)
    if not sess:
        return jsonify({'error': 'Not found'}), 404
    q = sess['queue']
    sess['ready'].set()

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
def api_stop_monitor(session_id):
    sess = monitor_sessions.get(session_id)
    if sess:
        sess['running'] = False
    return jsonify({'status': 'stopped'})

@app.route('/api/monitor/<session_id>/status')
def api_monitor_status(session_id):
    sess = monitor_sessions.get(session_id)
    if not sess:
        return jsonify({'error': 'Not found'}), 404
    return jsonify({
        'target_name': sess['target_name'],
        'started_at': sess['started_at'],
        'stats': sess['stats'],
        'alert_count': len(all_alerts.get(session_id, []))
    })

@app.route('/api/sessions')
def api_sessions():
    return jsonify([{
        'id': s['id'],
        'target_name': s['target_name'],
        'started_at': s['started_at'],
        'stats': s['stats'],
        'alert_count': len(all_alerts.get(s['id'], []))
    } for s in monitor_sessions.values()])

@app.route('/api/alerts')
def api_all_alerts():
    flat = []
    for sid, alerts in all_alerts.items():
        for a in alerts:
            flat.append({**asdict(a), 'session_id': sid})
    flat.sort(key=lambda a: a['timestamp'], reverse=True)
    return jsonify(flat)

if __name__ == '__main__':
    print("\n  SentinelLog\n  http://127.0.0.1:5050\n")
    app.run(debug=False, host='0.0.0.0', port=5050, threaded=True)


@app.route('/api/telegram/test', methods=['POST'])
def api_telegram_test():
    from core.alerting import TelegramAlerter
    data = request.json
    tg = TelegramAlerter(data.get('token',''), data.get('chat_id',''))
    ok = tg.test()
    return jsonify({'ok': ok, 'error': None if ok else 'Failed to send'})


@app.route('/api/email/test', methods=['POST'])
def api_email_test():
    from core.alerting import EmailAlerter
    data = request.json
    if data.get('provider') == 'gmail':
        emailer = EmailAlerter.gmail(data.get('username',''), data.get('password',''), data.get('to',''))
    else:
        emailer = EmailAlerter(
            data.get('smtp_host',''), int(data.get('smtp_port', 587)),
            data.get('username',''), data.get('password',''),
            data.get('username',''), data.get('to','')
        )
    ok = emailer.test()
    return jsonify({'ok': ok, 'error': None if ok else 'Check credentials'})
