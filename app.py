"""
SentinelLog — Flask Application
Week 1: Live log monitoring dashboard with brute force + suspicious time detection
"""

import json
import uuid
import queue
import threading
import os
from datetime import datetime
from dataclasses import asdict
from flask import Flask, render_template, request, jsonify, Response, stream_with_context

from core.detection import LogMonitor, parse_log_line
from core.detection_w2 import (
    parse_nginx_line, parse_sudo_line,
    NotFoundFloodDetector, DirectoryTraversalDetector, PrivilegeEscalationDetector
)

app = Flask(__name__)
app.secret_key = 'sentinellog-secret-2024'

# In-memory session store
monitor_sessions: dict = {}
event_queues: dict = {}
all_alerts: dict = {}   # session_id -> list of alerts
all_events: dict = {}   # session_id -> list of recent events (capped)


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
    flat_alerts = []
    for sid, alerts in all_alerts.items():
        for a in alerts:
            flat_alerts.append({**asdict(a), 'session_id': sid})
    flat_alerts.sort(key=lambda a: a['timestamp'], reverse=True)
    return render_template('alerts.html', alerts=flat_alerts)


@app.route('/alerts/<alert_id>')
def alert_detail(alert_id):
    for sid, alerts in all_alerts.items():
        for a in alerts:
            if a.id == alert_id:
                return render_template('alert_detail.html', alert=asdict(a), session_id=sid)
    return render_template('404.html'), 404


# ── API ──────────────────────────────────────────────────────────────────────

@app.route('/api/monitor/start', methods=['POST'])
def api_start_monitor():
    data = request.json
    session_id = str(uuid.uuid4())[:8]

    mode = data.get('mode', 'replay')       # 'replay' or 'tail'
    log_type = data.get('log_type', 'auth')     # 'auth', 'nginx', 'sudo'
    filepath = data.get('filepath', 'sample_logs/auth.log')
    delay = float(data.get('delay', 0.05))

    q = queue.Queue()
    event_queues[session_id] = q
    all_alerts[session_id] = []
    all_events[session_id] = []

    def on_event(event):
        all_events[session_id].append(event)
        if len(all_events[session_id]) > 500:
            all_events[session_id].pop(0)
        q.put({'event': 'log_event', 'data': {
            'timestamp': event.timestamp.isoformat(),
            'event_type': event.event_type,
            'username': event.username,
            'source_ip': event.source_ip,
            'raw_line': event.raw_line
        }})

    def on_alert(alert):
        all_alerts[session_id].append(alert)
        q.put({'event': 'alert', 'data': asdict(alert)})

    monitor = LogMonitor(event_callback=on_event, alert_callback=on_alert)
    monitor_sessions[session_id] = {
        'monitor': monitor,
        'mode': mode,
        'filepath': filepath,
        'started_at': datetime.utcnow().isoformat(),
        'target_name': data.get('target_name', 'Unnamed Source'),
        'log_type': log_type
    }

    # Week 2: support auth, nginx, sudo log types
    def run_monitor():
        import time as time_mod
        w2_404 = NotFoundFloodDetector(threshold=20, window_seconds=60)
        w2_trav = DirectoryTraversalDetector()
        w2_priv = PrivilegeEscalationDetector()

        def process_w2_line(line):
            if log_type == 'nginx':
                event = parse_nginx_line(line, 2026)
                if not event:
                    return
                on_event_raw(event)
                for detector in (w2_404, w2_trav):
                    alert = detector.process_event(event)
                    if alert:
                        on_alert(alert)
            elif log_type == 'sudo':
                event = parse_sudo_line(line, 2026)
                if not event:
                    return
                on_event_raw(event)
                alert = w2_priv.process_event(event)
                if alert:
                    on_alert(alert)
            else:
                monitor.process_line(line, assumed_year=2026)

        def on_event_raw(event):
            q.put({'event': 'log_event', 'data': {
                'timestamp': event.get('timestamp', datetime.utcnow()).isoformat() if isinstance(event, dict) else event.timestamp.isoformat(),
                'event_type': 'web_request' if hasattr(event, 'status_code') else 'sudo',
                'username': event.get('user') if isinstance(event, dict) else None,
                'source_ip': event.source_ip if hasattr(event, 'source_ip') else None,
                'raw_line': event.get('raw_line', '') if isinstance(event, dict) else event.raw_line
            }})

        if log_type in ('nginx', 'sudo'):
            with open(filepath, 'r') as f:
                for line in f:
                    if not monitor._running:
                        break
                    process_w2_line(line)
                    time_mod.sleep(delay)
        elif mode == 'tail':
            monitor.start_tail_async(filepath)
        else:
            import threading, time as _t
        def auth_with_delay():
            _t.sleep(1.0)
            monitor.replay_file(filepath, delay=delay, assumed_year=2026)
        threading.Thread(target=auth_with_delay, daemon=True).start()

    # Store run config so /api/monitor/<id>/run can trigger it after SSE connects
    monitor_sessions[session_id]['run_config'] = {
        'log_type': log_type,
        'mode': mode,
        'filepath': filepath,
        'delay': delay
    }

    return jsonify({'session_id': session_id, 'status': 'started'})




@app.route('/api/monitor/<session_id>/run', methods=['POST'])
def api_run_monitor(session_id):
    """Called by the browser after SSE connection is established."""
    import threading, time as _t
    sess = monitor_sessions.get(session_id)
    if not sess:
        return jsonify({'error': 'Not found'}), 404

    cfg = sess.get('run_config', {})
    log_type = cfg.get('log_type', 'auth')
    mode = cfg.get('mode', 'replay')
    filepath = cfg.get('filepath', 'sample_logs/auth.log')
    delay = cfg.get('delay', 0.15)
    monitor = sess['monitor']
    q = event_queues[session_id]

    def on_event(event):
        all_events[session_id].append(event)
        if len(all_events[session_id]) > 500:
            all_events[session_id].pop(0)
        q.put({'event': 'log_event', 'data': {
            'timestamp': event.timestamp.isoformat(),
            'event_type': event.event_type,
            'username': event.username,
            'source_ip': event.source_ip,
            'raw_line': event.raw_line
        }})

    def on_alert_run(alert):
        all_alerts[session_id].append(alert)
        q.put({'event': 'alert', 'data': asdict(alert)})

    monitor.event_callback = on_event
    monitor.alert_callback = on_alert_run

    def do_run():
        _t.sleep(0.3)
        if log_type == 'nginx':
            w2_404 = NotFoundFloodDetector(threshold=20, window_seconds=60)
            w2_trav = DirectoryTraversalDetector()
            monitor._running = True
            with open(filepath, 'r') as f:
                for line in f:
                    if not monitor._running:
                        break
                    event = parse_nginx_line(line, 2026)
                    if event:
                        q.put({'event': 'log_event', 'data': {
                            'timestamp': event.timestamp.isoformat(),
                            'event_type': event.event_type,
                            'username': None,
                            'source_ip': event.source_ip,
                            'raw_line': event.raw_line
                        }})
                        for det in (w2_404, w2_trav):
                            alert = det.process_event(event)
                            if alert:
                                all_alerts[session_id].append(alert)
                                q.put({'event': 'alert', 'data': asdict(alert)})
                    _t.sleep(delay)
            monitor._running = False

        elif log_type == 'sudo':
            w2_priv = PrivilegeEscalationDetector()
            monitor._running = True
            with open(filepath, 'r') as f:
                for line in f:
                    if not monitor._running:
                        break
                    event = parse_sudo_line(line, 2026)
                    if event:
                        q.put({'event': 'log_event', 'data': {
                            'timestamp': event['timestamp'].isoformat(),
                            'event_type': 'sudo',
                            'username': event.get('user'),
                            'source_ip': None,
                            'raw_line': event.get('raw_line', '')
                        }})
                        alert = w2_priv.process_event(event)
                        if alert:
                            all_alerts[session_id].append(alert)
                            q.put({'event': 'alert', 'data': asdict(alert)})
                    _t.sleep(delay)
            monitor._running = False

        else:
            monitor.replay_file(filepath, delay=delay, assumed_year=2026)

    threading.Thread(target=do_run, daemon=True).start()
    return jsonify({'status': 'running'})

@app.route('/api/monitor/stop/<session_id>', methods=['POST'])
def api_stop_monitor(session_id):
    sess = monitor_sessions.get(session_id)
    if not sess:
        return jsonify({'error': 'Not found'}), 404
    sess['monitor'].stop()
    return jsonify({'status': 'stopped'})


@app.route('/api/monitor/<session_id>/events')
def api_monitor_events(session_id):
    q = event_queues.get(session_id)
    if not q:
        return jsonify({'error': 'Not found'}), 404

    def generate():
        while True:
            try:
                item = q.get(timeout=30)
                yield f"event: {item['event']}\ndata: {json.dumps(item['data'])}\n\n"
            except queue.Empty:
                yield "event: heartbeat\ndata: {}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
    )


@app.route('/api/monitor/<session_id>/status')
def api_monitor_status(session_id):
    sess = monitor_sessions.get(session_id)
    if not sess:
        return jsonify({'error': 'Not found'}), 404
    stats = sess['monitor'].get_stats()
    return jsonify({
        'target_name': sess['target_name'],
        'mode': sess['mode'],
        'started_at': sess['started_at'],
        'stats': stats,
        'alert_count': len(all_alerts.get(session_id, []))
    })


@app.route('/api/sessions')
def api_sessions():
    result = []
    for sid, sess in monitor_sessions.items():
        stats = sess['monitor'].get_stats()
        result.append({
            'id': sid,
            'target_name': sess['target_name'],
            'mode': sess['mode'],
            'started_at': sess['started_at'],
            'stats': stats,
            'alert_count': len(all_alerts.get(sid, []))
        })
    return jsonify(result)


@app.route('/api/alerts')
def api_all_alerts():
    flat = []
    for sid, alerts in all_alerts.items():
        for a in alerts:
            flat.append({**asdict(a), 'session_id': sid})
    flat.sort(key=lambda a: a['timestamp'], reverse=True)
    return jsonify(flat)


@app.route('/api/upload-log', methods=['POST'])
def api_upload_log():
    """Accept an uploaded log file for analysis."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    f = request.files['file']
    os.makedirs('uploaded_logs', exist_ok=True)
    filename = f"uploaded_logs/{uuid.uuid4().hex[:8]}_{f.filename}"
    f.save(filename)
    return jsonify({'filepath': filename})


if __name__ == '__main__':
    print("\n  SentinelLog — Week 1\n  http://127.0.0.1:5050\n")
    app.run(debug=True, host='0.0.0.0', port=5050, threaded=True)
