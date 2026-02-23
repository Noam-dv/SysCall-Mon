from __future__ import annotations
import os
import sys
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, render_template, request
from syscall_helpers import syscall_category, SysType
from proc_util import ProcessUtil
from sys_tracer import SysTracer 

class MonApp:
    """
    flask application that mirrors the MonitorWindow flow in a web dashboard:
    - lists processes using proc util
    - starts and stops systracer instance for specific pid
    - drains tracer event queues in the background
    - endpoints used by index.html for processes and events
    - renders an index with categorys and realtime log
    """

    COLFORMAT = {
        SysType.FILE_IO: "#4fc3f7",
        SysType.FS_META: "#64b5f6",
        SysType.PROCESS: "#ffb74d",
        SysType.MEMORY: "#ba68c8",
        SysType.IPC: "#aed581",
        SysType.NETWORK: "#81c784",
        SysType.EVENTS: "#90a4ae",
        SysType.TIME: "#ffd54f",
        SysType.SECURITY: "#e57373",
        SysType.OTHER: "#b0bec5",
    }

    def __init__(self):
        self.app = Flask(__name__, template_folder='templates', static_folder='static')

        # proc listing and tracer management
        self.proc_util = ProcessUtil()
        self.tracers: Dict[int, SysTracer] = {}
        self.tracers_lock = threading.Lock()

        # event ring buffer 
        # newest event stored at the end
        self.MAX_EVENTS = 5000
        self.events: List[Dict[str, Any]] = []
        self.events_lock = threading.Lock()

        # poller
        # i attempted to write this more cleanly than the richclient version
        self.POLL_INTERVAL = 1.0  # seconds
        self._poll_thread = threading.Thread(target=self._poll_tracers_loop, daemon=True)
        self._poll_thread.start()

        # routes
        self._register_routes()


    def _format_args(self, args: Any) -> str:
        """
        formats dict arguments
        and keyword arguments
        """
        if not args:
            return ""
        if isinstance(args, dict):
            return ", ".join(f"{k}={v}" for k, v in args.items())
        return str(args)

    def _to_web_event(self, sc) -> Dict[str, Any]:
        """
        recieves event
        formats event to the version the api expects
        """
        st = getattr(sc, 'event_type', None) or syscall_category(getattr(sc, 'name', ''))
        ts = getattr(sc, 'timestamp', time.time())
        args = getattr(sc, 'args', None)
        anomalies = getattr(sc, 'anomalies', None) or []
        return {
            'pid': getattr(sc, 'pid', 0),
            'name': getattr(sc, 'name', ''),
            'timestamp': ts,
            'time': datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3],
            'category': st.value if isinstance(st, SysType) else str(st),
            'category_name': st.name if isinstance(st, SysType) else str(st),
            'args': args,
            'args_str': self._format_args(args),
            'anomaly': bool(anomalies),
            'anomalies': anomalies,
            'color': self.COLFORMAT.get(st, '#999999') if isinstance(st, SysType) else '#999999',
        }

    def _append_event(self, ev: Dict[str, Any]) -> None:
        """add an event, remove events from end"""
        with self.events_lock:
            self.events.append(ev)
            if len(self.events) > self.MAX_EVENTS:
                overflow = len(self.events) - self.MAX_EVENTS
                del self.events[:overflow]

    def _poll_tracers_loop(self):
        """
        thread loop to poll
        multi tracer will be allowed, therefore i will have threads
        """
        while True:
            with self.tracers_lock:
                items = list(self.tracers.items())
            for pid, tracer in items:
                for i in range(500):
                    try:
                        sc = tracer.events.get_nowait()
                    except Exception:
                        break
                    self._append_event(self._to_web_event(sc))
            time.sleep(self.POLL_INTERVAL)

    def _register_routes(self) -> None:
        """
        basic setup for endpoints
        ref app because flask doesnt like OOP apperantly
        """

        app = self.app

        @app.route('/')
        def index():
            """base route"""
            categories = [
                {
                    'key': st.name,
                    'value': st.value,
                    'label': st.value,
                    'checked': st != SysType.OTHER,
                    'color': self.COLFORMAT.get(st, '#999999'),
                }
                for st in SysType
            ]
            return render_template('index.html', categories=categories)

        @app.route('/api/processes', methods=['GET'])
        def api_processes():
            """
            api endpoint to list processes
            returns a json of the processes
            """
            procs = self.proc_util.get_all()
            out = []
            for p in procs:
                out.append({
                    'pid': p.pid,
                    'name': p.name,
                    'user': p.user or 'NA',
                    'status': p.status or 'NA',
                    'mem': p.mem,
                    'daemon': bool(getattr(p, 'daemon', False)),
                    'type': 'process' if not getattr(p, 'daemon', False) else 'service',
                })
            return jsonify({'processes': out})

        @app.route('/api/trace', methods=['POST'])
        def api_trace():
            """initialize tracer"""
            data = request.get_json(silent=True) or {}
            pid = data.get('pid')

            #verify pid
            if pid is None:
                return jsonify({'error': 'pid is required'}), 400
            try:
                pid = int(pid)
            except Exception:
                return jsonify({'error': 'pid must be an integer'}), 400

            with self.tracers_lock:
                if pid in self.tracers:
                    return jsonify({'status': 'ok', 'message': 'already tracing', 'pid': pid})
                try:
                    tracer = SysTracer(pid)
                    tracer.start()
                    self.tracers[pid] = tracer
                except Exception as e:
                    return jsonify({'error': f'failed to start tracer: {e}'}), 500

            return jsonify({'status': 'ok', 'pid': pid})

        @app.route('/api/stop', methods=['POST'])
        def api_stop():
            data = request.get_json(silent=True) or {}
            pid = data.get('pid')
            if pid is None:
                return jsonify({'error': 'pid is required'}), 400
            try:
                pid = int(pid)
            except Exception:
                return jsonify({'error': 'pid must be an integer'}), 400

            with self.tracers_lock:
                tracer = self.tracers.pop(pid, None)
            if tracer:
                try:
                    tracer.stop()
                except Exception:
                    pass
            return jsonify({'status': 'ok', 'pid': pid})

        @app.route('/api/events', methods=['GET'])
        def api_events():
            try:
                since = float(request.args.get('since', '0') or '0')
            except Exception:
                since = 0.0

            cats_raw = request.args.get('cats')
            cats: Optional[set] = None
            if cats_raw:
                cats = {c.strip() for c in cats_raw.split(',') if c.strip()}

            try:
                limit = int(request.args.get('limit', '500') or '500')
                limit = max(1, min(2000, limit))
            except Exception:
                limit = 500

            with self.events_lock:
                n = len(self.events)
                start = 0
                if since > 0 and n:
                    for i in range(n - 1, -1, -1):
                        if self.events[i]['timestamp'] <= since:
                            start = i + 1
                            break
                selected = []
                for e in self.events[start:]:
                    if cats is not None and e['category'] not in cats:
                        continue
                    selected.append(e)
                    if len(selected) >= limit:
                        break

            return jsonify({'events': selected, 'count': len(selected)})

        @app.route('/api/clear', methods=['POST'])
        def api_clear():
            with self.events_lock:
                self.events.clear()
            return jsonify({'status': 'ok'})

    def run(self, host: str = '127.0.0.1', port: int = 5000, debug: bool = True):
        self.app.run(host=host, port=port, debug=debug)


if __name__ == '__main__':
    MonApp().run()
