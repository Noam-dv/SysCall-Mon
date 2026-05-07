import sys, os
os.environ["QT_QPA_PLATFORM"] = "xcb"

import threading
import queue
import requests
import psutil

from PyQt6.QtWidgets import *
from PyQt6.QtCore import Qt, QTimer, pyqtSignal

from sys_tracer import SysTracer
from proc_util import ProcessUtil
from monitor_window import MonitorWindow


"""
connects to a remote server
sends syscall events and anomalies to it in the background
login window : auth against server, get token
agent app : process list and trace ui 
monitor window gets an extra "remote" tab
agent class handles the server pushing in bg
need root for ebpf
"""


# Agent

class Agent:
    """
    thin wrapper around systracer
    pushes events to the remote server in batches
    anomalies go through a queue and sender thread
    instead of spawning a new thread per anomaly
    """
    BATCH = 50

    def __init__(self, server_url, token, session_id):
        self.server = server_url.rstrip("/")
        self.token = token
        self.session_id = session_id
        self.tracers = {} # pid -> SysTracer
        self._buf = [] # pending events
        self._lock = threading.Lock()

        # single persistent thread for anomaly pushes
        self._anomaly_q = queue.Queue()
        self._anomaly_thread = threading.Thread(
            target=self._anomaly_sender, daemon=True
        )
        self._anomaly_thread.start()

    def _headers(self):
        return {"Authorization": f"Bearer {self.token}"}

    def add_pid(self, pid):
        if pid in self.tracers:
            return
        t = SysTracer(pid)
        t.start()
        self.tracers[pid] = t

    def drain(self):
        """
        pull events from all tracer queues into the push buffer
        returns the raw events so the ui can also display them
        called every 50ms by qt timer instead of a blocking loop
        """
        out = []
        for pid, tracer in list(self.tracers.items()):
            for _ in range(100):
                try:
                    evt = tracer.events.get_nowait()
                except queue.Empty:
                    break

                e = {
                    "pid": evt.pid,
                    "name": evt.name,
                    "timestamp": evt.timestamp,
                    "args": evt.args or {},
                    "category": evt.event_type.value if evt.event_type else "other",
                }

                with self._lock:
                    self._buf.append(e)

                out.append(evt)

                if evt.anomalies:
                    for a in evt.anomalies:
                        self._anomaly_q.put(a)  # hand off to sender thread

        return out

    def _flush_events_server(self):
        """push buffered events to server. called by qt timer"""
        with self._lock:
            if not self._buf:
                return
            batch = self._buf[:self.BATCH]
            self._buf = self._buf[self.BATCH:]

        def _do():
            try:
                r = requests.post(
                    f"{self.server}/api/sessions/{self.session_id}/push",
                    headers=self._headers(),
                    json={"events": batch},
                    timeout=5,
                )
                if r.status_code != 200:
                    print(f"[agent] push error {r.status_code}: {r.text[:100]}")
            except Exception as e:
                print(f"[agent] push failed: {e}")

        threading.Thread(target=_do, daemon=True).start()

    def _anomaly_sender(self):
        """
        persistent background thread 
        sits blocking on the anomaly queue
        sends one anomaly at a time so no thread spam
        """
        while True:
            anomaly = self._anomaly_q.get() # blocks until something arrives
            try:
                requests.post(
                    f"{self.server}/api/sessions/{self.session_id}/push_anomaly",
                    headers=self._headers(),
                    json={
                        "timestamp": anomaly.timestamp,
                        "pid": anomaly.pid,
                        "anomaly_type": anomaly.anomaly_type,
                        "severity": anomaly.severity,
                        "description": anomaly.description,
                        "details": anomaly.details,
                    },
                    timeout=3,
                )
            except Exception as e:
                print(f"[agent] anomaly push failed: {e}")

    def stop(self):
        for t in self.tracers.values():
            t.stop()
        self.tracers.clear()


# Login

class LoginWindow(QDialog):
    """
    shown before the main app
    handles login and signup against the flask server
    sets self.token and self.server_url if suceeded
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("sysmon agent login")
        self.resize(320, 200)
        self.token = None
        self.server_url = None
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.addWidget(QLabel("<b>sysmon remote agent</b>"))

        grid = QFormLayout()
        self.server_input = QLineEdit("http://localhost:5000")
        self.user_input = QLineEdit()
        self.pw_input = QLineEdit()
        self.pw_input.setEchoMode(QLineEdit.EchoMode.Password)

        grid.addRow("server:", self.server_input)
        grid.addRow("username:", self.user_input)
        grid.addRow("password:", self.pw_input)

        layout.addLayout(grid)

        self.status_lbl = QLabel("")
        layout.addWidget(self.status_lbl)

        btns = QHBoxLayout()
        login_btn = QPushButton("login")
        signup_btn = QPushButton("sign up")

        login_btn.clicked.connect(self._do_login)
        signup_btn.clicked.connect(self._do_signup)

        btns.addWidget(login_btn)
        btns.addWidget(signup_btn)
        layout.addLayout(btns)

        self.pw_input.returnPressed.connect(self._do_login)  # enter key login

    def _server(self):
        return self.server_input.text().strip().rstrip("/")

    def _json_err(self, r, fallback):
        try:
            return r.json().get("error", fallback)
        except Exception:
            return f"server error (HTTP {r.status_code}) is the server running?"

    def _do_signup(self):
        u = self.user_input.text().strip()
        p = self.pw_input.text()

        if not u or not p:
            self.status_lbl.setText("fill in all fields")
            return

        try:
            r = requests.post(
                f"{self._server()}/api/signup",
                json={"username": u, "password": p},
                timeout=5
            )
            if r.status_code == 200:
                self.status_lbl.setText("account created, logging in...")
                self._do_login()
            else:
                self.status_lbl.setText(self._json_err(r, "signup failed"))
        except requests.exceptions.ConnectionError:
            self.status_lbl.setText("cannot reach server check the URL")
        except Exception as e:
            self.status_lbl.setText(f"error: {e}")

    def _do_login(self):
        u = self.user_input.text().strip()
        p = self.pw_input.text()

        if not u or not p:
            self.status_lbl.setText("fill in all fields")
            return

        try:
            r = requests.post(
                f"{self._server()}/api/login",
                json={"username": u, "password": p},
                timeout=5
            )
            if r.status_code == 200:
                self.token = r.json()["token"]
                self.server_url = self._server()
                self.accept()
            else:
                self.status_lbl.setText(self._json_err(r, "login failed"))
        except requests.exceptions.ConnectionError:
            self.status_lbl.setText("cannot reach server check the URL")
        except Exception as e:
            self.status_lbl.setText(f"error: {e}")


# Remote Panel

class RemotePanel(QWidget):
    """
    tiny panel shown as an extra tab in monitor window
    shows live session stats from the server
    """
    _data_ready = pyqtSignal(dict)
    _error      = pyqtSignal()

    def __init__(self, server_url, token, session_id):
        super().__init__()
        self.server = server_url.rstrip("/")
        self.token = token
        self.session_id = session_id
        self._build()

        # signals connect bg thread → main thread safely
        self._data_ready.connect(self._update)
        self._error.connect(lambda: self.status_lbl.setText("status: unreachable"))

        self.poll_timer = QTimer(self)
        self.poll_timer.timeout.connect(self._poll)
        self.poll_timer.start(2000)

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        layout.setSpacing(10)

        layout.addWidget(QLabel("<b>Remote session</b>"))

        self.session_lbl = QLabel(f"session id: {self.session_id}")
        self.server_lbl  = QLabel(f"server: {self.server}")
        self.count_lbl   = QLabel("events pushed: 0")
        self.status_lbl  = QLabel("status: connecting")

        for lbl in [self.session_lbl, self.server_lbl, self.count_lbl, self.status_lbl]:
            layout.addWidget(lbl)

    def _poll(self):
        def _do():
            try:
                r = requests.get(
                    f"{self.server}/api/sessions/{self.session_id}",
                    headers={"Authorization": f"Bearer {self.token}"},
                    timeout=3,
                )
                if r.status_code == 200:
                    self._data_ready.emit(r.json())
                else:
                    self._error.emit()
            except:
                self._error.emit()

        threading.Thread(target=_do, daemon=True).start()

    def _update(self, s):
        alive = "alive" if s.get("alive") else "closed"
        self.count_lbl.setText(f"events pushed: {s.get('event_count', 0)}")
        self.status_lbl.setText(f"status: {alive}")


# Agent App

class AgentApp:
    def __init__(self, server_url, token, session_id): # agent and ui tg
        self.proc = ProcessUtil()
        self.all = []
        self.filtered = []
        self.monitor = None

        self.agent = Agent(server_url, token, session_id)
        self._session_id = session_id

        self.ui = ProcessListUI(self)
        self.ui.show()

        self.refresh()

        self.timer = QTimer()
        self.timer.timeout.connect(self.tick)
        self.timer.start(1000)

        self.trace_timer = QTimer()
        self.trace_timer.timeout.connect(self.poll_tracers)
        self.trace_timer.start(50)

        self.push_timer = QTimer()
        self.push_timer.timeout.connect(self.agent._flush_events_server)
        self.push_timer.start(200)

    def refresh(self):
        self.ui.set_status("loading processes")
        QApplication.processEvents()
        self.all = self.proc.get_all()
        self.apply_filter("")
        self.ui.set_status(f"{len(self.all)} processes | session: {self._session_id}")

    def apply_filter(self, qry):
        qry = qry.lower().strip()
        self.filtered = self.all if not qry else [p for p in self.all if self.proc.matches(p, qry)]
        self.ui.render(self.filtered)

    def tick(self):
        for p in self.filtered:
            try:
                p.mem = self.proc._get_mem_mb(psutil.Process(p.pid))
            except:
                pass
        self.ui.update_live(self.filtered, self.proc)

    def _monitor_closed(self):
        self.monitor = None

    def trace_selected(self):
        sel = self.ui.get_selected()
        if not sel:
            self.ui.set_status("nothing selected")
            return

        if self.monitor is None:
            self.monitor = MonitorWindow(on_close=self._monitor_closed)
            remote = RemotePanel(self.agent.server, self.agent.token, self._session_id)
            self.monitor.tabs.addTab(remote, "remote")
            self.monitor.show()

        for pid, name in sel:
            if pid in self.agent.tracers:
                continue
            self.agent.add_pid(pid)
            self.monitor.open_process((pid, name), self.agent.tracers[pid])

        self.ui.set_status(f"tracing {len(sel)} processes")

    def poll_tracers(self):
        evts = self.agent.drain()
        if self.monitor:
            for evt in evts:
                self.monitor.add_event(evt)

class ProcessListUI(QMainWindow):
    def __init__(self, app):
        super().__init__() # basic ui similar to the original nonagent ui
        self.app = app
        self.setWindowTitle("sysmon agent")
        self.resize(1000, 520)
        self._build()

    def _build(self):
        w = QWidget()
        self.setCentralWidget(w)

        root = QVBoxLayout(w)
        root.setSpacing(6)

        bar = QHBoxLayout()

        self.search = QLineEdit()
        self.search.setPlaceholderText("search pid / name / user")
        self.search.textChanged.connect(lambda t: self.app.apply_filter(t))

        refresh_btn = QPushButton("refresh")
        refresh_btn.clicked.connect(self.app.refresh)

        trace_btn = QPushButton("trace selected")
        trace_btn.clicked.connect(self.app.trace_selected)

        bar.addWidget(self.search)
        bar.addWidget(refresh_btn)
        bar.addWidget(trace_btn)
        root.addLayout(bar)

        self.table = QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels( # all columns
            ["", "PID", "name", "user", "status", "cpu %", "memory (MB)", "type"]
        )
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnWidth(0, 24)
        root.addWidget(self.table)

        self.status = QLabel("ready")
        root.addWidget(self.status)

    def render(self, procs):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)

        for p in procs: # update everything and also order them based mem usage
            r = self.table.rowCount()
            self.table.insertRow(r)

            icon_item = QTableWidgetItem()
            if p.icon:
                icon_item.setIcon(p.icon)

            self.table.setItem(r, 0, icon_item)
            self.table.setItem(r, 1, QTableWidgetItem(str(p.pid)))
            self.table.setItem(r, 2, QTableWidgetItem(p.name))
            self.table.setItem(r, 3, QTableWidgetItem(p.user or "NA"))
            self.table.setItem(r, 4, QTableWidgetItem(p.status or "NA"))

            cpu_item = QTableWidgetItem()
            cpu_item.setData(Qt.ItemDataRole.EditRole, 0.0)

            mem_item = QTableWidgetItem()
            mem_item.setData(Qt.ItemDataRole.EditRole, p.mem)

            type_item = QTableWidgetItem("service" if p.daemon else "process")

            self.table.setItem(r, 5, cpu_item)
            self.table.setItem(r, 6, mem_item)
            self.table.setItem(r, 7, type_item)

        self.table.setSortingEnabled(True)
        self.table.sortItems(6, Qt.SortOrder.DescendingOrder)

    def update_live(self, procs, util):
        self.table.setSortingEnabled(False)

        for r in range(self.table.rowCount()):
            try:
                pid = int(self.table.item(r, 1).text())
                for p in procs:
                    if p.pid == pid:
                        cpu = util.get_cpu_percent(pid)
                        self.table.item(r, 5).setData(Qt.ItemDataRole.EditRole, cpu)
                        self.table.item(r, 6).setData(Qt.ItemDataRole.EditRole, p.mem)
                        break
            except:
                pass

        self.table.setSortingEnabled(True)

    def get_selected(self):
        rows = set(i.row() for i in self.table.selectedItems())
        return [(int(self.table.item(r, 1).text()), self.table.item(r, 2).text()) for r in rows]

    def set_status(self, msg):
        self.status.setText(msg)


if __name__ == "__main__": # main app
    import socket
    app = QApplication(sys.argv)

    if os.path.exists("styles.css"):
        with open("styles.css") as f:
            app.setStyleSheet(f.read())

    login = LoginWindow()
    if login.exec() != QDialog.DialogCode.Accepted:
        sys.exit(0)

    try:
        r = requests.post( # start session after login
            f"{login.server_url}/api/sessions",
            headers={"Authorization": f"Bearer {login.token}"},
            json={"name": f"session from {socket.gethostname()}"},
            timeout=5,
        )
        session_id = r.json()["id"]
    except Exception as e:
        QMessageBox.critical(None, "error", f"could not create session:\n{e}")
        sys.exit(1)

    AgentApp(login.server_url, login.token, session_id)
    sys.exit(app.exec())