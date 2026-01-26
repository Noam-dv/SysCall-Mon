from PyQt6.QtWidgets import *
from PyQt6.QtCore import Qt
from datetime import datetime
import time

from sys_tracer import *
from syscall_helpers import syscall_category, SysType

#very simple monitor window with tabs
#todo : make selectable system call categorys to trace 
# also make tabs yelloow and red if anomolys detected  but thats much later

SYSCALL_COLORS = { #map colors
    SysType.FILE_IO: "#4fc3f7", #blue
    SysType.FS_META: "#64b5f6", #light blue
    SysType.PROCESS: "#ffb74d", #orange
    SysType.MEMORY: "#ba68c8", #purple
    SysType.IPC: "#aed581", #green
    SysType.NETWORK: "#81c784", #green darker
    SysType.EVENTS: "#90a4ae", #gray
    SysType.TIME: "#ffd54f", #yellow
    SysType.SECURITY: "#e57373", #red
    SysType.OTHER: "#b0bec5", #fallback gray
}

class MonitorWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("syscall monitor")
        self.resize(800, 500)
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        #pid: log, checkboxes, tracer
        self.sessions = {} #sessions of tracers

        self.setWindowFlags(
            Qt.WindowType.Window | Qt.WindowType.WindowMinimizeButtonHint | #no maxmimize button just to experiment
            Qt.WindowType.WindowCloseButtonHint
        )

    def open_process(self, pid, tracer):
        #dont open twice
        if pid in self.sessions:
            return

        w = QWidget()
        root = QVBoxLayout(w)

        #filter bar
        bar = QHBoxLayout()
        checks = {}

        for st in SysType:
            cb = QCheckBox(st.value)
            cb.setChecked(st != SysType.OTHER)

            #store category on the checkbox itself
            cb._category = st
            cb.stateChanged.connect(self._on_filter_changed)

            checks[st] = cb
            bar.addWidget(cb)

        bar.addStretch()
        root.addLayout(bar)

        #log view
        log = QTextEdit() #this lags like a mf 

        #potential fix for the lag with help from chatgpt
        log._buffer = []
        log._last_flush = time.time()

        log.setReadOnly(True)
        root.addWidget(log)

        self.tabs.addTab(w, f"PID {pid}")
        self.sessions[pid] = {
            "log": log,
            "checks": checks,
            "tracer": tracer,
        }

    def _on_filter_changed(self, state):
        #called when any checkbox changes
        cb = self.sender()
        if not cb:
            return

        category = cb._category
        enabled = state == Qt.CheckState.Checked

        #apply filter to all tracers
        for session in self.sessions.values():
            session["tracer"].set_filter(category.value, enabled)

    def add_event(self, evt: SysCall):
        pid = evt.pid
        if pid not in self.sessions: #only our pids
            return

        session = self.sessions[pid]
        log = session["log"]
        checkboxes = session["checks"]

        category = syscall_category(evt.name)

        #ui side checkbox filtering 
        if category in checkboxes and not checkboxes[category].isChecked():
            return

        ts = datetime.fromtimestamp(evt.timestamp).strftime("%H:%M:%S.%f")[:-3]
        color = SYSCALL_COLORS.get(category, "#b0bec5")

        line = ( #append the coloring format
            f'<span style="color:gray">[{ts}]</span> '
            f'<span style="color:{color}; font-weight:bold">'
            f'[{category.name}]</span> '
            f'<span style="color:white">{evt.name}</span>'
        )

        log._buffer.append(line)

        #push to ui max 10 times per second
        now = time.time()
        if now - log._last_flush < 0.1:
            return

        log._last_flush = now
        if log._buffer:
            log.insertHtml("<br>".join(log._buffer) + "<br>")
            log._buffer.clear()
            log.moveCursor(log.textCursor().MoveOperation.End)  #auto scroll
