from PyQt6.QtWidgets import *
from PyQt6.QtCore import Qt
from datetime import datetime
from sys_tracer import * 
#very simple monitor window with tabs
#todo : make selectable system call categorys to trace 
# also make tabs yelloow and red if anomolys detected  but thats much later

class MonitorWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("syscall monitor")
        self.resize(800, 500)

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        #pid: log, checkboxes, tracer
        self.sessions = {} #sessions of tracers

    def open_process(self, pid, tracer):
        #dont open twice
        if pid in self.sessions:
            return
        w = QWidget()
        root = QVBoxLayout(w)

        #filter bar
        bar = QHBoxLayout()
        checks = {}

        for name in ["file", "net", "proc", "mem", "other"]:
            cb = QCheckBox(name)
            cb.setChecked(name != "other")
            #connect checkbox to tracer filter
            cb.stateChanged.connect(lambda s, n=name: tracer.set_filter(n, bool(s))) #triugger the filter in each tracer
            checks[name] = cb
            bar.addWidget(cb)
        bar.addStretch()
        root.addLayout(bar)

        #log view
        log = QTextEdit()
        log.setReadOnly(True)
        root.addWidget(log)

        self.tabs.addTab(w, f"PID {pid}")
        self.sessions[pid] = (log, checks, tracer)

    def add_event(self, evt: SysCall):
        pid = evt.pid
        if pid not in self.sessions:
            return

        log, checkboxes, tracer = self.sessions[pid]

        ts = datetime.fromtimestamp(evt.timestamp).strftime("%H:%M:%S.%f")[:-3]
        line = f"[{ts}] {evt.name}"
        log.append(line)
        log.moveCursor(log.textCursor().MoveOperation.End)  #auto scroll