from PyQt6.QtWidgets import *
from PyQt6.QtCore import Qt, QTimer
from datetime import datetime
import time

from sys_tracer import *
from syscall_helpers import syscall_category, SysType

#very simple monitor window with tabs
#todo : make selectable system call categorys to trace 
# also make tabs yelloow and red if anomolys detected  but thats much later
 
SYSCALL_COLORS = { #map colors 
    #unused rn cuz we wanna prevent lag but i want to implement this
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

MAX_LINES = 5000 #hard cap log to prevent crashes
FLUSH_INTERVAL_MS = 200 #ui push rate 
#200ms = 0.2s
#30*0.2 = 6
#once every 6 ish frames

class MonitorWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("syscall monitor")
        self.resize(800, 500)
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        #pid: log, checkboxes, tracer
        self.sessions = {} #sessions of tracers
        #multi pid tracking is implemented
        #but i disabled it on the ui end because it currently lags too much


        self.setWindowFlags(
            Qt.WindowType.Window |
            Qt.WindowType.WindowMinimizeButtonHint | #no maxmimize button just to experiment
            Qt.WindowType.WindowCloseButtonHint
        )

        # global ui flush timer
        self.flush_timer = QTimer(self)
        self.flush_timer.timeout.connect(self._flush_all)
        self.flush_timer.start(FLUSH_INTERVAL_MS)

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

        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(lambda: self._clear_log(pid))
        bar.addWidget(clear_btn)

        root.addLayout(bar)

        #log view
        log = QPlainTextEdit() #this lags like a mf 
        log.setReadOnly(True)

        #potential fix for the lag with help from chatgpt
        log._buffer = []
        log._pending_lines = 0

        root.addWidget(log)

        self.tabs.addTab(w, f"PID {pid}")
        self.sessions[pid] = {
            "log": log,
            "checks": checks,
            "tracer": tracer,
        }

    def closeEvent(self, event):
        #when monitor window closes
        #stop all syscall tracers
        for pid, session in self.sessions.items():
            tracer = session.get("tracer")
            if tracer:
                tracer.stop()

        self.sessions.clear()
        event.accept()

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

        # plain text line (color handled by simplicity + speed)
        line = f"[{ts}] [{category.name}] {evt.name} ({evt.args})"

        log._buffer.append(line)

    def _flush_all(self):
        for session in self.sessions.values():
            self._flush_log(session["log"])

    def _flush_log(self, log: QPlainTextEdit):
        if not log._buffer:
            return

        log.appendPlainText("\n".join(log._buffer))
        log._pending_lines += len(log._buffer)
        log._buffer.clear()

       
        if log.blockCount() > MAX_LINES: #delete from the top when exceeding limit
            cursor = log.textCursor()
            cursor.movePosition(cursor.MoveOperation.Start)
            for i in range(log.blockCount() - MAX_LINES):
                cursor.select(cursor.SelectionType.BlockUnderCursor)
                cursor.removeSelectedText()
                cursor.deleteChar()
        log.moveCursor(log.textCursor().MoveOperation.End)

    def _clear_log(self, pid):
        if pid not in self.sessions:
            return
        log = self.sessions[pid]["log"]
        log.clear()
        log._buffer.clear()#clear buffer to reset next logs