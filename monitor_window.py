from PyQt6.QtWidgets import *
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QTextCursor, QTextCharFormat, QColor
from datetime import datetime
import time

from sys_tracer import *
from syscall_helpers import syscall_category, SysType


"""
simple syscall monitor window using tabbed views for multi tracing but its lowk impossible rn again bc of lag TODO FIX LAG (drop more calls)!!!
-each tab represents a diff process
-supports category based filtering and the checkboxes are dynamically added based on the categorys TODO add customizable categories (u can make ur own)
-buffered log flushing to reduce ui lag by a lottttt
"""

colformat = { 
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

max_lines = 5000 # shouldnt lag too bad but ill probably add a widget to reduce this
push_interval = 200
"""
pushinterval=0.2 secs
60*0.2 = +- once every 12ish frames
"""

class MonitorWindow(QMainWindow):
    """
    window for displaying syscall activity

    -manages perprocess tracing sessions
    -renders syscall logs with cached category coloring [ doesnt completley crash my linux vm now :) ]
    -applies ui side filtering so u can still get back any logs u dont currently display
    TODO: i want to add writing to logs and make a chart allowing u to pick which categories go to which log itll be cool
    """

    def __init__(self, on_close=None):
        super().__init__()

        self.setWindowTitle("syscall monitor")
        self.resize(800, 500)
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self._on_close = on_close

        """
        sessions indexed by pid
         -log widget
         -category checkboxes
         -associated syscall tracer
         again this will be useful with multiple sessions in the future
        """
        self.sessions = {}

        self.setWindowFlags(
            Qt.WindowType.Window |
            Qt.WindowType.WindowMinimizeButtonHint |
            Qt.WindowType.WindowCloseButtonHint
        )

        """
        cache text formats per syscall category
        to minimize formatting each line from scratch
        """
        self._col_cache = {}
        for cat, col in colformat.items():
            c = QTextCharFormat()
            c.setForeground(QColor(col))
            self._col_cache[cat] = c

        # flush to ui once every push_interval frames
        self.flush_timer = QTimer(self)
        self.flush_timer.timeout.connect(self._flush_all)
        self.flush_timer.start(push_interval)

    def open_process(self, pidname, tracer):
        """
        open process tab and is called by main 
        main gives us the reference to the tracer we just save it to the dict and dynamically creat ethe checkboxes
        """
     
        pid, name = pidname
        if pid in self.sessions:
            return

        w = QWidget()
        root = QVBoxLayout(w)

        
        #category filter bar
        bar = QHBoxLayout()
        checks = {}

        for st in SysType: # go over each systype and add teh checkbox (for future allowing ppl to add their own categories)
            cb = QCheckBox(st.value)
            cb.setChecked(st != SysType.OTHER)
            cb._category = st
            cb.stateChanged.connect(self._on_filter_changed)

            checks[st] = cb
            bar.addWidget(cb)

        bar.addStretch()

        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(lambda: self._clear_log(pid))
        bar.addWidget(clear_btn)

        root.addLayout(bar)

        """
        syscall log view
        this uses manually adding to the buffer so we can push to the log
        in chunks is much more optimized
        """
     
        log = QPlainTextEdit()
        log.setReadOnly(True)

        log._buffer = []
        log._pending_lines = 0

        root.addWidget(log)

        self.tabs.addTab(w, f"{name} [{pid}]")
        self.sessions[pid] = { # save the session with the format from earlier
            "log": log,
            "checks": checks,
            "tracer": tracer,
        }

    def closeEvent(self, event):
        """
        stop all active tracers and clear sessions on window close
        """
        for session in self.sessions.values():
            tracer = session.get("tracer")
            if tracer:
                tracer.stop()

        self.sessions.clear()
        if self._on_close:
            self._on_close()
        event.accept()

    def _on_filter_changed(self, state):
        cb = self.sender()
        if not cb:
            return

        category = cb._category
        enabled = state == Qt.CheckState.Checked

      
        #apply updated category filter to all tracers
        for session in self.sessions.values():
            session["tracer"].set_filter(category.value, enabled)

    def add_event(self, evt: SysCall):
        """
        called by the tracer when it recieves an event
        we just push it to the buffer and the buffer gets pushed to the actual visual
        once every however many ms we set at the top 
        """
     
        pid = evt.pid
        if pid not in self.sessions:
            return

        session = self.sessions[pid]
        log = session["log"]
        checkboxes = session["checks"]

        category = syscall_category(evt.name)

        if category in checkboxes and not checkboxes[category].isChecked():
            return

        ts = datetime.fromtimestamp(evt.timestamp).strftime("%H:%M:%S.%f")[:-3]
        line = f"[{ts}] [{category.name}] {evt.name} ({evt.args})"

        log._buffer.append((line, category))

    def _flush_all(self): # push all da logs !!!!
        for session in self.sessions.values():
            self._flush_log(session["log"])

    def _flush_log(self, log: QPlainTextEdit):
        """ 
        read from the buffer
        add cached formatting from earlier
        push to ui
        """
     
        if not log._buffer:
            return

        sb = log.verticalScrollBar()
        at_bottom = (sb.value() == sb.maximum())

        cursor = log.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)

        for t, cat in log._buffer:
            c = self._col_cache.get(cat) 
            if c:
                cursor.insertText(t + "\n", c)
            else:
                cursor.insertText(t + "\n")

        log._pending_lines += len(log._buffer)
        log._buffer.clear()

        
        #apply maximum line count by taking off lines from the top (this wont be an issue cuz u get to save to logs in the future so its ok)
        l = log.blockCount()
        if l > max_lines:
            cursor = log.textCursor()
            cursor.movePosition(cursor.MoveOperation.Start)
            for i in range(l - max_lines):
                cursor.select(cursor.SelectionType.BlockUnderCursor)
                cursor.removeSelectedText()
                cursor.deleteChar()

        if at_bottom:
            sb.setValue(sb.maximum())

    def _clear_log(self, pid):
        if pid not in self.sessions:
            return
        log = self.sessions[pid]["log"]
        log.clear()
        log._buffer.clear()
