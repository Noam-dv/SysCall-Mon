import sys, os
os.environ["QT_QPA_PLATFORM"] = "xcb"
from PyQt6.QtWidgets import *
from PyQt6.QtCore import Qt, QTimer
from proc_util import ProcessUtil
import psutil

from sys_tracer import SysTracer
from monitor_window import MonitorWindow


class MonApp:
    """main app class holding ui and session logic"""
    def __init__(self):
        self.proc = ProcessUtil()

        self.all = []
        self.filtered = []

        self.ui = MonUI(self)
        self.ui.show()

        """monitor window for syscall tracers"""
        self.monitor = None

        self.tracers = {} #pid: systracer
        self.refresh()

        """
        timers:
        -update memory on the ui
        -poll syscall tracer queues to prevent an overflow
        """
        self.timer = QTimer()
        self.timer.timeout.connect(self.tick)
        self.timer.start(1000)

        self.trace_timer = QTimer()
        self.trace_timer.timeout.connect(self.poll_tracers)
        self.trace_timer.start(50)

    def refresh(self):
        self.ui.set_status("loading processes")
        QApplication.processEvents()

        self.all = self.proc.get_all()
        self.apply_filter("")

        self.ui.set_status(f"{len(self.all)} processes")

    def apply_filter(self, qry):
        qry = qry.lower().strip() #simple filtering

        if not qry:
            self.filtered = self.all
        else:
            self.filtered = []
            for p in self.all:
                if self.proc.matches(p, qry):
                    self.filtered.append(p)

        self.ui.render(self.filtered)

    def tick(self):
        """update cpu and memory usage for displayed processes"""
        for p in self.filtered:
            try:
                proc = psutil.Process(p.pid)
                p.mem = self.proc._get_mem_mb(proc) 
            except:
                pass

        self.ui.update_live(self.filtered, self.proc)

    def _monitor_closed(self): #just a little event, dont know how else i couldve done it lol
        self.monitor = None
        
    def trace_selected(self):
        """loop over selected processes (i only allow 1 rn cuz of lag) and open a session for them"""
        sel = self.ui.get_selected()
        if not sel:
            self.ui.set_status("nothing selected")
            return

        if self.monitor is None:
            self.monitor = MonitorWindow(on_close=self._monitor_closed) #open window with the event callback
            self.monitor.show()

        for pid, name in sel:
            if pid in self.tracers:
                continue

            tracer = SysTracer(pid) #init ebpf tracer
            tracer.start()

            self.tracers[pid] = tracer
            self.monitor.open_process((pid, name), tracer) #load tracer into a new tab on the window

        self.ui.set_status(f"will trace {len(sel)} processes")

    def poll_tracers(self):
        """
        poll syscall tracer queues with a bounded per-tick limit
        to prevent ui stalling for long
        """
        m = 50

        for pid, tracer in self.tracers.items():
            for i in range(m):
                try:
                    evt = tracer.events.get_nowait()
                    self.monitor.add_event(evt) 
                except:
                    break


class MonUI(QMainWindow):
    """ui clutter is stuck here (main window)"""
    def __init__(self, app):
        super().__init__()
        self.app = app

        self.setWindowTitle("sysmon")
        self.resize(1000, 520)
        self._build()

    def _build(self):
        """buidld all the widgets, not too much to doc here"""
        w = QWidget()
        self.setCentralWidget(w)

        root = QVBoxLayout(w)
        root.setSpacing(6)

        bar = QHBoxLayout()

        self.search = QLineEdit()
        self.search.setPlaceholderText("search pid / name / user")
        self.search.textChanged.connect(
            lambda t: self.app.apply_filter(t)
        )
        
        refresh_btn = QPushButton("refresh")
        refresh_btn.clicked.connect(self.app.refresh)
        trace_btn = QPushButton("trace selected")
        trace_btn.clicked.connect(self.app.trace_selected)

        bar.addWidget(self.search)
        bar.addWidget(refresh_btn)
        bar.addWidget(trace_btn)

        root.addLayout(bar)

        self.table = QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels([
            "", "PID", "name", "user", "status", "cpu %", "memory (MB)", "type"
        ])
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
        """rebuild process table from scratch for refreshing"""
        self.table.setSortingEnabled(False)

        self.table.setRowCount(0)
        for p in procs:
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

            d = "service"
            if not p.daemon: # categorize daemons (not spot on accuracy tho)
                d = "process"
            type_item = QTableWidgetItem(d)

            self.table.setItem(r, 5, cpu_item)
            self.table.setItem(r, 6, mem_item)
            self.table.setItem(r, 7, type_item)

        self.table.setSortingEnabled(True)
        self.table.sortItems(6, Qt.SortOrder.DescendingOrder)

    def update_live(self, procs, util):
        """update cpu and memory values without rebuilding the entire table"""
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
        rows = []
        for i in self.table.selectedItems():
            rows.append(i.row())
        rows = set(rows)
        o = []
        for r in rows:
            pid = int(self.table.item(r, 1).text())
            name = self.table.item(r, 2).text()
            o.append((pid, name))
        return o

    def set_status(self, msg):
        self.status.setText(msg)


if __name__ == "__main__":
    app = QApplication(sys.argv)

    if os.path.exists("styles.css"):
        with open("styles.css") as f:
            app.setStyleSheet(f.read())

    MonApp()
    sys.exit(app.exec())
