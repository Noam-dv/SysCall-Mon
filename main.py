import sys, os
os.environ["QT_QPA_PLATFORM"] = "xcb" #idk why ths fixes the border buttons not working
from PyQt6.QtWidgets import *
from PyQt6.QtCore import Qt, QTimer
from proc_util import ProcessUtil
import psutil

from sys_tracer import SysTracer
from monitor_window import MonitorWindow


class MonApp:
    def __init__(self):
        self.proc = ProcessUtil()

        self.all = []
        self.filtered = []

        self.ui = MonUI(self)
        self.ui.show()

        #monitor window for syscall tracers
        self.monitor = None

        self.tracers = {} #pid: systracer
        self.refresh()

        #timer to update mem usage every second
        self.timer = QTimer()
        self.timer.timeout.connect(self.tick)
        self.timer.start(1000)

        #timer to get syscall tracer queues next to not have overflow
        self.trace_timer = QTimer()
        self.trace_timer.timeout.connect(self.poll_tracers)
        self.trace_timer.start(50) #not toooo fast

    def refresh(self):
        self.ui.set_status("loading processes")
        QApplication.processEvents()

        self.all = self.proc.get_all()
        self.apply_filter("")

        self.ui.set_status(f"{len(self.all)} processes")

    def apply_filter(self, qry):
        qry=qry.lower().strip() #normalize filter

        if not qry:
            self.filtered = self.all
        else:
            self.filtered = []
            for p in self.all: #allow searching by pid or name
                if self.proc.matches(p, qry):
                    self.filtered.append(p)

        self.ui.render(self.filtered)

    def tick(self):
        #update memory and cpu
        for p in self.filtered:
            try:
                proc = psutil.Process(p.pid)
                p.mem = self.proc._get_mem_mb(proc)
            except:
                pass

        self.ui.update_live(self.filtered, self.proc)

    def trace_selected(self):
        sel = self.ui.get_selected()
        if not sel:
            self.ui.set_status("nothing selected")
            return

        if self.monitor is None: #move here so monitor window
        #only opens when we start tracing

            self.monitor = MonitorWindow()
            self.monitor.show()

        for pid, name in sel:
            if pid in self.tracers:
                continue  #already tracing

            tracer = SysTracer(pid)
            tracer.start()

            self.tracers[pid] = tracer
            self.monitor.open_process(pid, tracer)

        self.ui.set_status(f"will trace {len(sel)} processes")

    def poll_tracers(self):
        #fixxed poll
        #dont poll ALLLLLL 
        #do only 50 max  in one ui tick
        m = 50 #modify as u wish, risky tho

        for pid, tracer in self.tracers.items():
            for i in range(m): #max events per tick
                try:
                    evt = tracer.events.get_nowait()
                    self.monitor.add_event(evt)
                except:
                    break

#small ui class (messy js for testing for now)
#will clean up later
class MonUI(QMainWindow): 
    def __init__(self, app):
        super().__init__()
        self.app = app

        #main window setup
        self.setWindowTitle("sysmon")
        self.resize(1000, 520)
        self._build()

    def _build(self):
        w = QWidget()
        self.setCentralWidget(w)

        root = QVBoxLayout(w)
        root.setSpacing(6)
        #topbar
        bar = QHBoxLayout()

        self.search = QLineEdit()
        self.search.setPlaceholderText("search pid / name / user")
        self.search.textChanged.connect(
            lambda t: self.app.apply_filter(t)
        )#connect seafch filter to apply filter when text changed
        
        #buttons setup
        refresh_btn = QPushButton("refresh")
        refresh_btn.clicked.connect(self.app.refresh)
        trace_btn = QPushButton("trace selected")
        trace_btn.clicked.connect(self.app.trace_selected)

        #build all widgets
        bar.addWidget(self.search)
        bar.addWidget(refresh_btn)
        bar.addWidget(trace_btn)

        root.addLayout(bar)

        #table
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels([
            "", "PID", "name", "user", "status", "cpu %", "memory (MB)" #first one is icon
        ])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnWidth(0, 24) #smaller column for icons

        root.addWidget(self.table)

        self.status = QLabel("ready")
        root.addWidget(self.status)

    def render(self, procs): #draw items
        self.table.setSortingEnabled(False) #turn off sorting while populating the table
        #not sure why sorting breaks it ?

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

            self.table.setItem(r, 5, cpu_item)
            self.table.setItem(r, 6, mem_item)

        self.table.setSortingEnabled(True) #add sorting click once for ascending twice for descending thanks qt :)
        self.table.sortItems(6, Qt.SortOrder.DescendingOrder) #sort by memory

    def update_live(self, procs, util):
        #update cpu and mem 
        #without rebuilding table
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
        rows=[] #small list then turn to set to remove dupes
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

    if os.path.exists("styles.css"):#small check cuz moving between linux and windows kept crashing
        with open("styles.css") as f: #basic AI styling
            app.setStyleSheet(f.read())

    MonApp()
    sys.exit(app.exec())
