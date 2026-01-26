import sys, os
from PyQt6.QtWidgets import *
from PyQt6.QtCore import Qt, QTimer
from proc_util import ProcessUtil


class MonApp:
    def __init__(self):
        self.proc = ProcessUtil()

        self.all = []
        self.filtered = []

        self.ui = MonUI(self)
        self.ui.show()

        self.refresh()

        #timer to update mem usage every second
        self.timer = QTimer()
        self.timer.timeout.connect(self.tick)
        self.timer.start(1000)

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
        #update memory + cpu live (no full refresh)
        self.ui.update_live(self.filtered, self.proc)

    def trace_selected(self):
        sel = self.ui.get_selected()
        if not sel:
            self.ui.set_status("nothing selected")
            return
        #small print for syscall tracer later
        print("TRACE:", sel)
        self.ui.set_status(f"will trace {len(sel)} processes")


#small ui class (messy js for testing for now)
#will clean up later
class MonUI(QMainWindow): 
    def __init__(self, app):
        super().__init__()
        self.app = app

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
            self.table.setItem(r, 5, QTableWidgetItem("0.0"))
            self.table.setItem(r, 6, QTableWidgetItem(f"{p.mem:.1f}"))

        self.table.setSortingEnabled(True) #add sorting click once for ascending twice for descending thanks qt :)
        self.table.sortItems(6, Qt.SortOrder.DescendingOrder) #sort by memory
        
    def update_live(self, procs, util):
        #update cpu + mem only (no table rebuild)
        for r in range(self.table.rowCount()):
            try:
                pid = int(self.table.item(r, 1).text())
                for p in procs:
                    if p.pid == pid:
                        cpu = util.get_cpu_percent(pid)
                        self.table.item(r, 5).setText(f"{cpu:.1f}")
                        self.table.item(r, 6).setText(f"{p.mem:.1f}")
                        break
            except:
                pass

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