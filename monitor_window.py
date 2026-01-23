from PySide6.QtWidgets import (
    QMainWindow, QTabWidget, QWidget,
    QVBoxLayout, QTableWidget, QTableWidgetItem
)
from PySide6.QtCore import Qt


class MonitorWindow(QMainWindow):
    def __init__(self, processes):
        super().__init__()
        self.processes = processes  #(pid,name) 
        self.setWindowTitle("syscall behavior Monitor")
        self.resize(900, 500)

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self._create_all_tab()
        self._create_process_tabs()
        with open("styles.css") as f:
            self.setStyleSheet(f.read())

    def _create_all_tab(self):
        self.tabs.addTab(self._make_table_tab(), "ALL")

    def _create_process_tabs(self):
        for pid, name in self.processes:
            label = f"{name} [{pid}]"
            self.tabs.addTab(self._make_table_tab(), label)

    def _make_table_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)

        table = QTableWidget(0, 6)
        table.setHorizontalHeaderLabels([
            "time", "PID", "thread",
            "Syscall", "result", "time (microsec)"
        ])
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.verticalHeader().setVisible(False)
        table.setSelectionBehavior(QTableWidget.SelectRows)

        layout.addWidget(table)
        return w
