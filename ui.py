from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit,
    QTableWidget, QTableWidgetItem,
    QAbstractItemView, QHeaderView
)
from PySide6.QtCore import Qt


class MonUI(QWidget):
    def __init__(self, controller):
        super().__init__()
        self.controller = controller

        self.tree = None
        self.status_label = None
        self.count_label = None
        self.search_entry = None

        self._style()
        self.setup_window()
        self.create_widgets()

    def _style(self):
        style = ""
        with open("styles.css", 'r') as f:
            style = f.read()

        self.setStyleSheet(style)

    def setup_window(self):
        self.setWindowTitle("syscall mon")
        self.resize(700, 420)

    def create_widgets(self):
        root = QVBoxLayout(self)
        root.setSpacing(8)
        root.setContentsMargins(10, 10, 10, 10)

        # top bar
        top = QHBoxLayout()
        top.setSpacing(6)

        refresh_btn = QPushButton("refresh")
        refresh_btn.clicked.connect(self.controller.refresh_processes)
        top.addWidget(refresh_btn)

        monitor_btn = QPushButton("monitor selected")
        monitor_btn.clicked.connect(self.controller.monitor_selected)
        top.addWidget(monitor_btn)

        top.addSpacing(16)

        top.addWidget(QLabel("search"))
        self.search_entry = QLineEdit()
        self.search_entry.textChanged.connect(self._on_search_text_changed)
        top.addWidget(self.search_entry)

        top.addStretch()

        self.count_label = QLabel("")
        top.addWidget(self.count_label)

        root.addLayout(top)

        # table
        self.tree = QTableWidget(0, 7)
        self.tree.setHorizontalHeaderLabels([
            "PID", "Name", "User", "Status",
            "Threads", "Memory", "CPU"
        ])

        self.tree.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tree.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tree.setAlternatingRowColors(True)
        self.tree.verticalHeader().setVisible(False)
        self.tree.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        self.tree.itemSelectionChanged.connect(
            lambda: self.controller.on_tree_select(None)
        )

        root.addWidget(self.tree)

        # status bar
        self.status_label = QLabel("Ready")
        self.status_label.setAlignment(Qt.AlignLeft)
        self.status_label.setStyleSheet("padding-top: 4px;")
        root.addWidget(self.status_label)

    def _on_search_text_changed(self):
        self.controller.on_search_changed()

    def clear_tree(self):
        self.tree.setRowCount(0)

    def insert_process(self, process):
        row = self.tree.rowCount()
        self.tree.insertRow(row)

        vals = [
            process.get("pid"),
            process.get("name") or "NA",
            process.get("username") or "NA",
            process.get("status") or "NA",
            process.get("num_threads", 0),
            f"{process.get('memory_mb', 0):.2f}",
            f"{process.get('cpu_percent', 0):.1f}",
        ]

        for col, v in enumerate(vals):
            self.tree.setItem(row, col, QTableWidgetItem(str(v)))

    def get_selected_pids(self):
        rows = set(i.row() for i in self.tree.selectedItems())
        out = []

        for r in rows:
            pid = int(self.tree.item(r, 0).text())
            name = self.tree.item(r, 1).text()
            out.append((pid, name))

        return out

    def update_status(self, msg):
        self.status_label.setText(msg)

    def update_count(self, s, t):
        if s == t:
            self.count_label.setText(f"processes: {t}")
        else:
            self.count_label.setText(f"showing: {s} / {t}")
