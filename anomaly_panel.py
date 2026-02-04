from PyQt6.QtWidgets import *
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor
from datetime import datetime
from collections import deque
from anomaly_detector import Anomaly


class AnomalyPanel(QWidget):
    """
    panel for displaying anomalies
    color coded by severity

    red - high 
    orange - medium
    yellow - low
    """

    def __init__(self):
        super().__init__()

        self.anomalies = deque(maxlen=500) #save history for stats
        self.max_rows = 100 #limit cuz lag

        self.high = 0 #counters for stats
        self.med = 0
        self.low = 0

        self._build_ui()

        """
        timer only updates stats text
        table updates happen on insert
        """
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self._update_stats)
        self.refresh_timer.start(1000)

        #cache colors js to not create a million qcolor objs
        self._col_chache = { 
            "high": QColor(229, 115, 115),
            "med": QColor(255, 183, 77),
            "low":QColor(255, 213, 79)
        }
    def _build_ui(self):
        # main layout
        layout = QVBoxLayout(self)
        layout.setSpacing(6)

        # header bar
        header = QHBoxLayout()
        title = QLabel("<b>Anomaly Detector</b>") #bold 
        header.addWidget(title)
        header.addStretch()

        # sensitivity control
        header.addWidget(QLabel("sensitivity:"))

        self.sensitivity_slider = QSlider(Qt.Orientation.Horizontal)
        self.sensitivity_slider.setMinimum(5)    # 0.5x
        self.sensitivity_slider.setMaximum(20)   # 2.0x
        self.sensitivity_slider.setValue(10)     # 1.0x
        self.sensitivity_slider.setMaximumWidth(100)
        self.sensitivity_slider.valueChanged.connect(self.update_sensitivity_label)

        self.sensitivity_label = QLabel("1.0x")

        header.addWidget(self.sensitivity_slider)
        header.addWidget(self.sensitivity_label)

        #clear anomalys
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.clear_anomalies)
        header.addWidget(clear_btn)

        layout.addLayout(header)

        #anomaly table
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels([
            "Time", "PID", "type", "severity", "description", "details"
        ])

        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSortingEnabled(False) #sorting off cuz lag
        self.table.setAlternatingRowColors(False)

        #fixed widths
        self.table.setColumnWidth(0, 90)
        self.table.setColumnWidth(1, 60)
        self.table.setColumnWidth(2, 100)
        self.table.setColumnWidth(3, 80)
        self.table.horizontalHeader().setStretchLastSection(True)

        layout.addWidget(self.table)

        # stats footer
        self.stats_label = QLabel("No anomalies detected")
        layout.addWidget(self.stats_label)

    def add_anomaly(self, anomaly: Anomaly):
        self.anomalies.append(anomaly) #store for stats

        #update counters once
        if anomaly.severity >= 0.7:
            self.high += 1
        elif anomaly.severity >= 0.4:
            self.med += 1
        else:
            self.low += 1

        #update table
        self._append_row(anomaly)

    def _append_row(self, anomaly: Anomaly):
        """
        insert new anomaly at top
        block updates to avoid layout spam
        """
        self.table.setUpdatesEnabled(False)

        if self.table.rowCount() >= self.max_rows:
            self.table.removeRow(self.table.rowCount() - 1)

        self.table.insertRow(0)

        # time
        ts = datetime.fromtimestamp(anomaly.timestamp).strftime("%H:%M:%S")
        self.table.setItem(0, 0, QTableWidgetItem(ts))

        self.table.setItem(0, 1, QTableWidgetItem(str(anomaly.pid))) #pid
        self.table.setItem(0, 2, QTableWidgetItem(anomaly.anomaly_type))#type

        #severity
        sev_pct = int(anomaly.severity * 100)
        sev_item = QTableWidgetItem(f"{sev_pct}%")
        if anomaly.severity >= 0.7: #format colors from the cache like in tracer view
            sev_item.setBackground(self._col_chache["high"])
        elif anomaly.severity >= 0.4:
            sev_item.setBackground(self._col_chache["med"])
        else:
            sev_item.setBackground(self._col_chache["low"])

        self.table.setItem(0, 3, sev_item)

        # desc
        self.table.setItem(0, 4, QTableWidgetItem(anomaly.description))

        details="" #get details from anomaly
        for k,v in anomaly.details.items():
            details += f" | {k}={v}"

        self.table.setItem(0, 5, QTableWidgetItem(details[:100]))
        self.table.setUpdatesEnabled(True)

    def _update_stats(self):
        #stats are cheap now
        if not self.anomalies:
            self.stats_label.setText("No anomalies detected")
            return

        self.stats_label.setText(
            f"total: {len(self.anomalies)} | "
            f"high: {self.high} | medium: {self.med} | low: {self.low}"
        )

    def clear_anomalies(self):
        #reset everything
        self.anomalies.clear()
        self.high = self.med = self.low = 0
        self.table.setRowCount(0)
        self.stats_label.setText("No anomalies detected")

    def get_sensitivity(self) -> float:
        return self.sensitivity_slider.value() / 10.0

    def update_sensitivity_label(self):
        self.sensitivity_label.setText(f"{self.get_sensitivity():.1f}x")