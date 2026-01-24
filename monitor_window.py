from PySide6.QtWidgets import (
    QMainWindow, QTabWidget, QWidget,
    QVBoxLayout, QListWidget, QListWidgetItem
)
from syslog import SysLog


class MonitorWindow(QMainWindow):
    def __init__(self, processes):
        super().__init__()
        self.processes = processes  #(pid,name) 
        self.setWindowTitle("syscall behavior Monitor")
        self.resize(900, 500)

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.per_pid_logs = {}

        self._create_all_tab()
        self._create_process_tabs()

        with open("styles.css") as f:
            self.setStyleSheet(f.read())

    def _create_all_tab(self):
        self.all_logs = QListWidget()
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.addWidget(self.all_logs)
        self.tabs.addTab(w, "ALL")

    def _create_process_tabs(self):
        for pid, name in self.processes:
            lw = QListWidget()
            self.per_pid_logs[int(pid)] = lw
            w = QWidget()
            layout = QVBoxLayout(w)
            layout.addWidget(lw)
            self.tabs.addTab(w, f"{name} [{pid}]")

    def add_log(self, log):
        # supports SysLog or dict
        if isinstance(log, dict):
            log = SysLog(
                timestamp=log["timestamp"],
                pid=log["pid"],
                process_name=log["process_name"],
                syscall=log["syscall"],
                result=log["result"],
                thread_id=log.get("thread_id"),
                args={"target": log.get("target")} if log.get("target") else None,
                duration_us=log.get("duration_us")
            )

        ts = log.timestamp.strftime("%H:%M:%S.%f")[:-3]
        op = log.syscall
        target = log.args.get("target") if log.args else None

        text = f"{ts}  {log.process_name} (PID {log.pid})  {op}"
        if target:
            text += f"  {target}"
        if log.result:
            text += f"  (result=0x{log.result:08X})"

        item = QListWidgetItem(text)

        self.all_logs.addItem(item)
        self.all_logs.scrollToBottom()

        lw = self.per_pid_logs.get(int(log.pid))
        if lw:
            lw.addItem(item.clone())
            lw.scrollToBottom()
