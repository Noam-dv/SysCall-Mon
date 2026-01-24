import sys
from PySide6.QtWidgets import QApplication
from ui import MonUI
from proc_util import ProcessUtil
from monitor_window import MonitorWindow
from sys_tracer import SysTracer


class MonApp:
    def __init__(self, app):
        self.app = app
        self.app.aboutToQuit.connect(self.cleanup)

        self.util = ProcessUtil()
        self.all_procs = []
        self.filtered = []

        self.ui = MonUI(self)
        self.ui.show()

        self.monitor_window = None
        self.sys_tracer = None

        self.refresh_processes()

    def cleanup(self):
        if self.sys_tracer:
            self.sys_tracer.stop()
            self.sys_tracer.wait()
            self.sys_tracer = None

    def refresh_processes(self):
        self.ui.update_status("loading processes...")

        self.all_procs = self.util.get_all_procs()
        self.all_procs.sort(key=lambda p: p.data.get("pid", 0))
        self.apply_filter()

        self.ui.update_status("ready")

    def apply_filter(self):
        search_text = self.ui.search_entry.text()
        self.filtered = self.util.filter_processes(self.all_procs, search_text)

        self.ui.clear_tree()
        for proc in self.filtered:
            self.ui.insert_process(proc.data)

        self.ui.update_count(len(self.filtered), len(self.all_procs))

    def on_search_changed(self):
        self.apply_filter()

    def on_tree_select(self, _):
        selected = self.ui.get_selected_pids()
        if selected:
            pid, name = selected[0]
            self.ui.update_status(f"selected: {name} (PID {pid})")

    def monitor_selected(self):
        selected = self.ui.get_selected_pids()
        if not selected:
            self.ui.update_status("no process selected")
            return

        text = ", ".join([f"{n} [{p}]" for p, n in selected])
        self.ui.update_status(f"monitoring: {text}")
        print("monitoring:", selected, flush=True)

        pids = [int(p) for p, _ in selected]

        # close old tracer
        if self.sys_tracer:
            self.sys_tracer.stop()
            self.sys_tracer.wait()
            self.sys_tracer = None

        # new window
        self.monitor_window = MonitorWindow(selected)
        self.monitor_window.setWindowTitle(f"Monitoring: {text}")
        self.monitor_window.show()

        # start tracer
        self.sys_tracer = SysTracer(pids)
        self.sys_tracer.new_event.connect(self.monitor_window.add_log)
        self.sys_tracer.start()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    MonApp(app)
    sys.exit(app.exec())
