import sys
from PySide6.QtWidgets import QApplication
from ui import MonUI
from proc_util import ProcessUtil

class MonApp: 
    # entry
    def __init__(self):
        self.util = ProcessUtil()
        self.all_procs = []
        self.filtered = []

        self.ui = MonUI(self)
        self.ui.show()

        self.refresh_processes()

    def refresh_processes(self): # reloads procs from procutil (freezes window for short period of time, will be fixed)
        self.ui.update_status("loading processes...")

        self.all_procs = self.util.get_all_procs()
        self.all_procs.sort(key=lambda p: p.data.get("pid", 0))
        self.apply_filter()

        self.ui.update_status("ready")
 
    def apply_filter(self): # search filter
        search_text = self.ui.search_entry.text()
        self.filtered = self.util.filter_processes(self.all_procs, search_text)

        self.ui.clear_tree()
        for proc in self.filtered:
            self.ui.insert_process(proc.data)

        self.ui.update_count(len(self.filtered), len(self.all_procs))

    def on_search_changed(self): # callback
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
        print("monitoring:", selected)  # hook etw here soon
        #monitoring logic will be added next commit


if __name__ == "__main__":
    app = QApplication(sys.argv)
    MonApp()
    sys.exit(app.exec())