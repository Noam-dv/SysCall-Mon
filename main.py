import tkinter as tk
from ui import MonUI
from proc_util import ProcessUtil

class MonApp:
    def __init__(self, root):
        self.root = root
        self.util = ProcessUtil()
        self.all_procs = []
        self.filtered = []
        self.ui = None
        self.start()

    def start(self):
        self.ui = MonUI(self.root, self)
        self.refresh_processes()

    def refresh_processes(self):
        self.ui.update_status("loading processes...")
        self.root.update()

        self.all_procs = self.util.get_all_procs()
        self.all_procs.sort(key=lambda p: p.data.get('pid', 0))
        self.apply_filter()

        self.ui.update_status("ready")

    def apply_filter(self):
        search_text = self.ui.search_pointer.get()
        self.filtered = self.util.filter_processes(self.all_procs, search_text)

        self.ui.clear_tree()
        for proc in self.filtered:
            self.ui.insert_process(proc.data)

        self.ui.update_count(len(self.filtered), len(self.all_procs))

    def on_search_changed(self, *args):
        self.apply_filter()

    def on_tree_select(self, event):
        selected = self.ui.get_selected_pids()
        if selected:
            i, n = selected[0] #name and pid
            self.ui.update_status(f"selected: {n} (PID {i})")

    def monitor_selected(self):
        selected = self.ui.get_selected_pids()
        if not selected:
            self.ui.update_status("no process selected")
            return

        text = ", ".join([f"{n} [{p}]" for p, n in selected])
        self.ui.update_status(f"monitoring: {text}")
        print("monitoring:", selected)  # monitoring has to be implemeneted ------------------------

def main():
    root = tk.Tk()
    app = MonApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()