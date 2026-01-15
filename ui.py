import tkinter as tk
from tkinter import ttk
from typing import List, Dict

class MonUI:
    def __init__(self, r,c):
        self.root = r
        self.controller = c

        self.search_pointer = tk.StringVar()

        self.tree = None
        self.status_label = None
        self.count_label = None

        self.setup_window()
        self.create_widgets()

    def setup_window(self):
        self.root.title("syscall mon")
        self.root.geometry("600x400")

    def create_widgets(self):
        self.create_top_frame()
        self.create_process_tree()
        self.create_status_bar()

    def create_top_frame(self):
        top_frame = tk.Frame(self.root)
        top_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

        refresh_btn = tk.Button(
            top_frame,
            text="refresh",
            command=self.controller.refresh_processes,
            bg="#4CAF50",
            fg="white",
            font=("Arial", 10, "bold")
        )
        refresh_btn.pack(side=tk.LEFT, padx=5)

        monitor_btn = tk.Button(
            top_frame,
            text="monitor selected",
            command=self.controller.monitor_selected,
            bg="#2196F3",
            fg="white",
            font=("Arial", 10, "bold")
        )
        monitor_btn.pack(side=tk.LEFT, padx=5)

        tk.Label(top_frame, text="search:", font=("Arial", 10)).pack(side=tk.LEFT, padx=(20, 5))
        search_entry = tk.Entry(top_frame,textvariable=self.search_pointer,width=30)
        search_entry.pack(side=tk.LEFT)

        try:
            self.search_pointer.trace_add("write", self._on_search_text_changed)
        except: #older tkinter error (ai fix)
            self.search_pointer.trace("w", self._on_search_text_changed)

        self.count_label = tk.Label(top_frame, text="", font=("Arial", 10))
        self.count_label.pack(side=tk.RIGHT, padx=10)

    def _on_search_text_changed(self, *args):
        # just pass it to the controller
        self.controller.on_search_changed()

    def create_process_tree(self):
        tree_frame = tk.Frame(self.root)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")

        self.tree = ttk.Treeview(
            tree_frame,
            columns=("PID", "Name", "User", "Status", "Threads", "Memory", "CPU%"),
            show="headings",
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set
        )

        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)

        self.tree.heading("PID", text="PID")
        self.tree.heading("Name", text="process name")
        self.tree.heading("User", text="user")
        self.tree.heading("Status", text="status")
        self.tree.heading("Threads", text="threads")
        self.tree.heading("Memory", text="memory (MB)")
        self.tree.heading("CPU%", text="CPU %")

        self.tree.column("PID", width=80)
        self.tree.column("Name", width=250)
        self.tree.column("User", width=150)
        self.tree.column("Status", width=100)
        self.tree.column("Threads", width=80)
        self.tree.column("Memory", width=100)
        self.tree.column("CPU%", width=80)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self.controller.on_tree_select)

    def create_status_bar(self):
        self.status_label = tk.Label(
            self.root,
            text="Ready",
            bd=1,
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X)

    def clear_tree(self):
        if not self.tree:
            return

        items = self.tree.get_children()
        for item in items:
            self.tree.delete(item)

    def insert_process(self, process: Dict):
        if not self.tree:
            return

        pid = process.get("pid")
        name = process.get("name") or "NA"
        user = process.get("username") or "NA"
        status = process.get("status") or "NA"
        threads = process.get("num_threads", 0)
        mem = process.get("memory_mb", 0)
        cpu = process.get("cpu_percent", 0)

        self.tree.insert("", tk.END, values=(
            pid, name, user, status, threads, f"{mem:.2f}", f"{cpu:.1f}"))

    def get_selected_pids(self):
        if not self.tree:
            return []

        selected = self.tree.selection()
        out = []

        for item in selected:
            values = self.tree.item(item)["values"]#[pid, name, etc]
            out.append((values[0], values[1]))

        return out

    def update_status(self, message: str):
        if self.status_label:
            self.status_label.config(text=message)

    def update_count(self, s, t): #shown and total
        if not self.count_label:
            return
        if s==t:
            self.count_label.config(text=f"processes: {t}")
        else:
            self.count_label.config(text=f"showing: {s} / {t}")
