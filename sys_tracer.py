import etw  # pywintrace
import psutil
from datetime import datetime
from PySide6.QtCore import QThread, Signal
from syslog import SysLog
from util import GeneralUtil


class SysTracer(QThread):
    new_event = Signal(object)  # emits SysLog
    def __init__(self, pids, parent=None):
        super().__init__(parent)
        self.pids = set(int(x) for x in pids)
        self._pid_to_name = {}
        self._running = False
        self.job = None

        for pid in self.pids:
            self._pid_to_name[pid] = self._safe_proc_name(pid)

    def _safe_proc_name(self, pid) -> str:
        try:
            return psutil.Process(pid).name()
        except Exception:
            return str(pid)

    def run(self):
        providers = [
            etw.ProviderInfo(
                "Microsoft-Windows-Kernel-Process",
                etw.GUID("{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}")
            ),
            etw.ProviderInfo(
                "Microsoft-Windows-Kernel-File",
                etw.GUID("{90CBDC39-4A3E-11D1-84F4-0000F80464E3}")
            ),
            etw.ProviderInfo(
                "Microsoft-Windows-Kernel-Registry",
                etw.GUID("{13735165-15D1-4691-995F-5582260655F5}")
            ),
        ]

        try:
            self.job = etw.ETW(providers=providers, event_callback=self._on_event)
        except Exception as e:
            GeneralUtil.log("ERROR", f"etw init failed: {e}")
            return

        self._running = True
        GeneralUtil.log("DEBUG", "etw session started")

        try:
            self.job.start()
        except Exception as e:
            GeneralUtil.log("ERROR", f"etw start failed: {e}")
            self._running = False
            return

        while self._running:
            self.msleep(100)

        try:
            if self.job:
                self.job.stop()
        except Exception:
            pass

        self.job = None
        GeneralUtil.log("DEBUG", "etw session stopped")

    def stop(self):
        self._running = False

    def _on_event(self, event):
        # event = (event_id, data_dict)
        try:
            _, data = event
        except Exception:
            return

        if not isinstance(data, dict):
            return

        header = data.get("EventHeader", {})
        pid = header.get("ProcessId", None)

        try:
            pid = int(pid)
        except Exception:
            return

        if pid not in self.pids:
            return

        if pid not in self._pid_to_name:
            self._pid_to_name[pid] = self._safe_proc_name(pid)

        proc_name = self._pid_to_name[pid]

        # syscall name
        syscall = (
            data.get("Task Name")
            or data.get("TaskName")
            or data.get("EventName")
            or data.get("Operation")
            or "SysCall"
        )

        # thread id
        tid = header.get("ThreadId", 0)
        try:
            tid = int(tid)
        except Exception:
            tid = 0

        # result
        result_code = data.get("Status") or data.get("NtStatus") or data.get("Result") or 0

        # target
        target = (
            data.get("FileName")
            or data.get("KeyName")
            or data.get("ValueName")
            or data.get("RelativeName")
        )

        args = {}
        if target:
            args["target"] = str(target)

        log = SysLog(
            timestamp=datetime.now(),
            pid=pid,
            process_name=proc_name,
            syscall=str(syscall),
            result=int(result_code, 16) if isinstance(result_code, str) and result_code.startswith("0x") else int(result_code),
            thread_id=tid,
            args=args if args else None,
            duration_us=None
        )

        # debug prints
        GeneralUtil.log("TRACE", f"{proc_name} [{pid}] {syscall}")

        self.new_event.emit(log)
