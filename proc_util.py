import psutil
import time
from dataclasses import dataclass
from typing import Optional, Any


@dataclass
class ProcessData:
    """
    Represents a single process (no GUI dependencies).
    """
    pid: int
    name: str
    mem: float
    user: Optional[str] = None
    status: Optional[str] = None
    daemon: bool = False


class ProcessUtil:
    def __init__(self):
        # pid -> (cpu_time, timestamp)
        self._last_cpu_check: dict[int, tuple[float, float]] = {}

    def get_all(self) -> list[ProcessData]:
        """Get all running processes."""
        out: list[ProcessData] = []
        for p in psutil.process_iter(["pid", "name", "username", "status"]):
            try:
                pid = p.pid
                name = p.info.get("name") or "???"
                user = p.info.get("username")
                status = p.info.get("status")
                mem = self._get_mem_mb(p)
                daemon = self._daemon_check(p)
                out.append(ProcessData(pid, name, mem, user, status, daemon))
            except Exception:
                # Process died or access denied
                continue
        out.sort(key=lambda x: x.pid)
        return out

    def _get_mem_mb(self, p: psutil.Process) -> float:
        try:
            return p.memory_info().rss / (1024 * 1024)
        except Exception:
            return 0.0

    def _daemon_check(self, p: psutil.Process) -> bool:
        """Basic daemon check based on having no controlling terminal."""
        try:
            if p.terminal() is None:
                return True
        except Exception:
            pass
        return False

    def get_cpu_percent(self, pid: int) -> float:
        """Approximate CPU usage percent for a PID since last call."""
        try:
            p = psutil.Process(pid)
            now = time.time()
            cpu = sum(p.cpu_times()[:2])  # user + system
            if pid not in self._last_cpu_check:
                self._last_cpu_check[pid] = (cpu, now)
                return 0.0

            last_cpu, last_t = self._last_cpu_check[pid]
            self._last_cpu_check[pid] = (cpu, now)

            dt = now - last_t
            if dt <= 0:
                return 0.0
            return ((cpu - last_cpu) / dt) * 100.0
        except Exception:
            return 0.0

    def get_details(self, pid: int) -> Optional[dict[str, Any]]:
        """Get detailed info for a single process."""
        try:
            p = psutil.Process(pid)
            return {
                "pid": pid,
                "name": p.name(),
                "exe": p.exe(),
                "cmdline": " ".join(p.cmdline()),
                "cwd": p.cwd(),
                "user": p.username(),
                "status": p.status(),
                "threads": p.num_threads(),
                "mem_mb": self._get_mem_mb(p),
                "ppid": p.ppid(),
                "create_time": p.create_time(),
                # Additional details (may require permissions)
                "open_files": p.open_files(),
                "connections": p.connections(kind="inet"),
                "nice": p.nice(),
            }
        except Exception:
            return None

    def matches(self, proc: ProcessData, qry: str) -> bool:
        qry = qry.lower()
        if qry in proc.name.lower():
            return True
        if qry in str(proc.pid):
            return True
        if proc.user and qry in proc.user.lower():
            return True
        return False

    def kill(self, pid: int) -> bool:
        try:
            psutil.Process(pid).kill()
            return True
        except Exception:
            return False
