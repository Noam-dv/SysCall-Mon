import psutil, os, time
from PyQt6.QtGui import QIcon
from dataclasses import dataclass


#small data holder
#dataclass is fine here cuz this is pure data
@dataclass
class ProcessData:
    pid: int
    name: str
    mem: float
    user: str | None = None
    status: str | None = None
    icon: QIcon | None = None
    daemon: bool=False

class ProcessUtil:
    def __init__(self):
        self._last_cpu_check = {} #pid: (cpu_time, timestamp)
        self._gio_ok = False # i guess we can utilize the dumbness of me making a util process instantiable
        self._gio = None
        self._icon_cache = {}
        
    #get all running processes
    #main entry point
    def get_all(self):
        out = []

        for p in psutil.process_iter(["pid", "name", "username", "status"]):
            try:
                pid = p.pid
                name = p.info.get("name") or "???"
                user = p.info.get("username")
                status = p.info.get("status")

                mem = self._get_mem_mb(p)
                icon = self._get_icon(p)
                daemon = self._daemon_check(p)

                out.append(ProcessData(pid, name, mem, user, status, icon, daemon))
            except:
                #process died or access denied
                continue

        out.sort(key=lambda x: x.pid)
        return out

    def _get_mem_mb(self, p):
        #memory in mb
        try:
            return p.memory_info().rss / (1024 * 1024)
        except:
            return 0.0

    def _init_gio(self): 
        if self._gio_ok:
            return
        try:
            import gi #moved here to not import every time we get icon 
            #which is per process 
            gi.require_version("Gio", "2.0")
            from gi.repository import Gio
            self._gio = Gio
            self._gio_ok = True
        except:
            self._gio_ok = False


    def _get_icon(self, p):
        #try to grab icon from gotten path
        #sometimes wont work but its fine

        #im still learning to develop on linux
        #tried to implement this better
        
        name = p.name()
        #cache
        if name in self._icon_cache:
            return self._icon_cache[name]
        icon = None

        #try gio desktop app icons first
        self._init_gio()
        if self._gio_ok:
            try:
                exe = p.exe()
                base = os.path.basename(exe) #try finding by executable name
                for a in self._gio.AppInfo.get_all(): #more efficient icon finding
                    try:
                        if base.lower() in a.get_executable().lower():
                            gicon = a.get_icon()
                            if gicon:
                                icon = QIcon.fromTheme(gicon.to_string())
                                break
                    except:
                        pass
            except:
                pass

        #qt theme icon fallback
        if not icon or icon.isNull():
            try:
                icon = QIcon.fromTheme(name.lower()) #qt theme icon (i wanna implement themes later)
            except:
                pass

        if not icon or icon.isNull(): #last fallback
            icon = QIcon.fromTheme("application-x-executable") #default icon

        self._icon_cache[name] = icon
        return icon

    def _daemon_check(self, p): #not exact
        try:
            if p.terminal() is None:
                return True
        except:
            pass
        return False

    def get_cpu_percent(self, pid): 
        #get cpu usage manually
        #prepping for real tracer logic
        try:
            p = psutil.Process(pid)
            now = time.time()
            cpu = sum(p.cpu_times()[:2]) #user+system
            if pid not in self._last_cpu_check:
                self._last_cpu_check[pid] = (cpu, now)
                return 0.0

            last_cpu, last_t = self._last_cpu_check[pid]
            self._last_cpu_check[pid] = (cpu, now)

            dt = now - last_t
            if dt <= 0:
                return 0.0

            #return avg cpu
            return ((cpu - last_cpu) / dt) * 100.0
        except:
            return 0.0

    def get_details(self, pid):
        #get detailed info for a single process 
        #this will be used a for future details panel that im adding 
        #for processes being shaddowed
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

                #extra stuff (nice for procmon vibes)
                "open_files": p.open_files(),
                "connections": p.connections(kind="inet"),
                "nice": p.nice(),
            }
        except:
            return None

    def matches(self, proc, qry):
        qry = qry.lower()
        if qry in proc.name.lower():
            return True
        if qry in str(proc.pid):
            return True
        if proc.user and qry in proc.user.lower():
            return True
        return False

    #kill process
    #will be used later for suspicious programs
    def kill(self, pid):
        try:
            psutil.Process(pid).kill()
            return True
        except:
            return False