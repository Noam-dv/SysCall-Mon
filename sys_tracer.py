from bcc import BPF
import time
import threading
import queue
#linux only
#run as root
from dataclasses import dataclass
from syscall_helpers import *

@dataclass
class SysCall:
    pid: int
    name: str
    timestamp: float
    args: dict
    event_type: SysType.OTHER

#MOVED TO SYSCALL_HELPERS.PY
#basic important syscall categories
#will be able to modify in the future
#FILE_IO = {"open", "openat", "read", "write", "close", "stat", "lstat"}
#NETWORK = {
#    "socket", "connect", "accept",
#    "sendto", "recvfrom", "sendmsg", "recvmsg"
#}
#PROCESS = {"fork", "vfork", "clone", "execve", "exit"}
#MEMORY = {"mmap", "munmap", "brk"}


class SysTracer:
    def __init__(self, pid):
        self.pid = pid
        self.running = False

        #thread safe queue
        #ui will pull from this
        self.events = queue.Queue(maxsize=4096) #max queue size prevent overflows

        #default filters to have on 
        self.filters = {
            "file": True,
            "net": True,
            "proc": True,
            "mem": False,
            "other": False
        }

        #this code actually runs in kernel 
        self.bpf = BPF(src_file="syscall_tracer.c")
        self.bpf["events"].open_perf_buffer(self._on_event)

        #worker thread not qt rhread
        self._thread = threading.Thread(
            target=self._run,
            daemon=True
        )

        self.syscall_table = load_syscall_table()
 
        self._last_emit = 0.0 #really wanna avoid lag so we w ill rate limit
        self._emit_interval = 0.01  #100 events per sec max per pid

    def set_filter(self, name, val):
        self.filters[name] = val

    def _on_event(self, cpu, data, size):
        try:
            now = time.time() #ratelimit
            if now - self._last_emit < self._emit_interval:
                return
            self._last_emit = now

            evt = self.bpf["events"].event(data)
            if evt.pid != self.pid: #only for our pid
                return
                 
            name = self.syscall_table.get(evt.id)
            if not name:
                name = f"sys_{evt.id}"

            raw_args = tuple(evt.args)

            #parse syscall args using helper
            parsed_args = parse_syscall_args(name, raw_args)

            sc = SysCall(
                pid=evt.pid,
                name=name,
                timestamp=now,
                args=parsed_args,
                event_type=syscall_category(name)
            )

            try:
                self.events.put_nowait(sc) #try add to queue 
                #if queue is full dont add to fix overflowing
            except queue.Full:
                pass

        except Exception as e:
            print(f"[event error] {e}")

    def start(self): #start tracing thread
        if self.running:
            return
        self.running = True
        self._thread.start()

    def _run(self):
        #poll perf buffer
        while self.running:
            try:
                self.bpf.perf_buffer_poll(timeout=500)
            except:
                pass

    def stop(self):
        self.running = False
        try:
            self.bpf.cleanup() #detach and free perf bufefrs
        except:
            pass