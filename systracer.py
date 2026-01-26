from bcc import BPF
import time
#linux only
#run as root
from dataclasses import dataclass

@dataclass
class SysCall:
    pid: int
    name: str
    timestamp: str

#basic important syscall categories
#will be able to modify in the future

FILE_IO = {"open", "openat", "read", "write", "close", "stat", "lstat"}
NETWORK = {
    "socket", "connect", "accept",
    "sendto", "recvfrom", "sendmsg", "recvmsg"
}
PROCESS = {"fork", "vfork", "clone", "execve", "exit"}
MEMORY = {"mmap", "munmap", "brk"}


class SysTracer:
    def __init__(self, pid, on_event):
        self.pid = pid
        self.on_event = on_event#callback to ui
        self.running = False

        #default filters
        self.filters = {"file": True,
            "net": True,
            "proc": True,
            "mem": False,
            "other": False
        }
        #ebpf program
        #basically the way ebpf works is u can basically write a callback
        #for system calls

        #we will use it here to check if the call is associated with our pid
        #if it is return it
        self.bpf_text = f""" 
        #include <linux/sched.h>
        TRACEPOINT_PROBE(syscalls, sys_enter) {{
            u32 pid = bpf_get_current_pid_tgid() >> 32; 
            if (pid != {pid}) return 0;

            bpf_trace_printk("%d %d\\n", args->id, pid);
            return 0;
        }}
        """

        # >> 32 gets the pid number, not sure why
        #bpf_trace_pirintk logs to trace_pipe
        #itll log numbers not names

        self.bpf = BPF(text=self.bpf_text)
        self.syscalls = self.bpf.get_syscall_fnname #lazy but fine

    def set_filter(self, name, val):
        self.filters[name] = val

    def _filter(self, name):
        #decide if syscall should be shown
        if name in FILE_IO:
            return self.filters["file"]
        if name in NETWORK:
            return self.filters["net"]
        if name in PROCESS:
            return self.filters["proc"]
        if name in MEMORY:
            return self.filters["mem"]
        return self.filters["other"]

    def run(self):
        self.running = True
        print(f"[+] tracing pid {self.pid}")

        while self.running:
            try:
                task, pid, cpu, flags, ts, msg = self.bpf.trace_fields()  #in this order
                parts = msg.decode().strip().split()
                if not parts:
                    continue

                syscall_id = int(parts[0])
                name = self.bpf.syscall_name(syscall_id) #based on id cuz it saves a number remember

                if not self._filter(name): #check system cal for the names we allow
                    continue 

                evt = SysCall(pid=pid,name=name,timestamp=time.time())
                self.on_event(evt) #we will add to the window here
            except:
                pass

    def stop(self):
        self.running = False
