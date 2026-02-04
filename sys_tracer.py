from bcc import BPF
import time
import threading
import queue
from dataclasses import dataclass
from syscall_helpers import *
from anomaly_detector import AnomalyDetector

"""
linux only
run as root
"""

@dataclass
class SysCall:
    pid: int
    name: str
    timestamp: float
    args: dict
    event_type: SysType.OTHER
    anomalies: list = None  # Detected anomalies for this syscall


class SysTracer:
    """
    SysTracer

    attaches an eBPF program that traces syscalls
    filters by pid
    parses syscall names and arguments
    pushes processed events into a thread-safe queue
    """

    def __init__(self, pid):
        self.pid = pid
        self.running = False

        #thread safe queueui will pull from this
        self.events = queue.Queue(maxsize=4096) #max queue size prevent overflows

        #default filters 
        self.filters = {
            "file": True,
            "net": True,
            "proc": True,
            "mem": True,
            "other": False
        }

        
        #this code actually runs in kernel
        self.bpf = BPF(src_file="syscall_tracer.c") # written in C to give the verifier an easier time (code compiles to bytecode and runs if verified)
        self.bpf["events"].open_perf_buffer(self._on_event)

        #worker thread not qt thread
        self._thread = threading.Thread(
            target=self._run,
            daemon=True
        )

        self.syscall_table = load_syscall_table() #maps id to syscall
 
        #eally wanna avoid lag so we will rate limit
        self._last_emit = 0.0
        self._emit_interval = 0.01 #100 events per sec max per pid

        #anomaly detection
        self.anomaly_detector = AnomalyDetector()

        self._last_analyze = time.time()
        self._analyze_interval = 0.25  # analyze every 250ms

    def set_filter(self, name, val):
        self.filters[name] = val

    def _on_event(self, cpu, data, size):
        """perf buffer callback"""
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

            parsed_args = parse_syscall_args(name, raw_args)
            cat = syscall_category(name)
            sc = SysCall(
                pid=evt.pid,
                name=name,
                timestamp=now,
                args=parsed_args,
                event_type=cat
            )

            #anomaly detection
            self.anomaly_detector.ingest_syscall(
                evt.pid,
                name,
                cat,
                parsed_args
            )

            #run batch analysis occasionally
            if now - self._last_analyze >= self._analyze_interval:
                batch_anomalies = self.anomaly_detector.analyze_batch()
                self._last_analyze = now
                #attach anomalies that belong to this pid
                sc.anomalies = [
                    a for a in batch_anomalies if a.pid == evt.pid
                ]

            try:
                self.events.put_nowait(sc) #try add to queue 
            except queue.Full:
                pass

        except Exception as e:
            print(f"[event error] {e}")

    def start(self):
        """start tracing thread"""
        if self.running:
            return
        self.running = True
        self._thread.start()

    def _run(self):
        """poll perf buffer"""
        while self.running:
            try:
                self.bpf.perf_buffer_poll(timeout=500)
            except:
                pass

    def stop(self):
        """stop tracing and cleanup"""
        self.running = False
        try:
            self.bpf.cleanup() #detach and free perf buffers
        except:
            pass

    def get_anomaly_detector(self):
        """get the anomaly detector for this tracer"""
        return self.anomaly_detector

    def set_detection_sensitivity(self, sensitivity: float):
        self.anomaly_detector.set_sensitivity(sensitivity)