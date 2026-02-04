import time
import math
from collections import deque, defaultdict, Counter
from dataclasses import dataclass
from typing import List, Dict
from syscall_helpers import SysType
from enum import Enum

"""
constants
how much data we need before trusting stats
avoids flagging stuff while the model is still cold, 
minimum sequences until we start judging out of the ordinary sequences
"""
min_samples = 30
min_seq = 500

frequency_z_thresh = 4.0 # rate spikes far from normal
sequence_prob = 0.001 # sequences rare than this are suspicious
param_z_thresh = 5.0 # parameters have to be super far from normal cuz theyre not a good tell
seq_severity_min = 0.6 #only report strong seq anomalys
min_std_dev = 0.1 # set a minimum to avoid setting it too low and having tons of false positives


@dataclass
class Anomaly:
    """represents a single event passed to the anomaly panel"""
    timestamp: float
    pid: int
    anomaly_type: str #frequency sequence or param anomaly
    severity: float
    description: str
    details: dict


class RollingStats:
    """
    keeps a rolling window of values
    used to learn what is the normal amount of weird activity
    and waht to flag
    """

    def __init__(self, window_size=100):
        # deque auto drops old values when full
        self.window = deque(maxlen=window_size)

    def add(self, value):
        self.window.append(value)

    def mean(self):
        # average of current window
        if not self.window:
            return 0.0
        return sum(self.window) / len(self.window)

    def std_dev(self):
        # how much values normally wiggle around the mean
        if len(self.window) < 2:
            return 0.0

        avg = self.mean()
        total = 0.0

        for x in self.window:
            diff = x - avg
            total += diff * diff

        return math.sqrt(total / len(self.window))

    def z_score(self, value):
        # how far value is from normal relative to usual noise
        std = self.std_dev()
        if std == 0:
            return 0.0
        return abs(value - self.mean()) / std

    def is_ready(self):
        # dont trust stats until enough samples exist
        return len(self.window) >= min_samples


class FrequencyDetector:
    """
    tracks syscall rate per category
    looks for sudden spikes compared to recent behavior
    uses the rollingstats class to identify wahts a normal frequency
    and whats weird
    """
    def __init__(self):
        self.category_rates = {} # keep zscore for each category
        self.last_counts = defaultdict(int) #raw counts since last tick
        self.last_check_time = time.time()

    def add_syscall(self, category: SysType):
        self.last_counts[category] += 1 #count syscall occurences

    def check_and_update(self) -> List[Anomaly]:
        now = time.time() # run once per sec
        elapsed = now - self.last_check_time

        if elapsed < 1.0:
            return []

        out = []

        for category, count in self.last_counts.items():
            if category not in self.category_rates: #initialize rolling state
                self.category_rates[category] = RollingStats(window_size=60)
                
            stats = self.category_rates[category]
            rate = count / elapsed
            if stats.is_ready():
                z = stats.z_score(rate)

                # only flag if far outside normal noise
                if z > frequency_z_thresh and stats.std_dev() > min_std_dev:
                    out.append(Anomaly(
                        timestamp=now,
                        pid=0,
                        anomaly_type="frequency",
                        severity=min(z / 15.0, 1.0), #dont go over 1
                        description=f"abnormal {category.value} rate: {rate:.1f}/s",
                        details={
                            "rate": rate,
                            "mean": stats.mean(),
                            "std": stats.std_dev(),
                            "z": z,
                        }
                    )) 

            stats.add(rate) # update mean

        self.last_counts.clear() #reset for next interval
        self.last_check_time = now

        return out #all categorys with anomalys

class ParameterDetector:
    """
    looks for syscall args that are way outside normal range
    file descriptor values sizes lengths etc
    """
    def __init__(self):
        self.fd_stats = RollingStats(window_size=100)
        self.size_stats = {}

    def analyze_args(self, syscall_name: str, args: dict) -> List[Anomaly]:
        if not args:
            return []
        out = []
        now = time.time()
        """
        file descrptor anomalies
        if the program suddenly accesses a new file or something far
        out of its reach then flag it 
        size anomalys
        if a process tries to write or read more than usual 
        then flag as slighlty suspicious
        """
        filedesc = args.get("fd")
        if isinstance(filedesc, int) and filedesc > 0:
            self.fd_stats.add(filedesc)

            if self.fd_stats.is_ready():
                z = self.fd_stats.z_score(filedesc)
                if z > param_z_thresh and self.fd_stats.std_dev() > 1.0: 
                    out.append(Anomaly(
                        timestamp=now,
                        pid=0,
                        anomaly_type="parameter",
                        severity=min(z / 15.0, 1.0),
                        description=f"fd unusually high: {filedesc}",
                        details={"fd": filedesc, "z": z}
                    ))

        #size params
        for key in ("size", "length", "count", "len"):
            val = args.get(key)
            if not isinstance(val, (int,float)) or val <= 0:
                continue

            stats = self.size_stats.get(key)
            if stats is None:
                stats = RollingStats(window_size=100)
                self.size_stats[key]=stats

            if stats.is_ready(): #enough data
                z = stats.z_score(val)
                if z > param_z_thresh and stats.std_dev() > 1.0:
                    out.append(Anomaly(
                        timestamp=now,
                        pid=0,
                        anomaly_type="parameter",
                        severity=min(z / 15.0, 1.0),
                        description=f"weird {key} in {syscall_name}: {val}",
                        details={"param": key, "value": val, "z": z}
                    ))
            stats.add(val)

        return out


class AnomalyDetector:
    """
    combines all prior detectors
    analysis happens in chunks
    """
    
    def __init__(self):
        self.processes: Dict[int, dict] = {} #each pid has its own detectors for future sessions
        self.recent_anomalies = deque(maxlen=1000)  #recent anomalies (for ui)
        self.sensitivity = 1.0 #global mult

        self.event_buffer: Dict[int, list] = defaultdict(list) #buffer of raw syscall

    def _get_detectors(self, pid: int) -> dict:
        #init detectors per process when first asked for
        if pid not in self.processes:
            self.processes[pid] = {
                "frequency": FrequencyDetector(),
                "parameter": ParameterDetector(),
                "start_time": time.time(),
                "syscall_count": 0,
            }
        return self.processes[pid]

    def ingest_syscall(self, pid: int, name: str, category: SysType, args: dict):
        #js store the data for batching
        self.event_buffer[pid].append((name, category, args))

    def analyze_batch(self) -> List[Anomaly]:
        """process calls in chunks now rather then event based cuz its far too expesnive"""
        out = []

        for pid, events in self.event_buffer.items():
            if not events:
                continue

            d = self._get_detectors(pid)

            for name, category, args in events:
                d["syscall_count"] += 1 #update freq
                d["frequency"].add_syscall(category)
                out.extend(d["parameter"].analyze_args(name, args))

            freq_out = d["frequency"].check_and_update()

            for a in freq_out: #forgot to set pid
                a.pid = pid

            for a in out:
                if a.pid == 0:
                    a.pid = pid

            out.extend(freq_out)

        self.event_buffer.clear()

        for a in out:
            a.severity = min(a.severity * self.sensitivity, 1.0)
            self.recent_anomalies.append(a)

        return out


    def get_process_stats(self, pid: int):
        if pid not in self.processes:
            return None

        d = self.processes[pid]
        return {
            "uptime": time.time() - d["start_time"],
            "total_syscalls": d["syscall_count"],
        }

    def get_recent_anomalies(self, limit=100) -> List[Anomaly]:
        return list(self.recent_anomalies)[-limit:]

    def clear_process(self, pid: int):
        self.processes.pop(pid, None) #when the proc exits
        self.event_buffer.pop(pid, None)

    def set_sensitivity(self, level: float):
        self.sensitivity = max(0.1,min(level,3.0)) # map between .1 and 3