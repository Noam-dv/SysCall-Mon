import psutil
import tkinter as tk
from tkinter import ttk
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass, field

@dataclass
class ProcessData:
    data: dict = field(default_factory=dict)

class ProcessUtil:
    # monitoring util    
    @staticmethod
    def get_all_procs():
        #get all processes
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'username', 'status', 'create_time']):
            try:
                i = proc.info
                i['memory_mb']=proc.memory_info().rss / (1024 * 1024)
                i['num_threads']=proc.num_threads()
                i['cpu_percent']=0.0 #placeholder for now
                processes.append(ProcessData(i))
            except: #process closed or access denied
                pass
        
        return processes
    
    @staticmethod
    def get_process_by_pid(pid):
        try:
            return psutil.Process(pid)
        except: #process closed or access denied
            return None
    
    @staticmethod
    def get_process_details(pid: int):
        proc = ProcessUtil.get_process_by_pid(pid)
        if not proc:
            return None
        
        try:
            data = ProcessData({ #format data properly and wrap in a dataclass for orrgnaization
                'pid': proc.pid, 'parent_pid': proc.ppid(), 'name': proc.name(),
                'exe': proc.exe(), 'cmdline': ' '.join(proc.cmdline()), 'cwd': proc.cwd(),
                'username': proc.username(),
                'status': proc.status(),
                'num_threads': proc.num_threads(),
                'memory_mb': proc.memory_info().rss / (1024 * 1024),
                'create_time': datetime.fromtimestamp(proc.create_time()).strftime('%Y-%m-%d %H:%M:%S') #thx chatgpt
            })
            return data
        except:
            return None
    
    @staticmethod
    def filter_processes(proc_ls, query):
        if not query:
            return proc_ls

        query = query.lower()
        filtered = []
        for proc in proc_ls:
            if _matches(proc,query):
                filtered.append(proc)
        return filtered
    
    @staticmethod
    def _matches(proc, query):
        name = str(data.get('name', '')).lower()
        user = str(data.get('username', '')).lower()
        pid_str = str(data.get('pid', ''))
        return query in name or query in user or query in pid_str
