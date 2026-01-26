import os
import re
from collections import deque, Counter
import time

#sorting to category
FILE_IO = {"open", "openat", "read", "write", "close", "stat", "lstat"}
NETWORK = {"socket", "connect", "accept", "sendto", "recvfrom", "sendmsg", "recvmsg"}
PROCESS = {"fork", "vfork", "clone", "execve", "exit"}
MEMORY = {"mmap", "munmap", "brk"}

def syscall_category(name): #basic categorization
    if name in FILE_IO: return "file"
    if name in NETWORK: return "net"
    if name in PROCESS: return "proc"
    if name in MEMORY: return "mem"
    return "other"
    
def load_syscall_table(): #syscall table will be done manually
    #for some reason ebpfs function doesn work
    #at runtime
    table = {}

    paths = [ #default paths
        "/usr/include/x86_64-linux-gnu/asm/unistd_64.h",
        "/usr/include/asm/unistd_64.h",
    ]

    for p in paths: 
        if not os.path.exists(p):
            continue
        with open(p) as f: #map syscal id to name
            for l in f:
                m = re.match(r"#define __NR_(\w+)\s+(\d+)", l) #(chatgpt regex)
                if m:
                    name, num = m.groups()
                    table[int(num)] = name
        break
    return table