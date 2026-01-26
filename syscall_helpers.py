import os
import re
import json
from enum import Enum

#syscall helpers:
#syscall table loader
#syscall categorization
#categories from json so this isnt hardcoded shit

class SysType(Enum):
    FILE_IO = "file" #actual data read write to files
    FS_META = "fs_meta" #filesystem structure and permissions not data itself but still important
    PROCESS = "process" #process creation exec exit signals basically program control
    MEMORY = "memory" #virtual memory management mapping protection and heap stuff
    IPC  = "ipc" #local process communication looks like network but isnt ( i dont really understand this one )
    NETWORK = "network" #networking to other machines
    EVENTS = "events" #waiting and notification syscalls (epoll poll type stuff)
    TIME = "time" #sleeping timers and clocks
    SECURITY = "security" #things that change authority
    OTHER = "other"


#load syscall categories from json
def load_category_dict(path="syscall_categories.json"):
    if not os.path.exists(path):
        raise FileNotFoundError(f"syscall category file doesnt exist: {path}")

    categories = {}
    with open(path, "r") as f:
        r = json.load(f)
        
    for cat, ls in r.items():
        #json format
        #{
        #  "file": ["open", "read"],
        #  "process": ["fork", "exec"]
        #}
        
        try:
            parsedcategory = SysType(cat)
        except ValueError:
            continue # nocategory name
        categories[parsedcategory] = tuple(ls)
    return categories


CATEGORIES = load_category_dict() #global

#basic categorization
#prefix based for less specific resutls
def syscall_category(name:str) -> SysType:
    for category, prefixes in CATEGORIES.items():
        if name.startswith(prefixes):
            return category
    return SysType.OTHER

#def syscall_category(name) -> SysType: #basic categorization
#    if name in FILE_IO: return SysType.FILE_IO
#    if name in NETWORK: return SysType.NETWORK
#    if name in PROCESS: return SysType.PROCESS
#    if name in MEMORY: return SysType.MEMORY
#    return SysType.OTHER


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