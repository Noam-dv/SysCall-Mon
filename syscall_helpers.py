import os
import re
import json
from enum import Enum

"""
syscall helpers:
syscall table loader
syscall categorization

categories and args from json so this isnt hardcoded shit
so many dicts luckily theyre are o(1) lookup
"""

class SysType(Enum):
    """
    FILE_IO    - actual data read write to files
    FS_META    - filesystem structure and permissions not data itself but still important
    PROCESS    - process creation exec exit signals basically program control
    MEMORY     - virtual memory management mapping protection and heap stuff
    IPC        - local process communication looks like network but isnt ( i dont really understand this one )
    NETWORK    - networking to other machines
    EVENTS     - waiting and notification syscalls (epoll poll type stuff)
    TIME       - sleeping timers and clocks
    SECURITY   - things that change authority
    OTHER
    """
    FILE_IO = "file"
    FS_META = "fs_meta"
    PROCESS = "process"
    MEMORY = "memory"
    IPC  = "ipc"
    NETWORK = "network"
    EVENTS = "events"
    TIME = "time"
    SECURITY = "security"
    OTHER = "other"


def load_category_dict(path="!syscall_categories.json"):
    """
    load syscall categories from json

    json format:
    {
      "file": ["open", "read"],
      "process": ["fork", "exec"]
    }
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"syscall category file doesnt exist: {path}")

    categories = {}
    with open(path, "r") as f:
        r = json.load(f)
        
    for cat, ls in r.items():
        try:
            parsedcategory = SysType(cat)
        except ValueError:
            continue # nocategory name
        categories[parsedcategory] = tuple(ls)
    return categories


CATEGORIES = load_category_dict() #global


def syscall_category(name:str) -> SysType:
    """
    basic categorization
    prefix based for less specific resutls
    """
    for category, prefixes in CATEGORIES.items():
        if name.startswith(prefixes):
            return category
    return SysType.OTHER


def load_syscall_signatures(path="!syscall_signatures.json"):
    """parse raw syscall args into named args based on the json"""
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        return json.load(f)


SIGNATURES = load_syscall_signatures()

#arg names that are actually strings (deref'd by ebpf)
#ebpf only reads one path per call so first match wins
STRING_ARG_NAMES = ("path", "filename", "oldpath", "target", "source", "linkpath")


def parse_syscall_args(name:str, args:tuple, path_str:str=None):
    """
    maps syscal name and raw args
    maps to a readable dict  { argname: argval }
    path_str is the string deref'd in kernel space (for path/filename args)
    """
    sig = SIGNATURES.get(name)
    if not sig: #no args
        return None
    parsed={}
    swapped = False #only one string per call from ebpf
    for i, arg in enumerate(sig):
        if i >= len(args):
            break #undefined arg ig?
        if path_str and not swapped and arg in STRING_ARG_NAMES:
            parsed[arg] = path_str #swap the pointer for the actual str
            swapped = True
        else:
            parsed[arg] = args[i]
    return parsed


def load_syscall_table():
    """
    syscall table will be done manually
    for some reason ebpfs function doesn work
    at runtime
    """
    table = {}

    paths = [
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