from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict

@dataclass(slots=True) #slots good for high volume logs
class SysLog:
    timestamp: datetime
    pid: int
    process_name: str
    syscall: str
    result: int
    thread_id: Optional[int] = None
    args: Optional[Dict[str, object]] = None
    duration_us: Optional[int] = None
