from dataclasses import dataclass
from typing import Optional

@dataclass
class BaseEvent:
    timestamp: float
    pid: int
    tid: int
    process_name: str
    event_id: int
    raw_entry: dict

@dataclass
class AllocateEvent(BaseEvent):
    event_type: str = "ALLOCATE"
    target_pid: int
    address: int 
    size: int 
    protection: int
    method: str
    
@dataclass
class WriteEvent(BaseEvent):
    event_type: str = "WRITE"
    target_pid: int
    address: int
    bytes_written: int
    method: str

@dataclass
class ExecuteEvent(BaseEvent):
    event_type: str = "EXECUTE"
    target_pid: int
    start_address: Optional[int] = None
    target_tid: Optional[int] = None
    method: str