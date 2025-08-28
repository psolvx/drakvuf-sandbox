from dataclasses import dataclass
from typing import List, Optional

@dataclass
class BaseEvent:
    source_pid: int
    target_pid: int
    evtid: int
    raw_entry: dict
    method: str

@dataclass
class AllocateEvent(BaseEvent):
    address: int 
    size: int 
    event_type: str = "allocate"

@dataclass
class WriteEvent(BaseEvent):
    address: int
    bytes_written: int
    event_type: str = "write"

@dataclass
class ExecuteEvent(BaseEvent):
    target_pid: int
    addresses: List[int]
    target_tid: Optional[int] = None
    event_type: str = "execute"