from dataclasses import dataclass, asdict, field
from typing import List, Optional, Dict, Any

@dataclass
class BaseEvent:
    source_pid: int
    evtid: int
    method: str
    raw_entries: List[Dict[str, Any]] = field(default_factory=list)
    target_pid: Optional[int] = None
    source_seqid: Optional[int] = None
    target_seqid: Optional[int] = None

@dataclass
class AllocateEvent(BaseEvent):
    address: int = 0
    size: int = 0
    event_type: str = "allocate"

@dataclass
class WriteEvent(BaseEvent):
    address: int = 0
    bytes_written: int = 0
    event_type: str = "write"

@dataclass
class ExecuteEvent(BaseEvent):
    addresses: List[int] = None
    target_tid: Optional[int] = None
    event_type: str = "execute"

@dataclass
class FileTaskFolderEvent(BaseEvent):
    file_name: str = ""
    event_type: str = "file_write"

@dataclass
class TaskRegisterEvent(BaseEvent):
    task_name: str = ""
    event_type: str = "task_register"


def event_to_dict(event_obj: BaseEvent) -> Dict[str, Any]:
    if not isinstance(event_obj, BaseEvent):
        return event_obj
        
    data = asdict(event_obj)
    data['event_type'] = event_obj.__class__.__name__
    return data

EVENT_CLASS_MAP = {
    "AllocateEvent": AllocateEvent,
    "WriteEvent": WriteEvent,
    "ExecuteEvent": ExecuteEvent,
    "FileTaskFolderEvent": FileTaskFolderEvent,
    "TaskRegisterEvent": TaskRegisterEvent
}

def dict_to_event(event_dict: dict) -> BaseEvent:
    class_name = event_dict.pop('event_type', None)
    if not class_name:
        raise ValueError("Dictionary is missing 'event_type' key")
        
    event_class = EVENT_CLASS_MAP.get(class_name)
    if not event_class:
        raise ValueError(f"Unknown event class name: {class_name}")

    return event_class(**event_dict)