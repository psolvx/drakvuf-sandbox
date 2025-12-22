from typing import Any, Dict, List, Optional
import msgspec


class PipelineItem(msgspec.Struct, omit_defaults=True, forbid_unknown_fields=False):
    """Base class for all pipeline items."""
    source_seqid: Optional[int] = None
    target_seqid: Optional[int] = None


class Log(PipelineItem, forbid_unknown_fields=False):
    """Base for all raw logs from the file"""
    raw: Dict[str, Any] = msgspec.field(default_factory=dict)


class SystemCall(Log, kw_only=True, forbid_unknown_fields=False, rename={"method": "Method", "args": "Arguments", "extra": "Extra", "return_value": "ReturnValue"}):
    method: str = ""
    args: Dict[str, Any] = msgspec.field(default_factory=dict)
    extra: Dict[str, Any] = msgspec.field(default_factory=dict)
    return_value: str = ""


class WinApiCall(Log, kw_only=True, forbid_unknown_fields=False, rename={"method": "Method", "args": "Arguments", "return_value": "ReturnValue"}):
    method: str = ""
    args: Dict[str, Any] = msgspec.field(default_factory=dict)
    return_value: str = ""

class Event(PipelineItem, kw_only=True, forbid_unknown_fields=False):
    """Base class for synthesized events"""
    source_pid: int = 0
    evtid: int = 0
    method: str = ""
    raw_entries: List[Dict[str, Any]] = msgspec.field(default_factory=list)
    target_pid: Optional[int] = None


class AllocateEvent(Event, forbid_unknown_fields=False):
    address: int = 0
    size: int = 0
    event_type: str = "allocate"


class WriteEvent(Event, forbid_unknown_fields=False):
    address: int = 0
    bytes_written: int = 0
    event_type: str = "write"


class ExecuteEvent(Event, forbid_unknown_fields=False):
    addresses: List[int] = msgspec.field(default_factory=list)
    target_tid: Optional[int] = None
    event_type: str = "execute"


class Finding(Event, forbid_unknown_fields=False):
    title: str = ""
    description: str = ""
    confidence: str = ""
    related_events: List[Event] = msgspec.field(default_factory=list)