from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict, model_validator


class PipelineItem(BaseModel):
    model_config = ConfigDict(extra='ignore', arbitrary_types_allowed=True)
    source_seqid: Optional[int] = None
    target_seqid: Optional[int] = None


class Log(PipelineItem):
    """Base for all raw logs from the file"""
    raw: Dict[str, Any] = Field(exclude=True)


class SystemCall(Log):
    model_config = ConfigDict(
        extra='ignore',
        arbitrary_types_allowed=True,
        populate_by_name=True
    )
    method: str = Field(alias="Method")
    args: Dict[str, Any] = Field(alias="Arguments", default_factory=dict)
    extra: Dict[str, Any] = Field(alias="Extra", default_factory=dict)
    return_value: str = Field(alias="ReturnValue")


class WinApiCall(Log):
    model_config = ConfigDict(
        extra='ignore',
        arbitrary_types_allowed=True,
        populate_by_name=True
    )
    method: str = Field(alias="Method")
    args: Dict[str, Any] = Field(alias="Arguments")
    return_value: str = Field(alias="ReturnValue")

    @model_validator(mode="before")
    @classmethod
    def build_arguments(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        args = values["Arguments"]
        values["Arguments"] = dict(arg.split("=", 1) for arg in args)
        return values

class Event(PipelineItem):
    """Base class for synthesized events"""
    source_pid: int
    evtid: int
    method: str
    raw_entries: List[Dict[str, Any]] = Field(default_factory=list)
    target_pid: Optional[int] = None


class AllocateEvent(Event):
    address: int = 0
    size: int = 0
    event_type: str = "allocate"


class WriteEvent(Event):
    address: int = 0
    bytes_written: int = 0
    event_type: str = "write"


class ExecuteEvent(Event):
    addresses: List[int] = Field(default_factory=list)
    target_tid: Optional[int] = None
    event_type: str = "execute"


class Finding(Event):
    title: str
    description: str
    confidence: str
    related_events: List[Event]