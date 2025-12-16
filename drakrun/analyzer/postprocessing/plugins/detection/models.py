from typing import Any, Dict, List, Optional, Literal, Union
from pydantic import BaseModel, Field, ConfigDict

class PipelineItem(BaseModel):
    model_config = ConfigDict(extra='ignore', arbitrary_types_allowed=True)
    timestamp: float = 0.0
    source_seqid: Optional[int] = None
    target_seqid: Optional[int] = None

class Log(PipelineItem):
    """Base for all raw logs from the file"""
    raw: Dict[str, Any] = Field(exclude=True)

class SystemCall(Log):
    method: str = Field(alias="Method")
    args: Dict[str, Any] = Field(alias="Arguments", default_factory=dict)
    extra: Dict[str, Any] = Field(alias="Extra", default_factory=dict)
    
class WinApiCall(Log):
    method: str = Field(alias="Method")
    args: Dict[str, Any] = Field(alias="Arguments", default_factory=dict)
    # Return values, etc...

class Event(PipelineItem):
    """Intermediate events produced by Rules"""
    pass

class MemoryWriteEvent(Event):
    address: int
    size: int
    data_source: Log # Traceability

class CodeExecuteEvent(Event):
    start_address: int
    method_used: str

class Finding(Event):
    title: str
    description: str
    confidence: str # Low, Medium, High