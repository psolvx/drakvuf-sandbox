import logging
from typing import Optional, Dict, Any, Iterator

from .events import BaseEvent, AllocateEvent, WriteEvent, ExecuteEvent
from analyzer.postprocessing.plugins.parse_utils import parse_log

logger = logging.getLogger(__name__)

def parse_syscall_entry(entry: Dict[str, Any]) -> Optional[BaseEvent]:
    method = entry.get("Method")
    if not method:
        return None

    try:
        if method == "NtAllocateVirtualMemory" and entry.get("ReturnValue") == "0x0":
            if "*BaseAddress" in entry:
                return AllocateEvent(
                    timestamp=float(entry["TimeStamp"]),
                    pid=entry["PID"],
                    tid=entry["TID"],
                    process_name=entry["ProcessName"],
                    event_uid=entry["EventUID"],
                    raw_entry=entry,
                    target_pid=entry.get("ProcessHandle_PID", entry["PID"]),
                    address=int(entry["*BaseAddress"], 16),
                    size=int(entry["*RegionSize"], 16),
                    protection=int(entry["Protect"], 16),
                    method="NtAllocateVirtualMemory"
                )

        elif method == "NtWriteVirtualMemory":
            target_pid = entry.get("ProcessHandle_PID")
            if target_pid and entry["PID"] != target_pid: # remote write
                return WriteEvent(
                    timestamp=float(entry["TimeStamp"]),
                    pid=entry["PID"],
                    tid=entry["TID"],
                    process_name=entry["ProcessName"],
                    event_uid=entry["EventUID"],
                    raw_entry=entry,
                    target_pid=target_pid,
                    address=int(entry["BaseAddress"], 16),
                    bytes_written=entry.get("NumberOfBytesToWrite", 0),
                    method="NtWriteVirtualMemory"
                )

        elif method == "NtCreateThreadEx":
            target_pid = entry.get("TargetPID")
            if target_pid and entry["PID"] != target_pid:
                return ExecuteEvent(
                    timestamp=float(entry["TimeStamp"]),
                    pid=entry["PID"],
                    tid=entry["TID"],
                    process_name=entry["ProcessName"],
                    event_uid=entry["EventUID"],
                    raw_entry=entry,
                    target_pid=target_pid,
                    technique="CreateRemoteThread",
                    start_address=int(entry.get("StartAddress", "0"), 16),
                    method="NtCreateThreadEx"
                )

    
    except (KeyError, ValueError, TypeError) as e:
        logger.debug(f"Skipping malformed log entry for {method}: {e}")
        return None

    return None

def stream_events(syscall_log_path) -> Iterator[BaseEvent]:
    logger.info(f"Streaming and parsing events from {syscall_log_path}...")
    yield from parse_log(syscall_log_path, filter_cb=parse_syscall_entry)