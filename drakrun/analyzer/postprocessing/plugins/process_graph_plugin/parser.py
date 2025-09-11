from collections import defaultdict
import logging
from typing import Dict, Any, Iterator, Optional

from .events import BaseEvent, AllocateEvent, WriteEvent, ExecuteEvent
from ..parse_utils import parse_log

logger = logging.getLogger(__name__)

def to_int(val: Optional[str]) -> Optional[int]:
    if val is None:
        return None
    try:
        if isinstance(val, str) and val.startswith('0x'):
            return int(val, 16)
        return int(val)
    except (ValueError, TypeError):
        return None

class Parser:
    def __init__(self):
        # tid: {"rip": int, "rcx": int, "eip": int, "eax": int}
        self.context_changes: Dict[int, Dict[str, int]] = defaultdict(dict)

    def parse_entry(self, entry: Dict[str, Any]) -> Optional[BaseEvent]:
        method = entry.get("Method")
        retval = entry.get("ReturnValue")
        if not method or retval is None:
            return None

        args = entry.get("Arguments", {})
        extra = entry.get("Extra", {})

        try:
            base_info = {
                "source_pid": to_int(entry.get("PID")),
                "evtid": to_int(entry.get("EventUID")),
                "method": method,
                "raw_entry": entry
            }

            # Allocation primitives
            if method in ["NtAllocateVirtualMemory", "NtAllocateVirtualMemoryEx"]:
                target_pid = to_int(extra.get("ProcessHandle_PID"))
                address = to_int(extra.get("*BaseAddress"))
                size = to_int(extra.get("*RegionSize"))
                if target_pid and address is not None and size is not None:
                    return AllocateEvent(**base_info, target_pid=target_pid, address=address, size=size)

            # Write primitives
            elif method == "NtWriteVirtualMemory":
                target_pid = to_int(extra.get("ProcessHandle_PID"))
                address = to_int(args.get("BaseAddress"))
                bytes_written = to_int(extra.get("*NumberOfBytesWritten"))
                if target_pid and address is not None and bytes_written > 0:
                    return WriteEvent(**base_info, target_pid=target_pid, address=address, bytes_written=bytes_written)
            
            elif method in ["NtMapViewOfSection", "NtMapViewOfSectionEx"]:
                target_pid = to_int(extra.get("ProcessHandle_PID"))
                address = to_int(extra.get("*BaseAddress"))
                size = to_int(extra.get("*ViewSize"))
                if target_pid and address is not None and size is not None:
                    return WriteEvent(**base_info, target_pid=target_pid, address=address, bytes_written=size)

            # Execute primitives
            elif method in ["NtCreateThread", "NtCreateThreadEx", "RtlCreateUserThread"]:
                target_pid = to_int(extra.get("ProcessHandle_PID"))
                start_address = (
                    to_int(extra.get("ThreadContext", {}).get("Rip")) or
                    to_int(extra.get("*StartRoutine")) or
                    to_int(extra.get("*StartAddress"))
                )
                if target_pid and start_address:
                    return ExecuteEvent(**base_info, target_pid=target_pid, addresses=[start_address])
                
            elif method == "NtSetContextThread":
                target_tid = to_int(extra.get("ThreadHandle_TID"))
                context_data = extra.get("Context", {})
                if target_tid and context_data:
                    rip = to_int(context_data.get("Rip"))
                    rcx = to_int(context_data.get("Rcx"))
                    if rip: self.context_changes[target_tid]["rip"] = rip 
                    if rcx: self.context_changes[target_tid]["rcx"] = rcx
                return None
                            
            elif method == "NtSetInformationThread":
                target_tid = to_int(extra.get("ThreadHandle_TID"))
                context_data = extra.get("Wow64Context", {})
                if target_tid and context_data:
                    eip = to_int(context_data.get("Eip"))
                    eax = to_int(context_data.get("Eax"))
                    if eip: self.context_changes[target_tid]["eip"] = eip 
                    if eax: self.context_changes[target_tid]["eax"] = eax
                return None

            elif method == "NtResumeThread":
                target_pid = to_int(extra.get("ThreadHandle_PID"))
                target_tid = to_int(extra.get("ThreadHandle_TID"))
                if target_pid and target_tid and target_tid in self.context_changes:
                    # Retrieve the pending context change and clear it
                    context = self.context_changes.pop(target_tid)
                    addresses = [v for v in context.values() if v]
                    if addresses:
                        return ExecuteEvent(**base_info, target_pid=target_pid, addresses=addresses)
                        
        except (KeyError, ValueError, TypeError) as e:
            logger.debug(f"Skipping malformed log entry for {method}: {e}, event {entry.get('EventUID')}")

        return None

def stream_events(syscall_log_path) -> Iterator[BaseEvent]:
    logger.info(f"Streaming and parsing events from {syscall_log_path}...")
    parser = Parser()
    yield from parse_log(syscall_log_path, filter_cb=parser.parse_entry)