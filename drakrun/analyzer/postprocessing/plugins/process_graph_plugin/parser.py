from collections import defaultdict
import logging
import re
from typing import Dict, Any, Iterator

from .events import BaseEvent, AllocateEvent, WriteEvent, ExecuteEvent
from ..parse_utils import parse_log

logger = logging.getLogger(__name__)

class Parser:
    def __init__(self):

        # tid: {"rax": int, "rcx": int}
        self.context_changes: Dict[int, Dict[str, int]] = defaultdict(dict)

    def parse_entry(self, entry: Dict[str, Any]) -> BaseEvent:
        method = entry.get("Method")
        retval = entry.get("ReturnValue")
        if not method or retval is None:
            return None

        try:
            base_info = {
                "source_pid": entry.get("PID"),
                "evtid": int(entry.get("EventUID"), 16),
                "method": entry.get("Method"),
                "raw_entry": entry
            }

            # Allocation primitives
            if method in ["NtAllocateVirtualMemory", "NtAllocateVirtualMemoryEx"] and entry.get("ProcessHandle_PID"):
                return AllocateEvent(
                    **base_info,
                    target_pid=int(entry.get("ProcessHandle_PID"), 16),
                    address=int(entry["*BaseAddress"], 16),
                    size=int(entry["*RegionSize"], 16)
                )                

            # Write primitives
            elif method == "NtWriteVirtualMemory" and entry.get("ProcessHandle_PID") and int(entry["*NumberOfBytesWritten"], 16) > 0:
                return WriteEvent(
                    **base_info,
                    target_pid=int(entry.get("ProcessHandle_PID"), 16),
                    address=int(entry["*BaseAddress"], 16),
                    bytes_written=int(entry["*NumberOfBytesWritten"], 16)
                )
            
            elif method in ["NtMapViewOfSection", "NtMapViewOfSectionEx"] and entry.get("ProcessHandle_PID"):
                return WriteEvent(
                    **base_info,
                    target_pid=int(entry.get("ProcessHandle_PID"), 16),
                    address=int(entry["*BaseAddress"], 16),
                    bytes_written=int(entry["*ViewSize"], 16)
                ) 
            
            elif method == "NtAddAtom":
                pass

            # Execute primitives
            elif method == "NtCreateThread" and entry.get("ProcessHandle_PID"):
                target_pid = int(entry.get("ProcessHandle_PID"), 16)
                context_data = self.parse_context(entry.get("*ThreadContext"))
                rip = context_data.get("rip")
                if target_pid and rip:
                    return ExecuteEvent(
                        **base_info,
                        target_pid=target_pid,
                        addresses=[rip],
                    )
                
            elif method == "NtCreateThreadEx" and entry.get("ProcessHandle_PID"):
                target_pid = int(entry.get("ProcessHandle_PID"), 16)
                start_routine = int(entry.get("*StartRoutine"), 16)
                if target_pid and start_routine:
                    return ExecuteEvent(
                        **base_info,
                        target_pid=target_pid,
                        addresses=[start_routine],
                    )
                
            elif method == "RtlCreateUserThread" and entry.get("ProcessHandle_PID"):
                target_pid = int(entry.get("ProcessHandle_PID"), 16)
                start_address = entry.get("*StartAddress", 16)
                if target_pid and start_address:
                    return ExecuteEvent(
                        **base_info,
                        target_pid=target_pid,
                        addresses=[start_address],
                    )
                
            elif method == "NtSetContextThread" and entry.get("ThreadHandle_PID"):
                target_tid = int(entry.get("ThreadHandle_TID"), 16)
                if target_tid:
                    context_data = self.parse_context(entry.get("*ThreadContext"))
                    rip = context_data.get("rip")
                    rcx = context_data.get("rcx")
                    if rip:
                        self.context_changes[target_tid]["rip"] = rip 
                    if rcx:
                        self.context_changes[target_tid]["rcx"] = rcx 
                return None
                            
            elif method == "NtSetInformationThread" and entry.get("ThreadHandle_TID"):
                target_tid = int(entry.get("ThreadHandle_TID"), 16)
                if target_tid:
                    context_data = self.parse_context(entry.get("*ThreadInformation"))
                    eip = context_data.get("eip")
                    eax = context_data.get("eax")
                    if eip:
                        self.context_changes[target_tid]["eip"] = eip 
                    if eax:
                        self.context_changes[target_tid]["eax"] = eax 
                return None

            elif method == "NtResumeThread" and entry.get("ThreadHandle_PID"):
                target_tid = int(entry.get("ThreadHandle_TID"), 16)
                if target_tid:
                    # Was the context of this thread changed?
                    context = self.context_changes.get(target_tid)
                    if context:
                        del self.context_changes[target_tid]
                        return ExecuteEvent(
                            **base_info,
                            target_pid=int(entry.get("ThreadHandle_PID"), 16),
                            addresses=[v for v in context.values() if v]
                        )
                        
        
        except (KeyError, ValueError, TypeError) as e:
            logger.debug(f"Skipping malformed log entry for {method}: {e}, event {entry.get('EventUID')}")
            return None

        return None
    
    def parse_context(self, context_str: str) -> Dict[str, int]:
        registers = {}
        matches = re.findall(r'(\w+): (\d+)', context_str)
        for (reg, val) in matches:
            registers[reg] = int(val)
        return registers
    


def stream_events(syscall_log_path) -> Iterator[BaseEvent]:
    logger.info(f"Streaming and parsing events from {syscall_log_path}...")
    parser = Parser()
    yield from parse_log(syscall_log_path, filter_cb=parser.parse_entry)