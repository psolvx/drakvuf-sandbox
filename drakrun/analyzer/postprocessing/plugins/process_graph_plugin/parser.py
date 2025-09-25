from collections import defaultdict
from dataclasses import dataclass
import logging
from typing import Dict, Any, Iterator, List, Optional

from .events import BaseEvent, AllocateEvent, WriteEvent, ExecuteEvent, FileTaskFolderEvent, TaskRegisterEvent
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

@dataclass
class _InternalSetContext:
    target_tid: int
    context_data: Dict[str, int]
    raw_entry: Dict[str, Any]

class Parser:
    def __init__(self):
        # key is tid
        self.context_changes: Dict[int, _InternalSetContext] = {}

    def parse_entry(self, entry: Dict[str, Any]) -> Optional[BaseEvent]:
        try:
            base_info = {
                "source_pid": to_int(entry.get("PID")),
                "evtid": to_int(entry.get("EventUID")),
                "method": entry.get("Method"),
            }

            plugin = entry.get("Plugin")

            if plugin == "filetracer":
                return self._parse_filetracer_log(entry, base_info)
            elif plugin == "apimon":
                return self._parse_apimon_log(entry, base_info)
            elif plugin == "syscall": 
                return self._parse_syscall_log(entry, base_info)
            
        except (KeyError, ValueError, TypeError) as e:
            logger.debug(f"Skipping malformed log entry for {entry.get('Method')}: {e}, event {entry.get('EventUID')}")

        return None
    
    def _parse_filetracer_log(self, entry: Dict[str, Any], base_info: Dict[str, Any]) -> Optional[BaseEvent]:
        method = entry.get("Method")
        file_name = entry.get("FileName")
        if not file_name:
            return None
        
        if file_name.startswith("\\??\\"):
            file_name = file_name[4:]

        if "\\system32\\tasks\\" in file_name.lower():
            is_create = method == "NtCreateFile" and "WRITE" in entry.get("DesiredAccess", "").upper()
            is_write = method == "NtWriteFile"
            
            if is_create or is_write:
                return FileTaskFolderEvent(**base_info, file_name=file_name, raw_entries=[entry])
        
        return None

    def _parse_apimon_log(self, entry: Dict[str, Any], base_info: Dict[str, Any]) -> Optional[BaseEvent]:
        method = entry.get("Method")
        if method == "ITaskFolder::RegisterTaskDefinition":
            args_list = entry.get("Arguments", [])
            task_name = None
            for arg in args_list:
                if arg.startswith("Arg1="):
                    try:
                        task_name = arg.split(':"')[1].rstrip('"')
                    except IndexError: pass
            if task_name:
                return TaskRegisterEvent(**base_info, task_name=task_name, raw_entries=[entry])
        
        return None


    def _parse_syscall_log(self, entry: Dict[str, Any], base_info: Dict[str, Any]) -> Optional[BaseEvent]:
        method = entry.get("Method")
        retval = entry.get("ReturnValue")
        if not method or retval is None:
            return None

        args = entry.get("Arguments", {})
        extra = entry.get("Extra", {})

        try:
            # Allocation primitives
            if method in ["NtAllocateVirtualMemory", "NtAllocateVirtualMemoryEx"]:
                target_pid = to_int(extra.get("ProcessHandle_PID"))
                address = to_int(extra.get("*BaseAddress"))
                size = to_int(extra.get("*RegionSize"))
                if target_pid and address is not None and size is not None:
                    return AllocateEvent(**base_info, target_pid=target_pid, address=address, size=size, raw_entries=[entry])

            # Write primitives
            elif method == "NtWriteVirtualMemory":
                target_pid = to_int(extra.get("ProcessHandle_PID"))
                address = to_int(args.get("BaseAddress"))
                bytes_written = to_int(extra.get("*NumberOfBytesWritten", 0))
                if target_pid and address is not None and bytes_written > 0:
                    return WriteEvent(**base_info, target_pid=target_pid, address=address, bytes_written=bytes_written, raw_entries=[entry])
            
            elif method in ["NtMapViewOfSection", "NtMapViewOfSectionEx"]:
                target_pid = to_int(extra.get("ProcessHandle_PID"))
                address = to_int(extra.get("*BaseAddress"))
                size = to_int(extra.get("*ViewSize"))
                if target_pid and address is not None and size is not None:
                    return WriteEvent(**base_info, target_pid=target_pid, address=address, bytes_written=size, raw_entries=[entry])

            # Execute primitives
            elif method in ["NtCreateThread", "NtCreateThreadEx", "RtlCreateUserThread"]:
                target_pid = to_int(extra.get("ProcessHandle_PID"))
                start_address = (
                    to_int(extra.get("ThreadContext", {}).get("Rip")) or
                    to_int(extra.get("*StartRoutine")) or
                    to_int(extra.get("*StartAddress"))
                )
                if target_pid and start_address:
                    return ExecuteEvent(**base_info, target_pid=target_pid, addresses=[start_address], raw_entries=[entry])

              # Set context
            elif method in ["NtSetContextThread", "NtSetInformationThread"]:
                target_tid = to_int(extra.get("ThreadHandle_TID"))
                context_data = extra.get("Context", {}) or extra.get("Wow64Context", {})

                if target_tid and context_data:
                    registers = {k.lower(): to_int(v) for k, v in context_data.items()}
                    valid_registers = {k: v for k, v in registers.items() if v is not None and k in ('rip', 'rcx', 'eip', 'eax')}

                    if valid_registers:
                        # Store the context change information
                        self.context_changes[target_tid] = _InternalSetContext(
                            target_tid=target_tid,
                            context_data=valid_registers,
                            raw_entry=entry
                        )
                return None # Nothing happens until the resume

            # Resume thread
            elif method == "NtResumeThread":
                target_pid = to_int(extra.get("ThreadHandle_PID"))
                target_tid = to_int(extra.get("ThreadHandle_TID"))

                if target_tid and target_tid in self.context_changes:
                    context_change_info = self.context_changes.pop(target_tid)
                    
                    return ExecuteEvent(
                        **base_info,
                        target_pid=target_pid,
                        # The execution addresses come from the stored context
                        addresses=list(context_change_info.context_data.values()),
                        # The evidence includes both raw log entries
                        raw_entries=[context_change_info.raw_entry, entry]
                    )

        except (KeyError, ValueError, TypeError) as e:
            logger.debug(f"Skipping malformed log entry for {method}: {e}, event {entry.get('EventUID')}")

        return None


def stream_events(log_paths: List[str]) -> Iterator[BaseEvent]:
    parser = Parser()
    for log_path in log_paths:
        if not log_path.exists():
            logger.warning(f"Log file not found, skipping: {log_path}")
            continue
        
        logger.info(f"Streaming and parsing events from {log_path}...")

        yield from parse_log(log_path, filter_cb=parser.parse_entry)