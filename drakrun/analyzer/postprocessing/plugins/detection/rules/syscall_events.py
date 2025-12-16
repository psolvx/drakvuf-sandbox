import logging
from typing import Dict, Any, Optional
from ..models import SystemCall, AllocateEvent, WriteEvent, ExecuteEvent
from ..context import AnalysisContext
from .base import BaseRule, subscribe
from ..registry import drakmon_rules

logger = logging.getLogger(__name__)


def to_int(value: Any) -> Optional[int]:
    """Convert value to int, handling hex strings and None."""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            if value.startswith("0x"):
                return int(value, 16)
            return int(value)
        except (ValueError, AttributeError):
            return None
    return None


class _InternalSetContext:
    """Internal class to store context changes until thread is resumed."""
    def __init__(self, target_tid: int, context_data: Dict[str, int], raw_entry: Dict[str, Any]):
        self.target_tid = target_tid
        self.context_data = context_data
        self.raw_entry = raw_entry


@drakmon_rules.register
class SyscallEventSynthesizer(BaseRule):
    """Synthesizes high-level events (Allocate, Write, Execute) from syscall logs."""

    def __init__(self):
        super().__init__()
        # Store context changes (SetContext) until thread is resumed
        self.context_changes: Dict[int, _InternalSetContext] = {}

    # Allocations not used for now
    # @subscribe(SystemCall, method="NtAllocateVirtualMemory")
    # @subscribe(SystemCall, method="NtAllocateVirtualMemoryEx")
    def handle_allocate(self, log: SystemCall, context: AnalysisContext) -> Optional[AllocateEvent]:
        target_pid = to_int(log.extra.get("ProcessHandle_PID"))
        address = to_int(log.extra.get("*BaseAddress"))
        size = to_int(log.extra.get("*RegionSize"))

        if target_pid and address is not None and size is not None:
            return AllocateEvent(
                source_pid=log.raw.get("PID", 0),
                evtid=to_int(log.raw.get("EventUID", 0)) or 0,
                method=log.method,
                target_pid=target_pid,
                address=address,
                size=size,
                raw_entries=[log.raw]
            )
        return None

    @subscribe(SystemCall, method="NtWriteVirtualMemory")
    def handle_write_memory(self, log: SystemCall, context: AnalysisContext) -> Optional[WriteEvent]:
        target_pid = to_int(log.extra.get("ProcessHandle_PID"))
        address = to_int(log.args.get("BaseAddress"))
        bytes_written = to_int(log.extra.get("*NumberOfBytesWritten", 0))
        number_of_bytes_to_write = to_int(log.args.get("BufferSize", 0))
        size = bytes_written if bytes_written and bytes_written > 0 else number_of_bytes_to_write

        if target_pid and address is not None and size and size > 0:
            source_pid = log.raw.get("PID", 0)

            # Get seqids from process tree
            source_proc = context.process_tree.get_process(source_pid)
            target_proc = context.process_tree.get_process(target_pid)

            return WriteEvent(
                source_pid=source_pid,
                evtid=to_int(log.raw.get("EventUID", 0)) or 0,
                method=log.method,
                target_pid=target_pid,
                address=address,
                bytes_written=size,
                raw_entries=[log.raw],
                source_seqid=source_proc.seqid if source_proc else None,
                target_seqid=target_proc.seqid if target_proc else None,
            )
        return None

    @subscribe(SystemCall, method="NtMapViewOfSection")
    @subscribe(SystemCall, method="NtMapViewOfSectionEx")
    def handle_map_view(self, log: SystemCall, context: AnalysisContext) -> Optional[WriteEvent]:
        target_pid = to_int(log.extra.get("ProcessHandle_PID"))
        address = to_int(log.extra.get("*BaseAddress"))
        size = to_int(log.extra.get("*ViewSize"))

        if target_pid and address is not None and size is not None:
            source_pid = log.raw.get("PID", 0)

            # Get seqids from process tree
            source_proc = context.process_tree.get_process(source_pid)
            target_proc = context.process_tree.get_process(target_pid)

            return WriteEvent(
                source_pid=source_pid,
                evtid=to_int(log.raw.get("EventUID", 0)) or 0,
                method=log.method,
                target_pid=target_pid,
                address=address,
                bytes_written=size,
                raw_entries=[log.raw],
                source_seqid=source_proc.seqid if source_proc else None,
                target_seqid=target_proc.seqid if target_proc else None,
            )
        return None

    @subscribe(SystemCall, method="NtCreateThread")
    @subscribe(SystemCall, method="NtCreateThreadEx")
    def handle_create_thread(self, log: SystemCall, context: AnalysisContext) -> Optional[ExecuteEvent]:
        target_pid = to_int(log.extra.get("ProcessHandle_PID"))

        thread_context = log.extra.get("ThreadContext", {})
        start_address = (
            to_int(thread_context.get("rip")) or
            to_int(log.extra.get("*StartRoutine")) or
            to_int(log.extra.get("*StartAddress"))
        )

        if target_pid and start_address:
            source_pid = log.raw.get("PID", 0)

            # Get seqids from process tree
            source_proc = context.process_tree.get_process(source_pid)
            target_proc = context.process_tree.get_process(target_pid)

            return ExecuteEvent(
                source_pid=source_pid,
                evtid=to_int(log.raw.get("EventUID", 0)) or 0,
                method=log.method,
                target_pid=target_pid,
                addresses=[start_address],
                raw_entries=[log.raw],
                source_seqid=source_proc.seqid if source_proc else None,
                target_seqid=target_proc.seqid if target_proc else None,
            )
        return None

    @subscribe(SystemCall, method="NtSetContextThread")
    @subscribe(SystemCall, method="NtSetInformationThread")
    def handle_set_context(self, log: SystemCall, context: AnalysisContext) -> None:
        target_tid = to_int(log.extra.get("ThreadHandle_TID"))
        context_data = log.extra.get("Context", {}) or log.extra.get("Wow64Context", {})

        if target_tid and context_data:
            registers = {k.lower(): to_int(v) for k, v in context_data.items()}
            valid_registers = {
                k: v for k, v in registers.items()
                if v is not None and k in ('rip', 'rcx', 'eip', 'eax')
            }

            if valid_registers:
                self.context_changes[target_tid] = _InternalSetContext(
                    target_tid=target_tid,
                    context_data=valid_registers,
                    raw_entry=log.raw
                )

        return None

    @subscribe(SystemCall, method="NtResumeThread")
    def handle_resume_thread(self, log: SystemCall, context: AnalysisContext) -> Optional[ExecuteEvent]:
        target_pid = to_int(log.extra.get("ThreadHandle_PID"))
        target_tid = to_int(log.extra.get("ThreadHandle_TID"))

        if target_tid and target_tid in self.context_changes:
            context_change_info = self.context_changes.pop(target_tid)
            source_pid = log.raw.get("PID", 0)

            # Get seqids from process tree
            source_proc = context.process_tree.get_process(source_pid)
            target_proc = context.process_tree.get_process(target_pid) if target_pid else None

            return ExecuteEvent(
                source_pid=source_pid,
                evtid=to_int(log.raw.get("EventUID", 0)) or 0,
                method=f"{context_change_info.raw_entry.get('Method')}+{log.method}",
                target_pid=target_pid,
                target_tid=target_tid,
                addresses=list(context_change_info.context_data.values()),
                raw_entries=[context_change_info.raw_entry, log.raw],
                source_seqid=source_proc.seqid if source_proc else None,
                target_seqid=target_proc.seqid if target_proc else None,
            )

        return None

    @subscribe(SystemCall, method="NtQueueApcThread")
    @subscribe(SystemCall, method="NtQueueApcThreadEx")
    def handle_queue_apc(self, log: SystemCall, context: AnalysisContext) -> Optional[ExecuteEvent]:
        target_tid = to_int(log.extra.get("ThreadHandle_TID"))
        target_pid = to_int(log.extra.get("ThreadHandle_PID"))

        # ApcRoutine is the function pointer that will be executed
        apc_routine = to_int(log.args.get("ApcRoutine"))

        # ApcArgument1/2/3 are optional arguments passed to the APC routine
        # These can sometimes contain important addresses
        apc_arg1 = to_int(log.args.get("ApcArgument1", 0))
        apc_arg2 = to_int(log.args.get("ApcArgument2", 0))
        apc_arg3 = to_int(log.args.get("ApcArgument3", 0))

        if target_pid and apc_routine:
            source_pid = log.raw.get("PID", 0)

            # Get seqids from process tree
            source_proc = context.process_tree.get_process(source_pid)
            target_proc = context.process_tree.get_process(target_pid)
            
            addresses = [apc_routine]
            # Include non-zero arguments as they might be shellcode addresses
            if apc_arg1 and apc_arg1 > 0x10000: 
                addresses.append(apc_arg1)
            if apc_arg2 and apc_arg2 > 0x10000:
                addresses.append(apc_arg2)
            if apc_arg3 and apc_arg3 > 0x10000:
                addresses.append(apc_arg3)

            return ExecuteEvent(
                source_pid=source_pid,
                evtid=to_int(log.raw.get("EventUID", 0)) or 0,
                method=log.method,
                target_pid=target_pid,
                target_tid=target_tid,
                addresses=addresses,
                raw_entries=[log.raw],
                source_seqid=source_proc.seqid if source_proc else None,
                target_seqid=target_proc.seqid if target_proc else None,
            )

        return None