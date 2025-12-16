import logging
from typing import Dict, Set, Tuple, Optional
from intervaltree import IntervalTree, Interval
from ..registry import drakmon_rules
from .base import BaseRule, subscribe
from ..models import WriteEvent, ExecuteEvent, Finding
from ..context import AnalysisContext

logger = logging.getLogger(__name__)


@drakmon_rules.register
class ProcessInjectionRule(BaseRule):
    """Detects process injection by tracking write operations followed by code execution."""

    def __init__(self):
        super().__init__()
        # {target_pid: IntervalTree}
        self.dirty_memory: Dict[int, IntervalTree] = {}

        # {(source_pid, target_pid, address)}
        self.reported_injections: Set[Tuple[int, int, int]] = set()

    @subscribe(WriteEvent)
    def track_write(self, event: WriteEvent, context: AnalysisContext) -> None:
        if event.source_pid == event.target_pid:
            return

        if event.bytes_written <= 0:
            return

        target_pid = event.target_pid

        if target_pid not in self.dirty_memory:
            self.dirty_memory[target_pid] = IntervalTree()

        # Add interval [start, end) with the WriteEvent as data
        start = event.address
        end = event.address + event.bytes_written
        self.dirty_memory[target_pid].addi(start, end, event)

        logger.debug(
            f"Tracked dirty memory: PID {event.source_pid} -> PID {target_pid} "
            f"at 0x{start:x}-0x{end:x} ({event.bytes_written} bytes) via {event.method}"
        )

    @subscribe(ExecuteEvent)
    def detect_injection(self, event: ExecuteEvent, context: AnalysisContext) -> Optional[Finding]:
        target_pid = event.target_pid

        if target_pid not in self.dirty_memory:
            return None

        tree = self.dirty_memory[target_pid]

        for exec_address in event.addresses:
            overlapping = tree.at(exec_address)

            if overlapping:
                # Get the first matching interval's data (WriteEvent)
                interval = overlapping.pop()
                write_event = interval.data

                # Avoid duplicate findings for the same injection
                finding_key = (write_event.source_pid, target_pid, exec_address)
                if finding_key in self.reported_injections:
                    continue

                self.reported_injections.add(finding_key)

                source_proc = context.process_tree.get_process(write_event.source_pid)
                target_proc = context.process_tree.get_process(target_pid)

                source_name = source_proc.procname if source_proc else f"PID:{write_event.source_pid}"
                target_name = target_proc.procname if target_proc else f"PID:{target_pid}"

                description = (
                    f"Process '{source_name}' (PID {write_event.source_pid}) wrote {write_event.bytes_written} bytes "
                    f"to '{target_name}' (PID {target_pid}) at address 0x{exec_address:x} using {write_event.method}, "
                    f"which was then executed via {event.method}."
                )

                confidence = "Medium"

                logger.info(f"Injection detected: {description}")

                return Finding(
                    title=f"Process Injection: {source_name} -> {target_name}",
                    description=description,
                    confidence=confidence,
                    # Event fields
                    source_pid=write_event.source_pid,
                    evtid=event.evtid,
                    method=f"{write_event.method}+{event.method}",
                    target_pid=event.target_pid,
                    source_seqid=write_event.source_seqid,
                    target_seqid=event.target_seqid,
                    related_events=[write_event, event]

                )

        return None
