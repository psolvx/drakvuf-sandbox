from abc import ABC, abstractmethod
from collections import defaultdict
from enum import Enum
import pathlib
from typing import Any, Dict, Iterator, List, TYPE_CHECKING, Optional
import logging
from .events import AllocateEvent, WriteEvent, ExecuteEvent, BaseEvent, FileTaskFolderEvent, TaskRegisterEvent, event_to_dict
if TYPE_CHECKING:
    from .process_graph import ProcessGraph 

logger = logging.getLogger(__name__)

class DisplayType(Enum):
    EDGE = "edge"
    NODE_ATTRIBUTE = "node_attribute" 
    NODE = "node"

class Finding:
    def __init__(self, 
                detection_name: str, 
                display_type: DisplayType,
                pattern: str,
                correlated_events: List[BaseEvent]):

        self.detection_name = detection_name
        self.display_type = display_type
        self.pattern = pattern
        self.correlated_events = correlated_events
        self.primary_target_seqid_override = None

    @property
    def all_source_seqids(self) -> List[int]:
        return sorted(list({evt.source_seqid for evt in self.correlated_events if evt.source_seqid}))

    @property
    def primary_target_seqid(self) -> Optional[int]:
        if self.primary_target_seqid_override is not None:
            return self.primary_target_seqid_override
        # Assumes all events in a finding share the same target
        if self.correlated_events:
            return self.correlated_events[0].target_seqid
        return None

    def __repr__(self):
        return (f"target={self.primary_target_seqid}, events={[(e.source_pid, e.method, hex(e.evtid)) for e in self.correlated_events]})")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detection_name": self.detection_name,
            "target_seqid": self.primary_target_seqid,
            "pattern": self.pattern,
            "correlated_events": [event_to_dict(event) for event in self.correlated_events]
        }
    

class BaseDetection(ABC):
    def __init__(self, graph: 'ProcessGraph'):
        self._graph = graph
        self.name = "Base Detection"

    @abstractmethod
    def run(self) -> Iterator[Finding]:
        """
        Runs the detection logic and yields Finding objects.
        """
        pass


class ProcessInjectionDetection(BaseDetection):
    def __init__(self, graph: 'ProcessGraph'):
        super().__init__(graph)
        self.name = "Process Injection"

    def run(self) -> Iterator[Finding]:
        logger.info(f"Running '{self.name}' detection...")
        
        for target_seqid, node_data in self._graph.get_process_nodes():

            incoming_events = list(self._graph.get_in_event_edges(target_seqid))
            
            allocations = [evt for evt in incoming_events if isinstance(evt, AllocateEvent)]

            incoming_events_with_source = list(self._graph.get_in_event_edges(target_seqid))
            
            allocations = [evt for evt in incoming_events_with_source if isinstance(evt, AllocateEvent)]
            writes = [evt for evt in incoming_events_with_source if isinstance(evt, WriteEvent)]
            executes = [evt for evt in incoming_events_with_source if isinstance(evt, ExecuteEvent)]

            yield from self.correlate_primitives(target_seqid, allocations, writes, executes)


    def correlate_primitives(self, target_seqid: int, allocations: List, writes: List, executes: List) -> Iterator[Finding]:
        alloc_write_pairs = [(a, w) for a in allocations for w in writes if self.is_alloc_write_match(a, w)]
        write_exec_pairs = [(w, e) for w in writes for e in executes if self.is_write_exec_match(w, e)]
        alloc_exec_pairs = [(a, e) for a in allocations for e in executes if self.is_alloc_exec_match(a, e)]

        for (a, w1) in alloc_write_pairs:
            for (w2, e) in write_exec_pairs:
                if w1 == w2: 
                    yield Finding(self.name, DisplayType.EDGE,  pattern="Alloc->Write->Exec", correlated_events=[a, w1, e])
                    alloc_write_pairs.remove((a, w1))
                    write_exec_pairs.remove((w2, e))
                    alloc_exec_pairs.remove((a, e))

        for a, w in alloc_write_pairs:
            yield Finding(self.name, DisplayType.EDGE, pattern="Alloc->Write", correlated_events=[a, w])

        for w, e in write_exec_pairs:
            yield Finding(self.name, DisplayType.EDGE, pattern="Write->Exec", correlated_events=[w, e])

        for a, e in alloc_exec_pairs:
            yield Finding(self.name, DisplayType.EDGE, pattern="Alloc->Exec", correlated_events=[a, e])

    def is_write_exec_match(self, write: WriteEvent, execute: ExecuteEvent) -> bool:
        write_end = write.address + write.bytes_written
        return any(write.address <= addr < write_end for addr in execute.addresses)

    def is_alloc_write_match(self, alloc: AllocateEvent, write: WriteEvent) -> bool:
        return max(alloc.address, write.address) < min(alloc.address + alloc.size, write.address + write.bytes_written)

    def is_alloc_exec_match(self, alloc: AllocateEvent, execute: ExecuteEvent) -> bool:
        alloc_end = alloc.address + alloc.size
        return any(alloc.address <= addr < alloc_end for addr in execute.addresses)
    


class ScheduledTaskDetection(BaseDetection):
    def __init__(self, graph: 'ProcessGraph'):
        super().__init__(graph)
        self.name = "Scheduled Task Creation"

    def run(self) -> Iterator[Finding]:
        logger.info(f"Running '{self.name}' detection...")

        api_events_by_name = defaultdict(list)
        file_events_by_name = defaultdict(list)

        for seqid, node_data in self._graph.get_process_nodes():
            for event in node_data.get('node_events', []):
                if isinstance(event, TaskRegisterEvent):
                    api_events_by_name[event.task_name].append(event)
                elif isinstance(event, FileTaskFolderEvent): # Using the base class
                    # Extract task name from file path
                    task_name = pathlib.PureWindowsPath(event.file_name).name
                    file_events_by_name[task_name].append(event)

        # Correlate the groups
        # Find task names that appear in both API calls and file events
        common_task_names = set(api_events_by_name.keys()) & set(file_events_by_name.keys())

        for task_name in common_task_names:
            # For each matched task, create one finding that combines all related events.
            api_events = api_events_by_name[task_name]
            file_events = file_events_by_name[task_name]
            
            # All API events for the same task will have the same source process
            source_process_seqid = api_events[0].source_seqid if api_events else None

            finding = Finding(
                detection_name=self.name,
                display_type=DisplayType.NODE_ATTRIBUTE,
                pattern=f"Task '{task_name}' Created",
                correlated_events=api_events + file_events
            )
            
            finding.primary_target_seqid_override = source_process_seqid
            
            yield finding
                    

class DetectionEngine:
    def __init__(self, graph: 'ProcessGraph'):
        self._graph = graph
        self._detections: List[Finding] = []
        
        self._strategies: List[BaseDetection] = [
            ProcessInjectionDetection(self._graph),
            ScheduledTaskDetection(self._graph)
        ]

    def run(self) -> List[Finding]:
            all_findings = []
            for strategy in self._strategies:
                try:
                    findings = list(strategy.run())
                    if findings:
                        logger.info(f"'{strategy.name}' found {len(findings)} potential finding(s).")
                        for f in findings:
                            logger.info(f)
                        all_findings.extend(findings)
                except Exception as e:
                    logger.error(f"Error running detection '{strategy.name}': {e}", exc_info=True)
            
            logger.info(f"Detection engine finished. Total findings: {len(all_findings)}")
            self._detections = all_findings
            return self._detections

    def get_findings(self) -> List[Finding]:
        return self._detections



