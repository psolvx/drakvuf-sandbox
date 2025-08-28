from .process_graph import ProcessGraph
import logging
from .events import AllocateEvent, WriteEvent, ExecuteEvent

logger = logging.getLogger(__name__)

class DetectionEngine:
    def __init__(self, graph: ProcessGraph):
        self._graph = graph
        self._detections = []

    def run(self):
        for process in self._graph.get_process_nodes():
            target_seqid = process['data'].get("seqid")
            incoming_edges = self._graph.get_in_event_edges(target_seqid)
            allocations = [e['data'] for e in incoming_edges if isinstance(e['data'], AllocateEvent)]
            writes = [e['data'] for e in incoming_edges if isinstance(e['data'], WriteEvent)]
            executes = [e['data'] for e in incoming_edges if isinstance(e['data'], ExecuteEvent)]

            self.correlate_primitives(target_seqid, allocations, writes, executes)

    def correlate_primitives(self, target_seqid, allocations, writes, executes):
        for exec_event in executes:
            for write_event in writes:
                if self.is_write_exec_match(write_event, exec_event):
                    logger.info(f"write+exec detection {exec_event.source_pid} -> {exec_event.target_pid}")
                    for alloc_event in allocations:
                        if self.is_alloc_write_match(alloc_event, write_event):
                            logger.info(f"alloc+write+exec detection {exec_event.source_pid} -> {exec_event.target_pid}")

    def is_write_exec_match(self, write, execute):
        return any(address in range(write.address, write.address + write.bytes_written) for address in execute.addresses)

    def is_alloc_write_match(self, alloc, write):
        return any(address in range(alloc.address, alloc.address + alloc.size) for address in range(write.address, write.address + write.bytes_written))

    def is_alloc_exec_match(self, alloc, execute):
        return any(address in range(alloc.address, alloc.address + alloc.size) for address in execute.addresses)
