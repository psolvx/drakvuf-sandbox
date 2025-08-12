import logging
import networkx as nx 
import pathlib

from analyzer.postprocessing.process_tree import Process, ProcessTree


logger = logging.getLogger(__name__)

class ProcessGraph:
    """A wrapper around a NetworkX graph"""

    def __init__(self):
        self._graph = nx.MultiDiGraph()

    def add_process_node(self, process: Process):
        """Adds a process to the graph with consistent attributes."""
        self._graph.add_node(
            process.seqid,
            type="Process",
            label=f"{pathlib.PureWindowsPath(process.procname).name}\n({process.pid})",
            data=process.as_dict()
        )
        logger.debug(f"Added node: {process.seqid} ({process.procname})")

    def add_child_edge(self, parent: Process, child: Process):
        """Adds a standard parent-child edge."""
        self._graph.add_edge(
            parent.seqid,
            child.seqid,
            key="child",
            type="child",
            label="child"
        )
        logger.debug(f"Added child edge: {parent.seqid} -> {child.seqid}")
        
    def add_event_edge(self, source_process: Process, target_process: Process, event_data: dict):
        technique = event_data.get("technique", "UNKNOWN")
        self._graph.add_edge(
            source_process.seqid,
            target_process.seqid,
            key=f"INJECT_{technique}_{event_data.get('timestamp')}", # A unique key
            type="INJECTION_PRIMITIVE",
            label=technique,
            data=event_data
        )
        logger.info(f"Added event edge: {source_process.seqid} -> {target_process.seqid} ({technique})")


    def to_cytoscape_data(self) -> dict:
        """Serializes the internal graph to the Cytoscape JSON format."""
        return nx.cytoscape_data(self._graph)


def graph_from_tree(process_tree: ProcessTree, context) -> ProcessGraph:
    process_graph = ProcessGraph()

    # Add process  nodes
    for process in process_tree.processes:
        process_graph.add_process_node(process)

    # Add child process edges
    for process in process_tree.processes:
        if process.parent:
            process_graph.add_child_edge(process.parent, process)
            
    return process_graph