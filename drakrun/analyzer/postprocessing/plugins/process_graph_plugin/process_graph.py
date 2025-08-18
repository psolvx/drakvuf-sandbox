import logging
import networkx as nx 
import pathlib
from collections import defaultdict

from drakrun.analyzer.postprocessing.process_tree import Process, ProcessTree


logger = logging.getLogger(__name__)

class ProcessGraph:
    """A wrapper around a NetworkX graph"""

    def __init__(self):
        self._graph = nx.MultiDiGraph()
        self._summary_graph = nx.MultiDiGraph()

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
            key=f"interaction_{event_data.get('timestamp')}", # A unique key
            type="interaction",
            data=event_data
        )
        logger.info(f"Added event edge: {source_process.seqid} -> {target_process.seqid} ({technique})")

    def generate_summary_graph(self):
        """"""
        for node, data in self._graph.nodes(data=True):
            self._summary_graph.add_node(node, **data)

        edge_groups = defaultdict(list)

        for source ,target, data in self._graph.edges(data=True):
            edge_groups[(source, target)].append(data)

        for (source, target), edges in edge_groups.items():
            child_edge = [e for e in edges if e.get("type") == "child"]
            interaction_edges = [e for e in edges if e.get("type") != "child"]

            if child_edge:
                self._summary_graph.add_edge(source, target, type="child", label="child")

            if interaction_edges:
                interaction_types = sorted(list(set(e['data']['event_type'] for e in interaction_edges)))

                label = ', '.join(interaction_types)

                self._summary_graph.add_edge(source, target, type="interaction", label=label)


    def to_cytoscape_data(self) -> dict:
        """Generate a summary graph and convert to Cytoscape JSON format."""
        self.generate_summary_graph()
        return nx.cytoscape_data(self._summary_graph)


def graph_from_tree(process_tree: ProcessTree) -> ProcessGraph:
    process_graph = ProcessGraph()

    # Add process  nodes
    for process in process_tree.processes:
        process_graph.add_process_node(process)

    # Add child process edges
    for process in process_tree.processes:
        if process.parent:
            process_graph.add_child_edge(process.parent, process)
            
    return process_graph