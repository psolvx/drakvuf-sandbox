import logging
from typing import Iterator
import networkx as nx 
import pathlib
from collections import defaultdict
from .events import BaseEvent
from .events import event_to_dict

from drakrun.analyzer.postprocessing.process_tree import Process, ProcessTree


logger = logging.getLogger(__name__)

class ProcessGraph:
    def __init__(self):
        self._graph = nx.MultiDiGraph()
        self._summary_graph = nx.MultiDiGraph()

    def add_process_node(self, process: Process):
        self._graph.add_node(
            process.seqid,
            type="Process",
            label=f"{pathlib.PureWindowsPath(process.procname).name}\n({process.pid})",
            data=process.as_dict()
        )
        logger.debug(f"Added node: {process.seqid} ({process.procname})")

    def get_process_nodes(self) -> Iterator[Process]:
        for node in self._graph.nodes(data=True):
            # (seqid, data)
            process = node[1]
            if process and process.get("type") == "Process":
                yield process

    def add_child_edge(self, parent: Process, child: Process):
        self._graph.add_edge(
            parent.seqid,
            child.seqid,
            key="child",
            type="child",
            label="child"
        )
        logger.debug(f"Added child edge: {parent.seqid} -> {child.seqid}")
        
    def add_event_edge(self, source_process: Process, target_process: Process, event_data: BaseEvent):
        self._graph.add_edge(
            source_process.seqid,
            target_process.seqid,
            key="interaction_" + str(event_data.evtid), # unique key
            type="interaction",
            data=event_data
        )
        logger.info(f"Added event edge: {source_process.seqid} -> {target_process.seqid}, {event_data.method}")

    def get_in_event_edges(self, seqid: int) -> Iterator[BaseEvent]:
        events = []
        for edge in self._graph.in_edges(seqid, data=True):
            # (src, dst, data)
            event = edge[2]
            if event.get("type") == "interaction":
                events.append(event)
        return events

    def create_summary_graph(self):
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
        """Create a summary graph and convert it to Cytoscape JSON format."""
        # event edges not subscriptable
        self.create_summary_graph()
        prepare_graph_for_json_export(self._summary_graph)
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

def prepare_graph_for_json_export(graph: nx.Graph) -> nx.Graph:
    if graph.is_multigraph():
        for u, v, key, data in graph.edges(data=True, keys=True):
            for attr_key, value in data.items():
                if isinstance(value, BaseEvent):
                    graph.edges[u, v, key][attr_key] = event_to_dict(value)

    return graph