import logging
from typing import Iterator, List
import networkx as nx 
import pathlib
from collections import defaultdict
from .events import BaseEvent
from .events import event_to_dict
from .detection import Finding, DisplayType

from drakrun.analyzer.postprocessing.process_tree import Process, ProcessTree


logger = logging.getLogger(__name__)

class ProcessGraph:
    def __init__(self):
        self._graph = nx.MultiDiGraph()
        self._summary_graph = nx.MultiDiGraph()
        self._findings: List[Finding] = []

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

    def add_process_node(self, process: Process):
        process_attributes = process.as_dict()

        process_attributes['type'] = "Process"
        process_attributes['label'] = f"{pathlib.PureWindowsPath(process.procname).name}\n({process.pid})"
        
        process_attributes['node_events'] = []

        self._graph.add_node(
            process.seqid,
            **process_attributes
        )
        logger.debug(f"Added node: {process.seqid} ({process.procname}) with attributes {list(process_attributes.keys())}")

    def add_node_event(self, process: Process, event_data: BaseEvent):
        if self._graph.has_node(process.seqid):
            self._graph.nodes[process.seqid]['node_events'].append(event_data)
            logger.info(f"Added node event to {process.seqid}: {event_data.method}")
        else:
            logger.warning(f"Could not add node event to non-existent node for seqid {process.seqid}")

    def get_process_nodes(self) -> Iterator[tuple[int, dict]]:
        for seqid, node_data in self._graph.nodes(data=True):
            if node_data and node_data.get("type") == "Process":
                yield seqid, node_data

    

    def get_in_event_edges(self, target_seqid: int) -> Iterator[BaseEvent]:
        for source, target, data in self._graph.in_edges(target_seqid, data=True):
            if data.get("type") == "interaction":
                yield data['data']

    def set_findings(self, findings: List[Finding]):
        self._findings = findings
        logger.info(f"Stored {len(findings)} findings in the process graph.")

    def create_summary_graph(self):
        self._summary_graph = nx.MultiDiGraph()

        for node_id, data in self._graph.nodes(data=True):
            node_data = data.copy()
            children_count = len([t for _, t, d in self._graph.out_edges(node_id, data=True) if d.get('type') == 'child'])
            node_data['child_count'] = children_count
            self._summary_graph.add_node(node_id, **node_data)

        for source, target, key, data in self._graph.edges(data=True, keys=True):
            if data.get("type") == "child":
                self._summary_graph.add_edge(source, target, key=key, id=f"{source}-{target}", **data)

        node_findings = defaultdict(list)
        for finding in self._findings:
            if finding.display_type == DisplayType.NODE_ATTRIBUTE:
                target_seqid = finding.primary_target_seqid
                if target_seqid is not None:
                    node_findings[target_seqid].append(finding)

        # Attach the collected node findings to the corresponding nodes in the summary graph
        for seqid, findings_list in node_findings.items():
            if self._summary_graph.has_node(seqid):
                self._summary_graph.nodes[seqid]['findings'] = [f.to_dict() for f in findings_list]
                self._summary_graph.nodes[seqid]['has_finding'] = True
                logger.info(f"Attached {len(findings_list)} node findings to node {seqid}.")

        edge_findings = defaultdict(list)
        for finding in self._findings:
            if finding.display_type == DisplayType.EDGE:
                for source_seqid in finding.all_source_seqids:
                    key = (source_seqid, finding.primary_target_seqid, finding.detection_name, finding.pattern)
                    edge_findings[key].append(finding)

        # Create one aggregated detection edge for each group of edge findings
        for (source_seqid, target_seqid, det_name, pattern), findings_list in edge_findings.items():
            count = len(findings_list)
            label = f"{pattern} (x{count})"

            if source_seqid is None or target_seqid is None:
                logger.warning(f"Skipping edge for detection '{det_name}' due to missing source/target seqid.")
                continue
            
            if not self._summary_graph.has_node(source_seqid) or not self._summary_graph.has_node(target_seqid):
                logger.warning(f"Skipping edge for detection '{det_name}': source/target node not in graph.")
                continue
            
            edge_key = f"detection_{det_name}_{pattern}_{source_seqid}_{target_seqid}"

            self._summary_graph.add_edge(
                source_seqid, target_seqid,
                type="detection",
                label=label,
                key=edge_key,
                id=edge_key,
                data={"findings": [f.to_dict() for f in findings_list]}
            )

        logger.info("Summary graph created with aggregated detection edges and node attributes.")

    def to_cytoscape_data(self) -> dict:
        """Create a summary graph and convert it to Cytoscape JSON format."""
        self.create_summary_graph()
        prepare_graph_for_json_export(self._summary_graph)
        return nx.cytoscape_data(self._summary_graph)


def graph_from_tree(process_tree: ProcessTree) -> ProcessGraph:
    process_graph = ProcessGraph()

    # Add process nodes
    for process in process_tree.processes:
        process_graph.add_process_node(process)

    # Add child process edges
    for process in process_tree.processes:
        if process.parent:
            process_graph.add_child_edge(process.parent, process)
            
    return process_graph

def prepare_graph_for_json_export(graph: nx.Graph) -> nx.Graph:
    for node_id, node_data in graph.nodes(data=True):
        if 'node_events' in node_data:
            node_data['node_events'] = [
                event_to_dict(event) for event in node_data['node_events']
            ]
    if graph.is_multigraph():
        for u, v, key, data in graph.edges(data=True, keys=True):
            for attr_key, value in data.items():
                if isinstance(value, BaseEvent):
                    graph.edges[u, v, key][attr_key] = event_to_dict(value)
                    logger.info(f"converted to dict: {u} {v} {key} {attr_key}")

    return graph
