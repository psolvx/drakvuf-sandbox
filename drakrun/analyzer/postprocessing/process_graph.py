import networkx as nx
from .process_tree import Process, ProcessTree
import json
import logging
import pathlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, TextIO

logger = logging.getLogger(__name__)


def graph_from_tree(process_tree: ProcessTree) -> nx.MultiDiGraph:
    logger.info("creating graph")
    process_graph = nx.MultiDiGraph()

    logger.info("adding nodes")
    for process in process_tree.processes:
        logger.info(f"adding {process.seqid}")
        process_graph.add_node(process.seqid, type="Process", data=process.as_dict())

    logger.info("adding edges")
    for process in process_tree.processes:
        if process.children:
            for child in process.children:
                logger.info(f"adding {process.seqid} -> {child.seqid}")
                process_graph.add_edge(process.seqid, child.seqid)

    return process_graph

