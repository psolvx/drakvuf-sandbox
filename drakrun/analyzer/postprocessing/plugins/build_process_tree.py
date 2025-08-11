import json
import logging
import networkx as nx

from ..process_tree import tree_from_log
from ..process_graph import graph_from_tree
from .plugin_base import PostprocessContext

logger = logging.getLogger(__name__)


def build_process_tree(context: PostprocessContext) -> None:
    analysis_dir = context.analysis_dir
    procmon_log_path = analysis_dir / "procmon.log"
    process_tree_path = analysis_dir / "process_tree.json"
    process_graph_path = analysis_dir / "process_graph.json"

    with procmon_log_path.open("r") as procmon_log:
        process_tree = tree_from_log(procmon_log)

    data = json.dumps(process_tree.as_dict())
    process_tree_path.write_text(data)

    graph_data = json.dumps(nx.cytoscape_data(graph_from_tree(process_tree)))
    process_graph_path.write_text(graph_data)

    context.process_tree = process_tree
    context.update_report(
        {
            "processes": [
                {
                    "seqid": process.seqid,
                    "pid": process.pid,
                    "parent_seqid": process.parent.seqid if process.parent else None,
                    "name": process.procname,
                    "args": process.args,
                    "started_at": process.ts_from,
                    "exited_at": process.ts_to,
                    "exit_code": process.exit_code,
                    "exit_code_str": process.exit_code_str,
                    "killed_by": process.killed_by,
                }
                for process in process_tree.processes
            ]
        }
    )
