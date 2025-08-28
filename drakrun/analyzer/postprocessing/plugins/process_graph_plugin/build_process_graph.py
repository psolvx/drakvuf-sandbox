from .process_graph import graph_from_tree
from .parser import stream_events
from .detection import DetectionEngine
from drakrun.analyzer.postprocessing.plugins.plugin_base import PostprocessContext
import logging
import json

logger = logging.getLogger(__name__)


def build_process_graph(context: PostprocessContext) -> None:
    # Check if the process tree was created by the previous plugin and is in the context
    if not hasattr(context, 'process_tree'):
        logger.error("Process tree not found in context. Ensure 'build_process_tree' runs first.")
        return

    analysis_dir = context.analysis_dir
    process_graph_path = analysis_dir / "process_graph.json"
    syscall_log_path = analysis_dir / "syscall.log"
    process_tree = context.process_tree

    logger.info("Building process graph...")
    
    process_graph = graph_from_tree(process_tree)

    # Add events
    for event in stream_events(syscall_log_path):
        source_process = process_tree.get_process_for_evtid(event.source_pid, event.evtid)
        if not source_process:
            logger.error("Failed to get process for pid: {event.source_pid}, evtid {event.evtid}")
            continue

        target_process = process_tree.get_process_for_evtid(event.target_pid, event.evtid)
        if not target_process:
            logger.error("Failed to get process for pid: {event.target_pid}, evtid {event.evtid}")
            continue

        process_graph.add_event_edge(source_process, target_process, event)

    # Run detections on the graph with events
    logger.info("running detections")
    de = DetectionEngine(process_graph)
    de.run()

    # Create summary graph, convert it to Cytoscape format and save
    try:
        # doesnt work yet. events are not serializable
        graph_data = json.dumps(process_graph.to_cytoscape_data())
        process_graph_path.write_text(graph_data)
        logger.info("Process graph built successfully.")
    except Exception as e:
        logger.error(f"Failed to serialize process graph to Cytoscape JSON: {e}")
