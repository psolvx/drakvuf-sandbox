from .process_graph import graph_from_tree
from .parser import stream_events
from .detection import DetectionEngine
from drakrun.analyzer.postprocessing.plugins.plugin_base import PostprocessContext
import logging
import json

logger = logging.getLogger(__name__)


def build_process_graph(context: PostprocessContext) -> None:
    if not hasattr(context, 'process_tree'):
        logger.error("Process tree not found in context. Ensure 'build_process_tree' runs first.")
        return

    analysis_dir = context.analysis_dir
    process_graph_path = analysis_dir / "process_graph.json"
    syscall_log_path = analysis_dir / "syscall.log"
    apimon_log_path = analysis_dir / "apimon.log"
    filetracer_log_path = analysis_dir / "filetracer.log"
    log_paths = [syscall_log_path, apimon_log_path, filetracer_log_path]
    process_tree = context.process_tree

    logger.info("Building process graph...")
    
    process_graph = graph_from_tree(process_tree)

    # Add events
    for event in stream_events(log_paths):
        source_process = process_tree.get_process_for_evtid(event.source_pid, event.evtid)
        if not source_process:
            logger.error(f"Failed to get process for pid: {event.source_pid}, evtid {hex(event.evtid)}")
            continue

        event.source_seqid = source_process.seqid

        if event.target_pid: # This is a process-to-process interaction
            target_process = process_tree.get_process_for_evtid(event.target_pid, event.evtid)
            if not target_process:
                logger.error(f"Failed to get process for pid: {event.target_pid}, evtid {hex(event.evtid)}")
                continue
            event.target_seqid = target_process.seqid
            process_graph.add_event_edge(source_process, target_process, event)
        else: # This is a node-attached event
            process_graph.add_node_event(source_process, event)

    # Run detections on the graph with events
    logger.info("running detections")
    de = DetectionEngine(process_graph)
    findings = de.run()

    process_graph.set_findings(findings)

    # Create summary graph, convert it to Cytoscape format and save
    try:
        graph_data = json.dumps(process_graph.to_cytoscape_data())
        process_graph_path.write_text(graph_data)
        logger.info("Process graph built successfully.")
    except Exception as e:
        logger.error(f"Failed to serialize process graph to Cytoscape JSON: {e}")
