from .process_graph import graph_from_tree
from analyzer.postprocessing.plugins.plugin_base import PostprocessContext
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
    
    logger.info("Building process graph...")
    
    process_graph = graph_from_tree(context.process_tree)

    # Convert to Cytoscape format and save
    try:
        graph_data = json.dumps(process_graph.to_cytoscape_data())
        process_graph_path.write_text(graph_data)
        logger.info("Process graph built successfully.")
    except Exception as e:
        logger.error(f"Failed to serialize process graph to Cytoscape JSON: {e}")
