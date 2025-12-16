import logging

from .plugin_base import PostprocessContext

logger = logging.getLogger(__name__)

def cleanup(context: PostprocessContext) -> None:
    analysis_dir = context.analysis_dir
    drakmon_log_path = analysis_dir / "drakmon.log"
    logger.info("Running postprocessing cleanup.")
    #drakmon_log_path.unlink()
