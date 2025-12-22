import logging
from pathlib import Path
import msgspec

from ..plugin_base import PostprocessContext
from . import rules as rules_package
from .context import AnalysisContext
from .engine import DetectionEngine
from .registry import RuleSet, load_rules, drakmon_rules
from .models import Log
from .parser import LogParser

logger = logging.getLogger(__name__)

def run_detections(context: PostprocessContext) -> None:
    analysis_dir = context.analysis_dir
    logger.info("Starting detection engine...")

    # Load all rule modules to trigger @drakmon_rules.register decorators
    load_rules(rules_package)

    analysis_ctx = AnalysisContext(context.process_tree)

    drakmon_log_path = analysis_dir / "drakmon.log"

    if drakmon_log_path.exists():
        with DetectionEngine(analysis_ctx) as engine:
            parser = LogParser()

            logger.info(f"Registering {len(drakmon_rules.rules)} rules")
            for rule_cls in drakmon_rules.rules:
                engine.register_rule(rule_cls())

            logger.info("Processing log file...")
            stream = parser.parse_file(drakmon_log_path)

            for log_obj in stream:
                enrich_seqid(log_obj, analysis_ctx)
                engine.process(log_obj)


    out_path = analysis_dir / "detections.json"

    encoder = msgspec.json.Encoder()
    json_bytes = encoder.encode(analysis_ctx.findings)

    with open(out_path, 'wb') as f:
        f.write(json_bytes)

    logger.info(f"Detection complete. Findings: {len(analysis_ctx.findings)}")

def enrich_seqid(log: Log, analysis_ctx: AnalysisContext):
    """Enrich log with source_seqid from process tree."""
    pid = log.raw.get("PID")
    if not pid:
        return

    evtid = log.raw.get("EventUID")
    proc = None

    # Try to find process by event ID first
    if evtid is not None:
        evtid_int = int(evtid, 16) if isinstance(evtid, str) and evtid.startswith("0x") else int(evtid)
        proc = analysis_ctx.process_tree.get_process_for_evtid(pid, evtid_int)

    # Fallback to getting the last process for this PID
    if not proc:
        proc = analysis_ctx.process_tree.get_process(pid)

    if proc:
        log.source_seqid = proc.seqid
    else:
        logger.debug(f"PID {pid} not found in process tree")
