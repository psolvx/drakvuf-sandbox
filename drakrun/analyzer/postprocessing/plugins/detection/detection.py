import logging

from .plugin_base import PostprocessContext
from . import rules as rules_package

import json
from pathlib import Path

from .models import SyscallLog, ApimonLog, FiletracerLog
from .context import AnalysisContext
from .engine import DetectionEngine
from .registry import RuleSet

logger = logging.getLogger(__name__)

drakmon_rules = RuleSet("drakmon")

def run_detection(context: PostprocessContext) -> None:
    analysis_dir = context.analysis_dir
    logger.info("Starting detection engine...")

    analysis_ctx = AnalysisContext(context.process_tree)    
    
    drakmon_log_path = analysis_dir / "drakmon.log"

    if drakmon_log_path.exists():
        with DetectionEngine(analysis_ctx) as engine:
            parser = LogParser()

            for rule_cls in drakmon_rules.rules:
                engine.register_rule(rule_cls())

                stream = parse_log(log_path, filter_cb=parser.parse_item)
                
                for log_obj in stream:
                    enrich_seqid(log_obj)
                    engine.process(log_obj)


    findings_data = [
        f.model_dump(mode='json', exclude_none=True) 
        for f in analysis_ctx.findings
    ]
    
    out_path = analysis_dir / "detections.json"
    with open(out_path, 'w') as f:
        json.dump(findings_data, f, indent=2)

    logger.info(f"Detection complete. Findings: {len(findings_data)}")

def enrich_seqid(log: Log):
    if log_obj.source_pid:
        proc = None
        
        if log_obj.evtid is not None:
            proc = context.process_tree.get_process_for_evtid(
                log_obj.source_pid, 
                log_obj.evtid
            )
        
        if not proc:
            # get last added process for this PID
            proc = context.process_tree.get_process(log_obj.source_pid)

        if proc:
            log_obj.source_seqid = proc.seqid
        else:
            logger.warning(f"PID {log_obj.source_pid} not in tree")
