from collections import deque, defaultdict
import inspect
import logging
from typing import List, Type, Any, Union
from .models import PipelineItem, Finding, Event

logger = logging.getLogger(__name__)

class DetectionEngine:
    def __init__(self, context):
        self.context = context
        self.queue = deque()
        self.rules = [] 
        
        self._subscribers = defaultdict(list)

    
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            self.finish()
        except Exception as e:
            logger.error(f"Error during engine finalization: {e}")
        return False

    def register_rule(self, rule_instance: Any):
        """Register a rule instance and its subscriptions."""
        self.rules.append(rule_instance)
        rule_name = type(rule_instance).__name__
        logger.info(f"Registering rule: {rule_name}")

        subscription_count = 0
        for name, method in inspect.getmembers(rule_instance, predicate=inspect.ismethod):
            if hasattr(method, "_subscriptions"):
                for (item_type, filters) in method._subscriptions:
                    self._subscribers[item_type].append({
                        "filters": filters,
                        "handler": method,
                        "rule_name": rule_name,
                        "method_name": name
                    })
                    filter_str = f" with filters {filters}" if filters else ""
                    logger.debug(f"  - {rule_name}.{name} -> {item_type.__name__}{filter_str}")
                    subscription_count += 1

        logger.info(f"Rule {rule_name} registered with {subscription_count} subscription(s)")

    def process(self, item: PipelineItem):
        """Main entry point for streaming logs."""
        self.queue.append(item)
        self._drain()

    def finish(self):
        logger.info("Finalizing rules...")
        
        for rule in self.rules:
            try:
                results = rule.finalize(self.context)
                if results:
                    self._process_results(results)
                    
            except Exception as e:
                logger.error(f"Error finalizing rule {type(rule).__name__}: {e}")

        self._drain()

    def _drain(self):
        """Depth-First processing of the queue."""
        while self.queue:
            item = self.queue.popleft()
            item_type = type(item)

            # Look for subscribers to this type and parent types
            candidates = []
            for cls in item_type.__mro__:
                if cls in self._subscribers:
                    candidates.extend(self._subscribers[cls])

            matched_count = 0
            for sub in candidates:
                filters = sub["filters"]
                handler = sub["handler"]
                rule_name = sub["rule_name"]
                method_name = sub["method_name"]

                if filters:
                    is_match = True
                    for key, val in filters.items():
                        item_val = getattr(item, key, None)
                        if item_val != val:
                            is_match = False
                            break
                    if not is_match:
                        continue

                matched_count += 1

                try:
                    results = handler(item, self.context)
                    if results:
                        logger.info(f"Rule {rule_name}.{method_name} produced: {type(results).__name__ if not isinstance(results, list) else f'{len(results)} items'}")
                        logger.debug(f"Results: {results}")
                        self._process_results(results)

                except Exception as e:
                    logger.exception(f"Error in rule {rule_name}.{method_name}: {e}")


    def _process_results(self, results: Union[PipelineItem, List[PipelineItem]]):
        if not isinstance(results, list):
            results = [results]

        items_to_queue = []
        findings_count = 0

        for res in results:
            if isinstance(res, Finding):
                self.context.findings.append(res)
                findings_count += 1
                logger.info(f"Finding added: {res.title} (confidence: {res.confidence})")

            elif isinstance(res, PipelineItem):
                items_to_queue.append(res)
                logger.debug(f"Queueing {type(res).__name__} for further processing")

        if items_to_queue:
            self.queue.extendleft(reversed(items_to_queue))
            logger.debug(f"Added {len(items_to_queue)} item(s) to processing queue")