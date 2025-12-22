from collections import deque, defaultdict
import inspect
import logging
import operator
from typing import List, Type, Any, Union, Dict, Callable, Tuple, Optional
from .models import PipelineItem, Finding, Event

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

OPERATORS: Dict[str, Callable] = {
    "exact": operator.eq,
    "startswith": lambda val, target: isinstance(val, str) and val.startswith(target),
    "contains": lambda val, target: isinstance(val, str) and target in val,
    "in": lambda val, target: val in target,
    "gt": operator.gt,
    "gte": operator.ge,
    "lt": operator.lt,
    "lte": operator.le,
    "ne": operator.ne,
    "exists": lambda val, target: (val is not None) == target,
}


def parse_filter_key(key: str) -> Tuple[Tuple[str, ...], str]:
    parts = key.split("__")

    if len(parts) > 1 and parts[-1] in OPERATORS:
        op_name = parts.pop()
        path = tuple(".".join(parts).split("."))
        return path, op_name
    return tuple(".".join(parts).split(".")), "exact"

def get_nested_value(obj: Any, path_tuple: Tuple[str, ...]) -> Any:
    value = obj
    for part in path_tuple:
        if value is None: return None

        # DRAKVUF alias: if the name starts with 'ptr_', look for '*'
        actual_key = part
        if part.startswith("ptr_"):
            actual_key = "*" + part[4:]
            
        if isinstance(value, dict):
            value = value.get(actual_key, value.get(part))
        else:
            value = getattr(value, part, None)

    if isinstance(value, str):
        if value.startswith("0x") or value.startswith("-0x"):
            try: return int(value, 16)
            except ValueError: pass
        elif value.isdigit() or (value.startswith("-") and value[1:].isdigit()):
            try: return int(value)
            except ValueError: pass

    return value

class DetectionEngine:
    def __init__(self, context):
        self.context = context
        self.queue = deque()
        self.rules = []

        # Raw index: rules registered to each class (before MRO flattening)
        # type -> field -> value -> [handlers]
        self._raw_index = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))

        # Type-only handlers: type -> [handlers]
        self._raw_type_only = defaultdict(list)

        # Flattened cache: concrete type -> (field_index, type_only_handlers, indexed_fields)
        # Built on-demand by combining rules from the type's MRO
        self._mro_cache = {}

    
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            self.finish()
        except Exception as e:
            logger.error(f"Error during engine finalization: {e}")
        return False

    def register_rule(self, rule_instance: Any):
        self.rules.append(rule_instance)
        rule_name = type(rule_instance).__name__
        logger.info(f"Registering rule: {rule_name}")

        subscription_count = 0
        for name, method in inspect.getmembers(rule_instance, predicate=inspect.ismethod):
            if hasattr(method, "_subscriptions"):
                for (item_type, filters) in method._subscriptions:
                    parsed_filters = []
                    primary_index_field = None
                    primary_index_value = None

                    if filters:
                        for key, value in filters.items():
                            path_tuple, op_name = parse_filter_key(key)

                            is_top_level = len(path_tuple) == 1
                        
                            if op_name == "exact" and is_top_level and (primary_index_field is None or path_tuple[0] == "method"):
                                # prefer index on method 
                                if primary_index_field:
                                    parsed_filters.append(((primary_index_field,), "exact", primary_index_value))
                                
                                primary_index_field = path_tuple[0]
                                primary_index_value = value
                            else:
                                parsed_filters.append((path_tuple, op_name, value))

                    handler_info = {
                        "filters": filters,
                        "parsed_filters": parsed_filters,
                        "handler": method,
                        "rule_name": rule_name,
                        "method_name": name
                    }

                    if primary_index_field:
                        self._raw_index[item_type][primary_index_field][primary_index_value].append(handler_info)
                        logger.info(f"  - {rule_name}.{name} indexed on {primary_index_field}={primary_index_value}")
                    else:
                        self._raw_type_only[item_type].append(handler_info)
                        logger.info(f"  - {rule_name}.{name} indexed on type {item_type.__name__} (no exact filters)")

                    filter_str = f" with filters {filters}" if filters else ""
                    logger.info(f"  - {rule_name}.{name} -> {item_type.__name__}{filter_str}")
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
        """Depth-First processing of the queue with indexed filtering."""
        while self.queue:
            item = self.queue.popleft()
            item_type = type(item)

            # get candidates using primary index
            candidates = self._get_candidates(item, item_type)

            matched_count = 0
            for sub in candidates:
                handler = sub["handler"]
                rule_name = sub["rule_name"]
                method_name = sub["method_name"]
                parsed_filters = sub.get("parsed_filters", [])

                # apply other filters
                if not self._apply_filters(item, parsed_filters):
                    continue

                matched_count += 1

                try:
                    results = handler(item, self.context)
                    if results:
                        logger.debug(f"Rule {rule_name}.{method_name} produced: {type(results).__name__ if not isinstance(results, list) else f'{len(results)} items'}")
                        logger.debug(f"Results: {results}")
                        self._process_results(results)

                except Exception as e:
                    logger.exception(f"Error in rule {rule_name}.{method_name}: {e}")

    def _flatten_mro(self, leaf_type: type) -> Tuple[Dict, List[Dict], set]:
        """Flatten MRO for a concrete type - combine rules from all parent classes."""
        flat_index = defaultdict(lambda: defaultdict(list))
        flat_type_only = []
        indexed_fields = set()

        # Walk MRO and collect rules from each parent class
        for cls in leaf_type.__mro__:
            # Pull field-indexed rules from this parent
            if cls in self._raw_index:
                for field, val_map in self._raw_index[cls].items():
                    indexed_fields.add(field)
                    for val, rules in val_map.items():
                        flat_index[field][val].extend(rules)

            # Pull type-only rules from this parent
            if cls in self._raw_type_only:
                flat_type_only.extend(self._raw_type_only[cls])

            if cls is PipelineItem:
                break

        return flat_index, flat_type_only, indexed_fields


    def _get_candidates(self, item: PipelineItem, item_type: type) -> List[Dict]:
        if item_type not in self._mro_cache:
            self._mro_cache[item_type] = self._flatten_mro(item_type)

        flat_index, flat_type_only, indexed_fields = self._mro_cache[item_type]

        candidates = []
        seen_handlers = set()

        # Add type-only rules
        for handler_info in flat_type_only:
            h_id = id(handler_info["handler"])
            if h_id not in seen_handlers:
                candidates.append(handler_info)
                seen_handlers.add(h_id)

        # Add field-indexed rules
        for field_name in indexed_fields:
            # field_name is a string here (e.g. "method")
            field_value = getattr(item, field_name, None)

            if field_value in flat_index[field_name]:
                for handler_info in flat_index[field_name][field_value]:
                    h_id = id(handler_info["handler"])
                    if h_id not in seen_handlers:
                        candidates.append(handler_info)
                        seen_handlers.add(h_id)

        return candidates

    def _apply_filters(self, item: PipelineItem, parsed_filters: List[Tuple]) -> bool:
        for path_tuple, op_name, expected_value in parsed_filters:
            actual_value = get_nested_value(item, path_tuple)

            if actual_value is None:
                return op_name == "exists" and expected_value is False
            try:
                if not OPERATORS[op_name](actual_value, expected_value):
                    return False
            except TypeError:
                logger.debug(f"Type mismatch for {path_tuple}: {type(actual_value)} vs {type(expected_value)}")
                return False
        return True

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