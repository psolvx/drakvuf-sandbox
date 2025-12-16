from typing import List, Type, Any
import importlib
import pkgutil
import logging
from .rules.base import BaseRule 
from types import ModuleType


logger = logging.getLogger(__name__)

class RuleSet:
    def __init__(self, name: str):
        self.name = name
        self._rules: List[Type[BaseRule]] = []

    def register(self, rule_cls: Type[BaseRule]):
        """Decorator to add a class to this set."""
        self._rules.append(rule_cls)
        return rule_cls

    @property
    def rules(self) -> List[Type[BaseRule]]:
        return self._rules

def load_rules(package: ModuleType):
    if hasattr(package, "__path__"):
        for _, name, is_pkg in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
            try:
                importlib.import_module(name)
            except Exception as e:
                logger.error(f"Failed to load rule module {name}: {e}")

drakmon_rules = RuleSet("drakmon")
