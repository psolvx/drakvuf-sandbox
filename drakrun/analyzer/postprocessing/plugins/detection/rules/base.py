from abc import ABC
from typing import List, Union, Any
from ..models import PipelineItem, Finding
from ..context import AnalysisContext
from typing import Type, Callable, Any, Dict
from ..models import PipelineItem

class BaseRule(ABC):
    """
    Base class for all rules. 
    Maintains the subscription list via the decorator.
    """
    
    # This will be populated by the @subscribe decorator
    # List[Tuple[Type, FiltersDict]]
    _subscriptions: List[Any] 

    def finalize(self, context: AnalysisContext) -> Union[None, Finding, List[Finding]]:
        return None


def subscribe(item_type: Type[PipelineItem], **filters):
    """
    Tags a method for subscription.
    
    Usage:
      @subscribe(SystemCall, method="NtWriteVirtualMemory")
      @subscribe(WriteEvent) 
    """
    def decorator(func: Callable):
        if not hasattr(func, "_subscriptions"):
            func._subscriptions = []
        
        func._subscriptions.append((item_type, filters))
        
        return func
    return decorator