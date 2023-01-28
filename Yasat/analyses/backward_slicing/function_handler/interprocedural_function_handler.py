from typing import List

from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from angr.knowledge_plugins.functions.function import Function

from .function_handler import FunctionHandler
from ..criteria_selector import ReturnSelector

class InterproceduralFunctionHandler(FunctionHandler):
    
    def handle_local_function(self, func: Function, args: List[MultiValues]) -> MultiValues:
        bs = func.project.analyses.BackwardSlicing(func, 
                                                   criteria_selectors=[ReturnSelector()], 
                                                   preset_arguments=args)
        results = set()
        for concrete_result in bs.concrete_results:
            results.add(concrete_result.expr)
        return MultiValues(offset_to_values={0: results})