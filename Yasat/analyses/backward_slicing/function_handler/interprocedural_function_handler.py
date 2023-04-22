from typing import List, Tuple

from angr.knowledge_plugins.functions.function import Function
import claripy
import logging

from .function_handler import FunctionHandler
from ..criteria_selector import ReturnSelector
from ...multi_values import MultiValues
from ...ast_enhancer import AstEnhancer

import logging
l = logging.getLogger(__name__)

class InterproceduralFunctionHandler(FunctionHandler):
    def handle_local_function(
        self, func: Function, args: List[MultiValues]
    ) -> MultiValues:
        bs = func.project.analyses.BackwardSlicing(
            target_func=func,
            criteria_selectors=[ReturnSelector()],
            preset_arguments=args,
            call_stack=self.analysis._call_stack + [func.addr],
        )
        values = {concrete_result.expr for concrete_result in bs.concrete_results}
        return MultiValues(values) if values else None

    def handle_external_function(
        self, func: Function, args: List[Tuple[MultiValues, MultiValues]]
    ) -> MultiValues:
        return MultiValues(AstEnhancer.call(claripy.BVV(func.addr, func.project.arch.bits)))