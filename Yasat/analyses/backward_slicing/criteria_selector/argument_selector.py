from typing import List

import ailment
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues

from .criteria_selector import CriteriaSelector

class ArgumentSelector(CriteriaSelector):
    
    callee_addr: int
    arg_idx: int
    
    def __init__(self, callee_addr, arg_idx):
        self.callee_addr = callee_addr
        self.arg_idx = arg_idx
    
    def select_from_expr(self, expr: ailment.expression.Expression) -> List[ailment.expression.Expression]:
        if isinstance(expr, ailment.statement.Call):
            if self.eval(expr.target) == self.callee_addr:
                return [expr.args[self.arg_idx]]
        return []