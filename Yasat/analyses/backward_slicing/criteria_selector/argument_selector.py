from typing import List

import ailment
import claripy

from .criteria_selector import CriteriaSelector


class ArgumentSelector(CriteriaSelector):
    callee_addr: int
    arg_idx: int

    def __init__(self, callee_addr, arg_idx):
        self.callee_addr = callee_addr
        self.arg_idx = arg_idx

    def select_from_expr(
        self, expr: ailment.expression.Expression
    ) -> List[ailment.expression.Expression]:
        if isinstance(expr, ailment.statement.Call):
            v = self.eval(expr.target).one_concrete
            if isinstance(v, claripy.ast.BV) and v._model_concrete.value == self.callee_addr:
                if expr.args is not None and len(expr.args) > self.arg_idx:
                    return [expr.args[self.arg_idx]]
        return []
