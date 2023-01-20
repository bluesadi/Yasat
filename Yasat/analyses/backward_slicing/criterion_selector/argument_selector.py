import ailment

from .criterion_selector import CriterionSelector

class ArgumentSelector(CriterionSelector):
    
    callee_addr: int
    arg_idx: int
    
    def __init__(self, callee_addr, arg_idx):
        self.callee_addr = callee_addr
        self.arg_idx = arg_idx
    
    def select(self, expr: ailment.Expr) -> ailment.Expr:
        if isinstance(expr, ailment.statement.Call):
            if self.eval(expr.target) == self.callee_addr:
                return expr.args[self.arg_idx]
        return None