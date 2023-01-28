from typing import Optional, List

import ailment
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues

class CriteriaSelector:
    
    def __init__(self):
        self.analysis = None
        
    def hook(self, analysis):
        self.analysis = analysis
        
    def eval(self, expr: MultiValues) -> Optional[int]:
        expr = self.analysis._engine._expr(expr)
        for expr_v in next(expr.values()):
            if expr_v.concrete:
                return expr_v._model_concrete.value
        return None
    
    def select_from_expr(self, expr: ailment.expression.Expression) -> List[ailment.expression.Expression]:
        return []
    
    def select_from_stmt(self, stmt: ailment.statement.Statement) -> List[ailment.expression.Expression]:
        return []