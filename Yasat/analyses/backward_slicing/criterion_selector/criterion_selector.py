from typing import Optional

import ailment

class CriterionSelector:
    
    def __init__(self):
        self.analysis = None
        
    def hook(self, analysis):
        self.analysis = analysis
        
    def eval(self, expr) -> Optional[int]:
        expr = self.analysis._engine._expr(expr)
        if expr.concrete:
            return expr._model_concrete.value
        return None
    
    def select(self, expr: ailment.Expr) -> ailment.Expr:
        raise NotImplementedError('select() is not implemented.')