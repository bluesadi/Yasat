from typing import List

import ailment

from ...multi_values import MultiValues


class CriteriaSelector:
    def __init__(self):
        self.analysis = None

    def hook(self, analysis):
        self.analysis = analysis

    def eval(self, expr: MultiValues) -> MultiValues:
        return self.analysis._engine._expr(expr)

    def select_from_expr(
        self, expr: ailment.expression.Expression
    ) -> List[ailment.expression.Expression]:
        return []

    def select_from_stmt(
        self, stmt: ailment.statement.Statement
    ) -> List[ailment.expression.Expression]:
        return []
