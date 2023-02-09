from typing import List

import ailment

from .criteria_selector import CriteriaSelector


class ReturnSelector(CriteriaSelector):
    def select_from_stmt(
        self, expr: ailment.statement.Statement
    ) -> List[ailment.expression.Expression]:
        if isinstance(expr, ailment.statement.Return):
            return expr.ret_exprs
        return []
