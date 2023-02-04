from typing import List

import ailment
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues

from .criteria_selector import CriteriaSelector

class ConditionSelector(CriteriaSelector):
    
    def select_from_stmt(self, stmt: ailment.statement.Statement) -> List[ailment.expression.Expression]:
        if isinstance(stmt, ailment.Stmt.ConditionalJump):
            return [stmt.condition]
        return []