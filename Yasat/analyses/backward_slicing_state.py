from typing import Set, List, Tuple

from ailment import Block
from ailment.statement import Statement
import claripy

from .backward_slicing import SlicingCriterion

class BackwardSlicingState:
    
    block: Block
    addr: int
    
    slicing_criterion: SlicingCriterion
    
    _tracking_asts: Set[Tuple[claripy.BV, List[Statement]]]
    
    def __init__(self, block: Block):
        self.block = block
        self.addr = block.addr
        
    def merge(self, *others):
        state = self.copy()
        return state
    
    def copy(self):
        return self
    
    def update_asts(self, new_def):
        pass
    
    def __eq__(self, another: object) -> bool:
        if isinstance(another, BackwardSlicingState):
            return self.block == another.block and \
                self.addr == another.addr
                
    def __hash__(self) -> int:
        pass