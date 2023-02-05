from typing import Union, Set, Optional

import claripy

class MultiValues:
    
    def __init__(self, values: Union[claripy.ast.Base, Set[claripy.ast.Base]]):
        self.values = {values} if isinstance(values, claripy.ast.Base) else values
    
    def __iter__(self):
        return iter(self.values)
    
    @property
    def one_concrete(self) -> Optional[claripy.ast.Base]:
        for v in self.values:
            if v.concrete:
                return v
        return None