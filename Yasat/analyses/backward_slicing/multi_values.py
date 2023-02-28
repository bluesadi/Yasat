from typing import Union, Set, Optional

import claripy


class MultiValues:
    def __init__(self, values: Union[claripy.ast.Base, Set[claripy.ast.Base]]):
        self.values = {values} if isinstance(values, claripy.ast.Base) else values
        self.values = {self._normalize(v) for v in self.values}
        assert all([isinstance(v, claripy.ast.Base) for v in self.values])
        assert len(self.values) > 0
        self.size = next(iter(self.values)).size()
        assert all([v.size() == self.size for v in self.values])

    def __iter__(self):
        return iter(self.values)

    def _normalize(self, v: claripy.ast.Base) -> claripy.ast.BV:
        if isinstance(v, claripy.ast.Bool):
            if v.op == "BoolS":
                return claripy.BVS(v.args[0], 1, explicit_name=True)
            elif v.concrete:
                return claripy.BVV(1 if v.is_true() else 0, 1)
            else:
                return claripy.If(v, claripy.BVV(1, 1), claripy.BVV(0, 1))
        return v

    @property
    def one_concrete(self) -> Optional[claripy.ast.Base]:
        for v in self.values:
            if v.concrete:
                return v
        return None
    
    def __repr__(self) -> str:
        str(self)
        
    def __str__(self) -> str:
        return f'MultiValues {self.values}'
