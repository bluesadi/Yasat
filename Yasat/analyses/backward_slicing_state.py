from typing import Set, List, Dict
import copy

from ailment import Block
from ailment.statement import Statement
import claripy

class SlicingTrack:
    
    def __init__(self, ast: claripy.ast.BV, path: List[Statement]):
        self.ast = ast
        self.path = path
        
    def __str__(self) -> str:
        return f'{{ast={self.ast}, path={self.path}}}'
    
    def __repr__(self) -> str:
        return str(self)
        
    def __hash__(self) -> int:
        return self.ast.__hash__() + sum(stmt.__hash__() for stmt in self.path)
    
    def __eq__(self, another: object) -> bool:
        if isinstance(another, SlicingTrack):
            return self.ast.__hash__() == another.ast.__hash__() and self.path == another.path
        return False

class BackwardSlicingState:
    
    block: Block
    addr: int
    solver: claripy.Solver
    
    changed: bool
    
    _tracks: Set[SlicingTrack]
    _concrete_tracks: Set[SlicingTrack]
    _tops: Dict[int, claripy.ast.BV]
    
    def __init__(self, analysis, block: Block):
        self.block = block
        self.addr = block.addr
        self.changed = None
        self.solver = claripy.Solver()
        
        self.analysis = analysis
        self.arch = analysis.project.arch
        
        self._tracks = set()
        self._concrete_tracks = set()
        self._tops = set()
        
    def merge(self, *others):
        state = self.copy()
        for another in others:
            state._tracks |= another._tracks
            state._concrete_tracks |= another._concrete_tracks
            state._tops |= another._tops
        return state
    
    def copy(self):
        state_copy = BackwardSlicingState(self.analysis, self.block.copy())
        state_copy._tracks = copy.deepcopy(self._tracks)
        state_copy._concrete_tracks = copy.deepcopy(self._concrete_tracks)
        state_copy._tops = copy.deepcopy(self._tops)
        return state_copy
    
    def add_track(self, ast, stmt):
        track = SlicingTrack(ast, [stmt])
        if ast.concrete:
            self._concrete_tracks.add(track)
        else:
            self._tracks.add(track)
        self.changed = True
            
    
    def update_tracks(self, old, new, stmt):
        for track in self._tracks.copy():
            old_ast = track.ast
            new_ast = track.ast.replace(old, new)
            if old_ast.__hash__() != new_ast.__hash__():
                self.changed = True
                if new_ast.concrete:
                    self._tracks.remove(track)
                    self._concrete_tracks.add(track)
                track.path.append(stmt)
                track.ast = new_ast
        
    def top(self, bits: int):
        if bits in BackwardSlicingState._tops:
            return BackwardSlicingState._tops[bits]
        top = claripy.BVS('TOP', bits, explicit_name=True)
        BackwardSlicingState._tops[bits] = top
        return top
    
    def is_top(self, expr) -> bool:
        if isinstance(expr, claripy.ast.BV):
            if expr.op == 'BVS' and expr.args[0] == 'TOP':
                return True
            if 'TOP' in expr.variables:
                return True
        return False
    
    @property
    def ended(self):
        return self.changed is not None and len(self._tracks) == 0
    
    @property
    def has_concrete_results(self):
        return len(self._concrete_tracks) > 0
    
    @property
    def concrete_results(self):
        return self._concrete_tracks
    
    def __eq__(self, another: object) -> bool:
        if isinstance(another, BackwardSlicingState):
            return self.block == another.block and \
                self.addr == another.addr
                
    def __hash__(self) -> int:
        pass