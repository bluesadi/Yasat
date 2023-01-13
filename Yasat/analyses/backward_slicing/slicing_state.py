from typing import Set, Tuple, Dict

from ailment import Block
from ailment.statement import Statement
from ailment.utils import stable_hash
import claripy

from ...utils.common import pstr
from ...utils.ailment import stmt_to_str

class SlicingTrack:
    
    def __init__(self, expr: claripy.ast.BV, slice: Tuple[Statement]):
        self._expr = expr
        self._slice = slice
        
    @property    
    def expr(self):
        return self._expr
    
    @property
    def slice(self):
        return self._slice
    
    def concrete_string(self, proj):
        concrete_int = self.concrete_int()
        if concrete_int is not None:
            pass
    
    def concrete_int(self):
        if self._expr.concrete:
            solver = claripy.Solver()
            return solver.eval(self.expr, 1)[0]
        return None
        
    def __str__(self) -> str:
        return 'SlicingTrack ' + pstr({'expr': str(self.expr), 'slice': [str(stmt) for stmt in self.slice]})
    
    def __repr__(self) -> str:
        return str(self)
        
    def __hash__(self) -> int:
        return stable_hash((SlicingTrack, self.expr) + self.slice)
    
    def __eq__(self, another: object) -> bool:
        return type(self) is type(another) and \
            hash(self.expr) == hash(another.expr) and self.slice == another.slice

class SlicingState:
    
    block: Block
    addr: int
    solver: claripy.Solver
    
    _tracks: Set[SlicingTrack]
    _concrete_tracks: Set[SlicingTrack]
    
    _tops: Dict[int, claripy.ast.BV] = set()
    
    def __init__(self, analysis, block: Block):
        self.block = block
        self.addr = block.addr
        self.changed = None
        self.solver = claripy.Solver()
        
        self.analysis = analysis
        self.arch = analysis.project.arch
        
        self._tracks = set()
        self._concrete_tracks = set()
        
    def top(self, bits: int):
        if bits in SlicingState._tops:
            return SlicingState._tops[bits]
        top = claripy.BVS('TOP', bits, explicit_name=True)
        SlicingState._tops[bits] = top
        return top
    
    def is_top(self, expr) -> bool:
        if isinstance(expr, claripy.ast.BV):
            if expr.op == 'BVS' and expr.args[0] == 'TOP':
                return True
            if 'TOP' in expr.variables:
                return True
        return False
        
    def merge(self, *others):
        state = self.copy()
        for another in others:
            state._tracks |= another._tracks
            state._concrete_tracks |= another._concrete_tracks
            state._tops |= another._tops
        return state
    
    def copy(self):
        state_copy = SlicingState(self.analysis, self.block.copy())
        state_copy._tracks = self._tracks.copy()
        state_copy._concrete_tracks = self._concrete_tracks.copy()
        return state_copy
    
    def add_track(self, expr, stmt):
        if self.is_top(expr):
            return
        track = SlicingTrack(expr, (stmt,))
        if expr.concrete:
            self._concrete_tracks.add(track)
        else:
            self._tracks.add(track)
        self.changed = True
    
    def update_tracks(self, old, new, stmt):
        new_tracks = set()
        for track in self._tracks:
            new_expr = track.expr.replace(old, new)
            if self.is_top(new_expr):
                continue
            new_track = SlicingTrack(new_expr, track.slice + (stmt,))
            if hash(track.expr) != hash(new_track.expr):
                self.changed = True
                if new_track.expr.concrete:
                    self._concrete_tracks.add(new_track)
                    continue
            new_tracks.add(new_track)
        self._tracks = new_tracks
    
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
        if isinstance(another, SlicingState):
            return self.block == another.block and \
                self.addr == another.addr
                
    def __hash__(self) -> int:
        pass
    
    def dbg_repr(self):
        def track_to_dict(track):
            return {
                'expr': str(track.expr),
                'slice': [stmt_to_str(stmt) for stmt in track.slice]
            }
        return 'BackwardSlicingState ' + pstr({'tracks': [track_to_dict(track) for track in self._tracks], 
                                               'concrete_tracks': [track_to_dict(track) for track in self._concrete_tracks]})