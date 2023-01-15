from typing import Set, Tuple, Dict

import angr
from ailment import Block
from ailment.statement import Statement
from ailment.utils import stable_hash
import claripy

from ...utils.common import pstr
from ...utils.ailment import stmt_to_str

class SlicingTrack:
    
    def __init__(self, expr: claripy.ast.BV, slice: Tuple[Statement], state):
        self._expr = expr
        self._slice = slice
        self._state = state
        self._proj = state.analysis.project
        
    @property    
    def expr(self):
        return self._expr
    
    @property
    def slice(self):
        return self._slice
    
    @property
    def string_expr(self):
        int_expr = self.int_expr
        if int_expr is None:
            raise RuntimeError(f'Expression {self._expr} is not a concrete value')
        sim_state: angr.sim_state.SimState = self._proj.factory.entry_state()
        return sim_state.mem[int_expr].string.concrete
    
    @property
    def int_expr(self):
        if self._expr.concrete:
            return self.expr._model_concrete.value
        raise RuntimeError(f'Expression {self._expr} is not a concrete value')
        
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
    stmt_idx: Statement
    
    _tracks: Set[SlicingTrack]
    _concrete_tracks: Set[SlicingTrack]
    _ended: bool
    
    _tops: Dict[int, claripy.ast.BV] = {}
    _loads: Dict[int, claripy.ast.BV] = {}
    _proj: angr.Project
    
    def __init__(self, analysis, block: Block):
        self.block = block
        self.addr = block.addr
        self.stmt_idx = -1
        
        self.analysis = analysis
        self.arch = analysis.project.arch
        self._proj = analysis.project
        self._tracks = set()
        self._concrete_tracks = set()
        self._ended = False
        
    @staticmethod
    def top(bits: int):
        if bits in SlicingState._tops:
            return SlicingState._tops[bits]
        top = claripy.BVS('TOP', bits, explicit_name=True)
        SlicingState._tops[bits] = top
        return top
    
    @staticmethod
    def is_top(expr) -> bool:
        if isinstance(expr, claripy.ast.BV):
            if expr.op == 'BVS' and expr.args[0] == 'TOP':
                return True
            if 'TOP' in expr.variables:
                return True
        return False
    
    @staticmethod
    def load(addr: claripy.ast.BV, bits:int):
        if bits in SlicingState._loads:
            load = SlicingState._loads[bits]
        else:
            load = claripy.BVS('__load__', bits, explicit_name=True)
            SlicingState._loads[bits] = load
        return load ** addr
    
    @staticmethod
    def contains_load(expr) -> bool:
        if isinstance(expr, claripy.ast.BV):
            if expr.op == 'BVS' and expr.args[0] == '__load__':
                return True
            if '__load__' in expr.variables:
                return True
        return False
        
    def merge(self, *others):
        state = self.copy()
        for another in others:
            state._tracks |= another._tracks
            state._concrete_tracks |= another._concrete_tracks
        return state
    
    def copy(self):
        state_copy = SlicingState(self.analysis, self.block.copy())
        state_copy._tracks = self._tracks.copy()
        state_copy._concrete_tracks = self._concrete_tracks.copy()
        return state_copy
    
    def add_track(self, expr, stmt):
        if self.is_top(expr):
            return
        track = SlicingTrack(expr, (stmt,), self)
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
            new_track = SlicingTrack(new_expr, track.slice + (stmt,), self)
            if hash(track.expr) != hash(new_track.expr):
                self.changed = True
                if new_track.expr.concrete:
                    self._concrete_tracks.add(new_track)
                    continue
            new_tracks.add(new_track)
        self._tracks = new_tracks
        self._ended = len(new_tracks) == 0
    
    @property
    def ended(self):
        return self._ended
    
    @property
    def num_tracks(self):
        return len(self._tracks)
    
    @property
    def num_concrete_tracks(self):
        return len(self._concrete_tracks)
    
    @property
    def has_concrete_results(self):
        return len(self._concrete_tracks) > 0
    
    def _is_concrete_load(self, ast):
        if isinstance(ast, claripy.ast.BV) and len(ast.args) == 2:
            if isinstance(ast.args[0], claripy.ast.BV) and isinstance(ast.args[1], claripy.ast.BV):
                if ast.args[0].op == 'BVS' and '__load__' in ast.args[0].variables:
                    return ast.args[1].concrete
        return False
    
    @property
    def concrete_results(self):
        sim_state = self._proj.factory.entry_state()
        concrete_tracks = self._concrete_tracks.copy()
        for track in self._tracks:
            new_expr = track.expr
            while self.contains_load(new_expr):
                for ast in list(track.expr.children_asts()) + [track.expr]:
                    if self._is_concrete_load(ast):
                        repl = sim_state.memory.load(ast.args[1]._model_concrete.value, 
                                               ast.size() // self.arch.byte_width,
                                               endness=self.arch.memory_endness)
                        new_expr = new_expr.replace(ast, repl)
            if new_expr.concrete:
                concrete_tracks.add(SlicingTrack(new_expr, track.slice, self))    
                            
        return concrete_tracks
    
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
        return 'BackwardSlicingState ' + \
            pstr({'stmts': [stmt_to_str(stmt) for stmt in self.block.statements],
                  'tracks': [track_to_dict(track) for track in self._tracks], 
                  'concrete_tracks': [track_to_dict(track) for track in self._concrete_tracks]})