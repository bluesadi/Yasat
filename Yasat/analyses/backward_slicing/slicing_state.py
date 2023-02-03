from typing import Set, Tuple

import angr
from ailment import Block
from ailment.statement import Statement
from ailment.utils import stable_hash
import claripy
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from angr.sim_variable import SimStackVariable, SimRegisterVariable

from ...utils.logger import LoggerMixin
from ...utils.print import PrintUtil
from .ast_enhancer import AstEnhancer

class SlicingTrack(LoggerMixin):
    
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
    def string_value(self):
        int_value = self.int_value
        if int_value is None:
            return None
        sim_state: angr.sim_state.SimState = self._proj.factory.entry_state()
        return sim_state.mem[int_value].string.concrete.decode('UTF-8')
    
    @property
    def int_value(self):
        if self._expr.concrete:
            return self.expr._model_concrete.value
        self.l.error(f'Expression {self._expr} is not a concrete value')
        return None
        
    def __str__(self) -> str:
        return 'SlicingTrack ' + PrintUtil.pstr({'expr': str(self.expr), 
                                                 'slice': [PrintUtil.pstr_stmt(stmt) for stmt in self.slice]})
    
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
    
    def add_track(self, expr: MultiValues, stmt):
        for expr_v in next(expr.values()):
            if AstEnhancer.is_top(expr_v):
                return
            track = SlicingTrack(expr_v, (stmt,), self)
            if expr_v.concrete:
                self._concrete_tracks.add(track)
            else:
                self._tracks.add(track)
    
    def update_tracks(self, old: MultiValues, new: MultiValues, stmt):
        new_tracks = set()
        for old_v in next(old.values()):
            for new_v in next(new.values()):
                for track in self._tracks:
                    new_expr = track.expr.replace(old_v, new_v)
                    if AstEnhancer.is_top(new_expr):
                        continue
                    new_track = track
                    if hash(track.expr) != hash(new_expr):
                        new_track = SlicingTrack(new_expr, track.slice + (stmt,), self)
                        if new_expr.concrete:
                            self._concrete_tracks.add(new_track)
                            continue
                    new_tracks.add(new_track)
        self._tracks = new_tracks
    
    @property
    def num_tracks(self):
        return len(self._tracks)
    
    @property
    def num_concrete_tracks(self):
        return len(self._concrete_tracks)
    
    @property
    def has_concrete_results(self):
        return len(self._concrete_tracks) > 0
    
    @property
    def concrete_results(self):
        sim_state = self._proj.factory.entry_state()
        concrete_tracks = self._concrete_tracks.copy()
        for track in self._tracks:
            new_expr = track.expr
            # Step 1. Replace passed arguments if applicable
            for var, expr in self.analysis.preset_arguments:
                for expr_v in next(expr.values()):
                    # If the arg is passed by stack
                    if isinstance(var, SimStackVariable):
                        stack_expr_v = claripy.BVS(AstEnhancer.stack_var_to_name(var), expr_v.size(), 
                                                   explicit_name=True)
                        # Like global memory, stack variable is always used with Load expression
                        new_expr = new_expr.replace(
                            AstEnhancer.load(MultiValues(stack_expr_v), expr_v.size()).one_value(),
                            expr_v)
                    # If the arg is passed by register
                    elif isinstance(var, SimRegisterVariable):
                        reg_expr_v = claripy.BVS(AstEnhancer.reg_var_to_name(var), expr_v.size(), explicit_name=True)
                        new_expr = new_expr.replace(reg_expr_v, expr_v)
            # Step 2. Iteratively find and replace concrete load (e.g., load from global memory) 
            # until we can't find concrete loads in an iteration
            while True:
                loads = AstEnhancer.extract_loads(new_expr)
                if not loads:
                    break
                for load in loads:
                    repl = sim_state.memory.load(load.args[1]._model_concrete.value, 
                                                 load.size() // self.arch.byte_width,
                                                 endness=self.arch.memory_endness)
                    new_expr = new_expr.replace(load, repl)
            if new_expr.concrete:
                concrete_tracks.add(SlicingTrack(new_expr, track.slice, self))    
                            
        
        return concrete_tracks
    
    @property
    def sorted_concrete_results(self):
        return sorted(self.concrete_results, key=lambda track: track.slice[0].ins_addr)
    
    def __eq__(self, another: object) -> bool:
        if isinstance(another, SlicingState):
            return self.block == another.block and \
                self.addr == another.addr
                
    def dbg_repr(self):
        def track_to_dict(track):
            return {
                'expr': str(track.expr),
                'slice': [PrintUtil.pstr_stmt(stmt) for stmt in track.slice]
            }
        return 'BackwardSlicingState ' + \
            PrintUtil.pstr({'stmts': [PrintUtil.pstr_stmt(stmt) for stmt in self.block.statements],
                            'tracks': [track_to_dict(track) for track in self._tracks],
                            'concrete_tracks': [track_to_dict(track) for track in self._concrete_tracks]})