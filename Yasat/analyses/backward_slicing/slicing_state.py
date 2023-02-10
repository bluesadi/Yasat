from typing import Set, Tuple
import logging

import angr
from ailment import Block
from ailment.statement import Statement
from ailment.utils import stable_hash
import claripy
from angr.sim_variable import SimStackVariable, SimRegisterVariable

from ...utils.print import PrintUtil
from .ast_enhancer import AstEnhancer
from .multi_values import MultiValues

l = logging.getLogger(__name__)


class SlicingTrack:
    def __init__(self, expr: claripy.ast.Base, slice: Tuple[Statement], state):
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
        return sim_state.mem[int_value].string.concrete.decode("UTF-8")

    @property
    def int_value(self):
        if self._expr.concrete:
            return self.expr._model_concrete.value
        l.error(f"Expression {self._expr} is not a BV or concrete value")
        return None

    @property
    def bool_value(self):
        int_value = self.int_value
        if int_value is not None:
            return int_value != 0
        return None

    def __str__(self) -> str:
        return "SlicingTrack " + PrintUtil.pstr(
            {
                "expr": str(self.expr),
                "slice": [PrintUtil.pstr_stmt(stmt) for stmt in self.slice],
            }
        )

    def __repr__(self) -> str:
        return str(self)

    def __hash__(self) -> int:
        return stable_hash((SlicingTrack, self.expr) + self.slice)

    def __eq__(self, another: object) -> bool:
        return (
            type(self) is type(another)
            and hash(self.expr) == hash(another.expr)
            and self.slice == another.slice
        )


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
        self._cached_concrete_results = None

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
        for expr_v in expr:
            if AstEnhancer.is_top(expr_v):
                return
            track = SlicingTrack(expr_v, (stmt,), self)
            if expr_v.concrete:
                self._concrete_tracks.add(track)
            else:
                self._tracks.add(track)

    def update_tracks(self, old: MultiValues, new: MultiValues, stmt):
        new_tracks = set()
        for old_v in old:
            for new_v in new:
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

    def _apply_preset_arguments(self, expr: claripy.ast.Base):
        # Step 1. Replace passed arguments if applicable
        new_expr = expr
        for var, arg in self.analysis.preset_arguments:
            for arg_v in arg:
                # If the arg is passed by stack
                if isinstance(var, SimStackVariable):
                    stack_expr_v = AstEnhancer.stack_base_offset(var)
                    # Like global memory, stack variable is always used with Load expression
                    new_expr = new_expr.replace(
                        AstEnhancer.load_v(stack_expr_v, arg_v.size()), arg_v
                    )
                # If the arg is passed by register
                elif isinstance(var, SimRegisterVariable):
                    reg_expr_v = AstEnhancer.reg(var)
                    new_expr = new_expr.replace(reg_expr_v, arg_v)
        return new_expr

    def _resolve_load_exprs(self, expr: claripy.ast.Base):
        """
        Iteratively find and replace concrete load (e.g., load from global memory)
        until we can't find concrete loads in an iteration
        """
        sim_state = self._proj.factory.entry_state()
        new_expr = expr
        while True:
            loads = AstEnhancer.extract_loads(new_expr)
            if not loads:
                break
            for load in loads:
                repl = sim_state.memory.load(
                    load.args[1]._model_concrete.value,
                    load.size() // self.arch.byte_width,
                    endness=self.arch.memory_endness,
                )
                new_expr = new_expr.replace(load, repl)
        return new_expr

    def _simplify(self, expr):
        new_expr = expr
        for ast in list(new_expr.children_asts()) + [new_expr]:
            if ast.op == "If":
                cond, iftrue, iffalse = ast.args
                if cond.concrete:
                    if cond._model_concrete.value == 1:
                        new_expr = new_expr.replace(ast, iftrue)
                    elif cond._model_concrete.value == 0:
                        new_expr = new_expr.replace(ast, iffalse)
        return new_expr

    @property
    def concrete_results(self):
        # if self._cached_concrete_results:
        # return self._cached_concrete_results

        concrete_results = self._concrete_tracks.copy()
        for track in self._tracks:
            new_expr = self._apply_preset_arguments(track.expr)
            new_expr = self._resolve_load_exprs(new_expr)
            new_expr = self._simplify(new_expr)

            if new_expr.concrete:
                concrete_results.add(SlicingTrack(new_expr, track.slice, self))

        # self._cached_concrete_results = concrete_results
        return concrete_results

    @property
    def sorted_concrete_results(self):
        return sorted(self.concrete_results, key=lambda track: track.slice[0].ins_addr)

    def __eq__(self, another: object) -> bool:
        if isinstance(another, SlicingState):
            return self.block == another.block and self.addr == another.addr

    def dbg_repr(self):
        def track_to_dict(track):
            return {
                "expr": str(track.expr),
                "slice": [PrintUtil.pstr_stmt(stmt) for stmt in track.slice],
            }

        return "BackwardSlicingState " + PrintUtil.pstr(
            {
                "stmts": [PrintUtil.pstr_stmt(stmt) for stmt in self.block.statements],
                "tracks": [track_to_dict(track) for track in self._tracks],
                "concrete_tracks": [
                    track_to_dict(track) for track in self._concrete_tracks
                ],
            }
        )
