import traceback
import logging

import ailment
import claripy
from angr.engines.light.engine import SimEngineLight, SimEngineLightAILMixin
from angr.errors import SimEngineError
from ailment.statement import *
from ailment.expression import *

from .multi_values import MultiValues
from .ast_enhancer import AstEnhancer
from ...utils.print import PrintUtil

l = logging.getLogger(__name__)


class SimEngineBackwardSlicing(
    SimEngineLightAILMixin,
    SimEngineLight,
):
    def __init__(self, analysis):
        super().__init__()

        self.analysis = analysis
        self.project = self.analysis.project
        self._synced_with_slicing_criterion = False

        self._stmt_handlers = {
            ailment.Stmt.Assignment: self._ail_handle_Assignment,
            ailment.Stmt.Store: self._ail_handle_Store,
            ailment.Stmt.Jump: self._ail_handle_Jump,
            ailment.Stmt.ConditionalJump: self._ail_handle_ConditionalJump,
            ailment.Stmt.Call: self._ail_handle_Call,
            ailment.Stmt.Return: self._ail_handle_Return,
            ailment.Stmt.DirtyStatement: self._ail_handle_DirtyStatement,
            ailment.Stmt.Label: self._ail_handle_Label,
        }

        self._expr_handlers = {
            claripy.ast.BV: self._ail_handle_BV,
            ailment.Expr.Tmp: self._ail_handle_Tmp,
            ailment.Stmt.Call: self._ail_handle_CallExpr,
            ailment.Expr.Register: self._ail_handle_Register,
            ailment.Expr.Load: self._ail_handle_Load,
            ailment.Expr.Convert: self._ail_handle_Convert,
            ailment.Expr.Reinterpret: self._ail_handle_Reinterpret,
            ailment.Expr.ITE: self._ail_handle_ITE,
            ailment.Expr.UnaryOp: self._ail_handle_UnaryOp,
            ailment.Expr.BinaryOp: self._ail_handle_BinaryOp,
            ailment.Expr.Const: self._ail_handle_Const,
            ailment.Expr.StackBaseOffset: self._ail_handle_StackBaseOffset,
            ailment.Expr.DirtyExpression: self._ail_handle_DirtyExpression,
        }

    def process(self, state, *args, **kwargs):
        try:
            self._process(
                state,
                None,
                block=kwargs.pop("block", None),
            )
        except SimEngineError as e:
            raise e
        return state

    def _process_Stmt(self, whitelist=None):
        if whitelist is not None:
            whitelist = set(whitelist)

        for stmt_idx, stmt in reversed(list(enumerate(self.block.statements))):
            if whitelist is not None and stmt_idx not in whitelist:
                continue
            self.stmt = stmt
            self.stmt_idx = stmt_idx
            self.state.stmt_idx = stmt_idx
            self.ins_addr = stmt.ins_addr

            self._handle_Stmt(stmt)

    def _handle_Stmt(self, stmt):
        # Identify criteria using CriteriaSelector
        for selector in self.analysis.criteria_selectors:
            criteria = selector.select_from_stmt(stmt)
            for criterion in criteria:
                self.state.add_track(self._expr(criterion), self.stmt)
        handler = self._stmt_handlers.get(type(stmt), None)
        if handler is not None:
            try:
                handler(stmt)
            except:
                l.error(
                    f"Error occured when handling statment: {PrintUtil.pstr_stmt(stmt)}"
                )
                l.error(traceback.format_exc())
        else:
            l.warning(f"Unsupported statement: {PrintUtil.pstr_stmt(stmt)}")

    def _expr(self, expr: Expression) -> MultiValues:
        # Identify criteria using CriteriaSelector
        for selector in self.analysis.criteria_selectors:
            criteria = selector.select_from_expr(expr)
            for criterion in criteria:
                self.state.add_track(self._expr(criterion), self.stmt)
        handler = self._expr_handlers.get(type(expr), None)
        if handler is not None:
            return handler(expr)
        else:
            l.warning(f"Unsupported expression: {expr}")
            return MultiValues(AstEnhancer.top(expr.bits))

    def _ail_handle_Call(self, stmt: Call):
        # We treat Call statements as Call expressions
        self._expr(stmt)

    def _ail_handle_Store(self, stmt: Store):
        addr = self._expr(stmt.addr)
        data = self._expr(stmt.data)
        return self.state.update_tracks(
            AstEnhancer.load(addr, stmt.data.bits), data, stmt
        )

    def _ail_handle_Assignment(self, stmt: Assignment):
        dst = self._expr(stmt.dst)
        src = self._expr(stmt.src)
        self.state.update_tracks(dst, src, stmt)

    def _ail_handle_Jump(self, stmt: Jump):
        pass

    def _ail_handle_ConditionalJump(self, stmt: ConditionalJump):
        self._expr(stmt.condition)
        self._expr(stmt.true_target)
        self._expr(stmt.false_target)

    def _ail_handle_Return(self, stmt: Return):
        for expr in stmt.ret_exprs:
            self._expr(expr)

    def _ail_handle_Label(self, stmt: Label):
        pass

    def _ail_handle_DirtyStatement(self, stmt: DirtyStatement):
        pass

    def _ail_handle_CallExpr(self, expr: Call):
        func_addr_v = self._expr(expr.target).one_concrete
        if (
            len(self.analysis._call_stack) <= self.analysis._max_call_depth
            and func_addr_v is not None
        ):
            args = [self._expr(arg) for arg in expr.args] if expr.args else []
            handler = self.analysis.function_handler
            if handler:
                func = self.project.kb.functions[func_addr_v._model_concrete.value]
                ret_expr = handler.handle(func, args)
                if ret_expr:
                    return ret_expr
        if expr.ret_expr:
            return MultiValues(AstEnhancer.top(expr.ret_expr.bits))
        return None

    def _ail_handle_BV(self, expr: claripy.ast.BV):
        return MultiValues(expr)

    def _ail_handle_Load(self, expr: Load):
        addr = self._expr(expr.addr)
        values = set()
        for addr_v in addr:
            if addr_v.concrete:
                values.add(
                    self.analysis._sim_state.memory.load(
                        addr_v._model_concrete.value,
                        addr_v.size() // self.arch.byte_width,
                        endness=self.arch.memory_endness,
                    )
                )
            else:
                values.add(AstEnhancer.load_v(addr_v, expr.bits))
        # return AstEnhancer.load(addr, expr.bits)
        return MultiValues(values)

    def _ail_handle_Convert(self, expr: Convert):
        src = self._expr(expr.operand)
        return MultiValues({AstEnhancer.convert(src_v, expr.to_bits) for src_v in src})

    def _ail_handle_Reinterpret(self, expr: Reinterpret):
        # What's this?
        l.warning(f"Unusual expression Reinterpret: {expr}")
        return MultiValues(AstEnhancer.top(expr.bits))

    def _ail_handle_ITE(self, expr: ITE):
        cond = self._expr(expr.cond)
        iftrue = self._expr(expr.iftrue)
        iffalse = self._expr(expr.iffalse)
        values = set()
        for cond_v in cond:
            if cond_v.concrete:
                if cond_v._model_concrete.value != 0:
                    values |= iftrue.values
                    continue
                elif cond_v._model_concrete.value == 0:
                    values |= iffalse.values
                    continue
            for iftrue_v in iftrue:
                for iffalse_v in iffalse:
                    values.add(claripy.If(cond_v, iftrue_v, iffalse_v))
        return MultiValues(values)

    # Unary operations
    def _calc_UnaryOp(self, expr: UnaryOp, op_func) -> MultiValues:
        op = self._expr(expr.operand)
        return MultiValues({op_func(op_v) for op_v in op})

    def _ail_handle_Not(self, expr: UnaryOp):
        return self._calc_UnaryOp(expr, lambda v: ~v)

    def _ail_handle_Neg(self, expr: UnaryOp):
        return self._calc_UnaryOp(expr, lambda v: -v)

    # Binary operations
    def _calc_BinaryOp(self, expr: BinaryOp, op_func) -> MultiValues:
        op0 = self._expr(expr.operands[0])
        op1 = self._expr(expr.operands[1])
        values = set()
        for op0_v in op0:
            for op1_v in op1:
                # Two operands of a binary operation can be of different sizes
                # It's very weird but does happen (e.g., shr   edx, cl)
                # Thus we should do some adjustment for that
                if op0_v.size() > op1_v.size():
                    op1_v = op1_v.zero_extend(op0_v.size() - op1_v.size())
                elif op0_v.size() > op1_v.size():
                    op0_v = op1_v.zero_extend(op1_v.size() - op0_v.size())
                values.add(op_func(op0_v, op1_v))
        return MultiValues(values)

    def _is_zero(self, expr_v):
        return expr_v.concrete and expr_v._model_concrete.value == 0

    def _ail_handle_Add(self, expr: BinaryOp):
        return self._calc_BinaryOp(expr, lambda v0, v1: v0 + v1)

    def _ail_handle_Sub(self, expr: BinaryOp):
        return self._calc_BinaryOp(expr, lambda v0, v1: v0 - v1)

    def _ail_handle_Div(self, expr: BinaryOp):
        return self._calc_BinaryOp(
            expr,
            lambda v0, v1: AstEnhancer.top(expr.bits) if self._is_zero(v1) else v0 / v1,
        )

    def _ail_handle_DivMod(self, expr: BinaryOp):
        # What's this
        l.warning(f"Unusual expression Divmod: {expr}")
        return self._ail_handle_Div(expr)

    def _ail_handle_Mul(self, expr: BinaryOp):
        return self._calc_BinaryOp(
            expr,
            lambda v0, v1: MultiValues(claripy.BVV(0, expr.bits))
            if self._is_zero(v0) or self._is_zero(v1)
            else v0 * v1,
        )

    def _ail_handle_Mull(self, expr: BinaryOp):
        # What's this?
        l.warning(f"Unusual expression Mull: {expr}")
        return self._ail_handle_Mul(expr)

    def _ail_handle_Mod(self, expr: BinaryOp):
        return self._calc_BinaryOp(
            expr,
            lambda v0, v1: AstEnhancer.top(expr.bits) if self._is_zero(v1) else v0 % v1,
        )

    def _ail_handle_Shr(self, expr: BinaryOp):
        return self._calc_BinaryOp(expr, lambda v0, v1: claripy.LShR(v0, v1))

    def _ail_handle_Sar(self, expr: BinaryOp):
        return self._calc_BinaryOp(expr, lambda v0, v1: v0 >> v1)

    def _ail_handle_Shl(self, expr: BinaryOp):
        return self._calc_BinaryOp(expr, lambda v0, v1: v0 << v1)

    def _ail_handle_And(self, expr: BinaryOp):
        return self._calc_BinaryOp(expr, lambda v0, v1: v0 & v1)

    def _ail_handle_Or(self, expr: BinaryOp):
        return self._calc_BinaryOp(expr, lambda v0, v1: v0 | v1)

    def _ail_handle_LogicalAnd(self, expr: BinaryOp):
        return self._calc_BinaryOp(expr, lambda v0, v1: claripy.If(v0 == 0, v0, v1))

    def _ail_handle_LogicalOr(self, expr: BinaryOp):
        return self._calc_BinaryOp(expr, lambda v0, v1: claripy.If(v0 != 0, v0, v1))

    def _ail_handle_Xor(self, expr: BinaryOp):
        return self._calc_BinaryOp(expr, lambda v0, v1: v0 ^ v1)

    _Cmp_handlers = {
        "CmpEQ": lambda v0, v1: v0 == v1,
        "CmpNE": lambda v0, v1: v0 != v1,
        "CmpLE": lambda v0, v1: v0 <= v1,
        "CmpLT": lambda v0, v1: v0 < v1,
        "CmpGE": lambda v0, v1: v0 >= v1,
        "CmpGT": lambda v0, v1: v0 > v1,
    }

    def _ail_handle_Cmp(self, expr: BinaryOp) -> MultiValues:
        op0 = self._expr(expr.operands[0])
        op1 = self._expr(expr.operands[1])
        handler = lambda v0, v1: AstEnhancer.top(expr.bits)
        if expr.op in self._Cmp_handlers:
            handler = self._Cmp_handlers[expr.op]

        return MultiValues({handler(op0_v, op1_v) for op0_v in op0 for op1_v in op1})

    _ail_handle_CmpF = _ail_handle_Cmp
    _ail_handle_CmpEQ = _ail_handle_Cmp
    _ail_handle_CmpNE = _ail_handle_Cmp
    _ail_handle_CmpLE = _ail_handle_Cmp
    _ail_handle_CmpLEs = _ail_handle_Cmp
    _ail_handle_CmpLT = _ail_handle_Cmp
    _ail_handle_CmpLTs = _ail_handle_Cmp
    _ail_handle_CmpGE = _ail_handle_Cmp
    _ail_handle_CmpGEs = _ail_handle_Cmp
    _ail_handle_CmpGT = _ail_handle_Cmp
    _ail_handle_CmpGTs = _ail_handle_Cmp

    def _ail_handle_Concat(self, expr: BinaryOp):
        # What's this?
        l.warning(f"Unusual expression Concat: {expr}")
        return MultiValues(AstEnhancer.top(expr.bits))

    def _ail_handle_StackBaseOffset(self, expr: StackBaseOffset):
        return MultiValues(AstEnhancer.stack_base_offset(expr))

    def _ail_handle_Tmp(self, expr: Tmp):
        return MultiValues(AstEnhancer.tmp(expr))

    def _ail_handle_Register(self, expr: Register):
        return MultiValues(AstEnhancer.reg(expr))

    def _ail_handle_DirtyExpression(self, expr: DirtyExpression):
        return MultiValues(AstEnhancer.top(expr.bits))

    def _ail_handle_Const(self, expr: Const):
        return MultiValues(AstEnhancer.const(expr))
