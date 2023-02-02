import logging

import ailment
import claripy
from angr.engines.light.engine import SimEngineLight, SimEngineLightAILMixin
from angr.errors import SimEngineError
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from ailment.statement import *
from ailment.expression import *

from .ast_enhancer import AstEnhancer

class SimEngineBackwardSlicing(
    SimEngineLightAILMixin,
    SimEngineLight,
):
    
    def __init__(self, analysis):
        super().__init__()
        self.l.setLevel(logging.INFO)
        
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
            ailment.Stmt.Label: self._ail_handle_Label
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
            print(state.dbg_repr())
            self._process(
                state,
                None,
                block=kwargs.pop('block', None),
            )
            self.l.debug(f'Current state: {self.state.dbg_repr()}')
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
        for selector in self.analysis.criteria_selectors:
            criteria = selector.select_from_stmt(stmt)
            for criterion in criteria:
                self.state.add_track(self._expr(criterion), self.stmt)
        handler = self._stmt_handlers.get(type(stmt), None)
        if handler is not None:
            handler(stmt)
        else:
            self.l.warning(f'Unsupported statement: {stmt}')
            
    def _expr(self, expr: Expression) -> MultiValues:
        # Identify criteria and start tracking them
        for selector in self.analysis.criteria_selectors:
            criteria = selector.select_from_expr(expr)
            for criterion in criteria:
                self.state.add_track(self._expr(criterion), self.stmt)
        handler = self._expr_handlers.get(type(expr), None)
        if handler is not None:
            return handler(expr)
        else:
            self.l.warning(f'Unsupported expression: {expr}')
            return [AstEnhancer.top(expr.bits)]
        
    def _ail_handle_Call(self, stmt: Call):
        # We treat Call statements as Call expressions
        self._expr(stmt)
    
    def _ail_handle_Store(self, stmt: Store):
        addr = self._expr(stmt.addr)
        data = self._expr(stmt.data)
        return self.state.update_tracks(AstEnhancer.load(addr, stmt.data.bits), data, stmt)
        
    def _ail_handle_Assignment(self, stmt: Assignment):
        dst = self._expr(stmt.dst)
        src = self._expr(stmt.src)
        if not AstEnhancer.is_top(dst):
            self.state.update_tracks(dst, src, stmt)
        
    def _ail_handle_Jump(self, stmt: Jump):
        pass
    
    def _ail_handle_ConditionalJump(self, stmt: ConditionalJump):
        self._expr(stmt.condition)
    
    def _ail_handle_Return(self, stmt: Return):
        for expr in stmt.ret_exprs:
            self._expr(expr)
    
    def _ail_handle_Label(self, stmt: Label):
        pass
    
    def _ail_handle_DirtyStatement(self, stmt: DirtyStatement):
        pass
    
    def _ail_handle_CallExpr(self, expr: Call):
        func_addr = self._expr(expr.target)
        args = [] if expr.args is None else [self._expr(arg) for arg in expr.args]
        for func_addr_v in next(func_addr.values()):
            if func_addr_v.concrete:
                handler = self.analysis.function_handler
                if handler is not None:
                    func = self.project.kb.functions[func_addr_v._model_concrete.value]
                    ret_expr = handler.handle(func, args)
                    if ret_expr is not None:
                        return ret_expr
            return MultiValues(AstEnhancer.top(func_addr_v.size()))
    
    def _ail_handle_BV(self, expr: claripy.ast.BV):
        return MultiValues(expr)
    
    def _ail_handle_Load(self, expr: Load):
        src = self._expr(expr.addr)
        return AstEnhancer.load(src, expr.bits)
    
    def _ail_handle_Convert(self, expr: Convert):
        src = self._expr(expr.operand)
        results = set()
        for src_v in next(src.values()):
            results.add(AstEnhancer.convert(src_v, expr.to_bits))
        return MultiValues(offset_to_values={0: results})
    
    def _ail_handle_Reinterpret(self, expr: Reinterpret):
        # What's this?
        self.l.debug(f'Unusual expression Reinterpret: {expr}')
        return MultiValues(AstEnhancer.top(expr.bits))
    
    def _ail_handle_ITE(self, expr: ITE):
        cond = self._expr(expr.cond)
        results = set()
        for cond_v in next(cond.values()):
            iftrue = self._expr(expr.iftrue)
            iffalse = self._expr(expr.iffalse)
            for iftrue_v in next(iftrue.values()):
                for iffalse_v in next(iffalse.values()):
                    results.add(claripy.If(cond_v, iftrue_v, iffalse_v))
        return MultiValues(offset_to_values={0: results})
    
    # Unary operations
    def _calc_UnaryOp(self, expr: UnaryOp, op_func) -> MultiValues:
        expr0 = expr.operand
        results = set()
        for expr0_v in next(expr0.values()):
            results.add(op_func(expr0_v))
        return MultiValues(offset_to_values={0: results})
    
    def _ail_handle_Not(self, expr: UnaryOp):
        return self._calc_UnaryOp(expr, lambda v: ~v)
    
    def _ail_handle_Neg(self, expr: UnaryOp):
        return self._calc_UnaryOp(expr, lambda v: -v)
    
    # Binary operations
    def _calc_BinaryOp(self, expr: BinaryOp, op_func) -> MultiValues:
        expr0 = self._expr(expr.operands[0])
        expr1 = self._expr(expr.operands[1])
        results = set()
        for expr0_v in next(expr0.values()):
            for expr1_v in next(expr1.values()):
                # Two operands of a binary operation can be of different sizes
                # It's very weird but does happen (e.g., shr   edx, cl)
                # Thus we should do some adjustment for that
                if expr0_v.size() > expr1_v.size():
                    expr1_v = expr1_v.zero_extend(expr0_v.size() - expr1_v.size())
                elif expr0_v.size() > expr1_v.size():
                    expr0_v = expr1_v.zero_extend(expr1_v.size() - expr0_v.size())
                results.add(op_func(expr0_v, expr1_v))
        return MultiValues(offset_to_values={0: results})
    
    def _is_zero(self, expr_v):
        return expr_v.concrete and expr_v._model_concrete.value == 0
    
    def _ail_handle_Add(self, expr: BinaryOp):
        return self._calc_BinaryOp(expr, lambda v0, v1: v0 + v1)
        
    def _ail_handle_Sub(self, expr: BinaryOp):
        return self._calc_BinaryOp(expr, lambda v0, v1: v0 - v1)
    
    def _ail_handle_Div(self, expr: BinaryOp):
        return self._calc_BinaryOp(expr, lambda v0, v1: AstEnhancer.top(expr.bits) 
                                         if self._is_zero(v1) else v0 / v1)
    
    def _ail_handle_DivMod(self, expr: BinaryOp):
        # What's this
        self.l.debug(f'Unusual expression Divmod: {expr}')
        return self._ail_handle_Div(expr)
    
    def _ail_handle_Mul(self, expr: BinaryOp):
        return self._calc_BinaryOp(expr, lambda v0, v1: MultiValues(claripy.BVV(0, expr.bits)) 
                                         if self._is_zero(v0) or self._is_zero(v1) else v0 * v1)
    
    def _ail_handle_Mull(self, expr: BinaryOp):
        # What's this?
        self.l.debug(f'Unusual expression Mull: {expr}')
        return self._ail_handle_Mul(expr)
    
    def _ail_handle_Mod(self, expr: BinaryOp):
        return self._calc_BinaryOp(expr, lambda v0, v1: AstEnhancer.top(expr.bits) 
                                         if self._is_zero(v1) else v0 % v1)
    
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
    
    def _ail_handle_Concat(self, expr: BinaryOp):
        # What's this?
        self.l.debug(f'Unusual expression Concat: {expr}')
        return MultiValues(AstEnhancer.top(expr.bits))

    def _ail_handle_StackBaseOffset(self, expr: StackBaseOffset):
        return MultiValues(claripy.BVS(AstEnhancer.stack_expr_to_name(expr), expr.bits, explicit_name=True))
    
    def _ail_handle_Tmp(self, expr: Tmp):
        return MultiValues(claripy.BVS(str(expr), expr.bits, explicit_name=True))
    
    def _ail_handle_Register(self, expr: Register):
        return MultiValues(claripy.BVS(AstEnhancer.reg_expr_to_name(expr), expr.bits, explicit_name=True))
    
    def _ail_handle_DirtyExpression(self, expr: DirtyExpression):
        return MultiValues(AstEnhancer.top(expr.bits))
    
    def _ail_handle_Const(self, expr: Const):
        return MultiValues(claripy.BVV(expr.value, expr.bits))