import ailment
import claripy
from angr.engines.light.engine import SimEngineLight, SimEngineLightAILMixin
from angr.errors import SimEngineError
from ailment.statement import *
from ailment.expression import *

from ...utils.ailment import stmt_to_str

class SimEngineBackwardSlicing(
    SimEngineLightAILMixin,
    SimEngineLight,
):
    
    def __init__(self, analysis):
        super().__init__()
        
        self.analysis = analysis
        self._synced_with_slicing_criterion = False
        
        self._stmt_handlers = {
            ailment.Stmt.Assignment: self._ail_handle_Assignment,
            ailment.Stmt.Store: self._ail_handle_Store,
            ailment.Stmt.Jump: self._ail_handle_Jump,
            ailment.Stmt.ConditionalJump: self._ail_handle_ConditionalJump,
            ailment.Stmt.Call: self._ail_handle_Call,
            ailment.Stmt.Return: self._ail_handle_Return,
            ailment.Stmt.DirtyStatement: self._ail_handle_DirtyStatement,
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
                block=kwargs.pop('block', None),
            )
            self.l.debug(f'State: {self.state.dbg_repr()}')
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
        handler = self._stmt_handlers.get(type(stmt), None)
        if handler is not None:
            handler(stmt)
        else:
            self.l.warning('Unsupported statement type %s.', type(stmt).__name__)
            
    def _expr(self, expr: Expression) -> claripy.ast.BV:
        handler = self._expr_handlers.get(type(expr), None)
        if handler is not None:
            for selector in self.analysis.criterion_selectors:
                criterion = selector.select(expr)
                if criterion is not None:
                    self.state.add_track(self._expr(criterion), self.stmt)
            return handler(expr)
        else:
            self.l.warning('Unsupported expression type %s.', type(expr).__name__)
            return self.state.top(expr.bits)
        
    def _ail_handle_Call(self, stmt: Call):
        self._expr(stmt)
    
    def _ail_handle_Store(self, stmt: Store):
        dst = self._expr(stmt.addr)
        src = self._expr(stmt.data)
        if not self.state.is_top(dst):
            self.state.update_tracks(self.state.load_expr(dst, stmt.addr.bits), src, stmt)
        
    def _ail_handle_Assignment(self, stmt: Assignment):
        dst = self._expr(stmt.dst)
        src = self._expr(stmt.src)
        if not self.state.is_top(dst):
            self.state.update_tracks(dst, src, stmt)
        
    def _ail_handle_Jump(self, stmt: Jump):
        self.l.debug(f'Ignore Jump: {stmt}')
    
    def _ail_handle_ConditionalJump(self, stmt: ConditionalJump):
        self._expr(stmt.condition)
    
    def _ail_handle_Return(self, stmt: Return):
        for expr in stmt.ret_exprs:
            self._expr(expr)
    
    def _ail_handle_DirtyStatement(self, stmt: DirtyStatement):
        self.l.debug(f'Ignore DirtyStatement: {stmt}')
    
    def _ail_handle_CallExpr(self, expr: Call):
        if hasattr(expr, 'bits'):
            return self.state.top(expr.bits)
        return None
    
    def _ail_handle_BV(self, expr: claripy.ast.BV):
        return expr
    
    def _ail_handle_Tmp(self, expr: Tmp):
        return claripy.BVS(str(expr), expr.bits, explicit_name=True)
    
    def _ail_handle_Register(self, expr: Register):
        return claripy.BVS(str(expr), expr.bits, explicit_name=True)
    
    def _ail_handle_Load(self, expr: Load):
        src = self._expr(expr.addr)
        if self.state.is_top(src):
            return self.state.top(expr.bits)
        return self.state.load_expr(src, expr.bits)
    
    def _ail_handle_Convert(self, expr: Convert):
        src = self._expr(expr.operand)
        if self.state.is_top(src):
            return self.state.top(expr.to_bits)
        elif expr.to_bits < expr.from_bits:
            return src[expr.to_bits - 1: 0]
        elif expr.to_bits > expr.from_bits:
            return claripy.ZeroExt(expr.to_bits - expr.from_bits, src)
        return src
    
    def _ail_handle_Reinterpret(self, expr: Reinterpret):
        return self.state.top(expr.bits)
    
    def _ail_handle_ITE(self, expr: ITE):
        cond = self._expr(expr.cond)
        iftrue = self._expr(expr.iftrue)
        iffalse = self._expr(expr.iffalse)
        if cond.concrete:
            if cond._model_concrete.value != 0:
                return iftrue
            else:
                return iffalse
        return claripy.If(cond, iftrue, iffalse)
    
    def _ail_handle_Not(self, expr: UnaryOp):
        return ~self._expr(expr)
    
    def _ail_handle_Neg(self, expr: UnaryOp):
        return -self._expr(expr)
    
    def _ail_handle_Add(self, expr: BinaryOp):
        return self._expr(expr.operands[0]) + self._expr(expr.operands[1])
        
    def _ail_handle_Sub(self, expr: BinaryOp):
        return self._expr(expr.operands[0]) - self._expr(expr.operands[1])
    
    def _ail_handle_Div(self, expr: BinaryOp):
        dividend = self._expr(expr.operands[0])
        divisor = self._expr(expr.operands[1])
        if divisor.concrete and divisor._model_concrete.value == 0:
            return self.state.top(expr.bits)
        if dividend.concrete and divisor._model_concrete.value == 0:
            return claripy.BVV(0, expr.bits)
        return dividend / divisor
    
    def _ail_handle_DivMod(self, expr: BinaryOp):
        # How is an assembly instruction translated to DivMod?
        self.l.debug(f'Divmod: {expr}')
        return self._ail_handle_Div(expr)
    
    def _ail_handle_Mul(self, expr: BinaryOp):
        expr0 = self._expr(expr.operands[0])
        expr1 = self._expr(expr.operands[1])
        if (expr0.concrete and expr0._model_concrete.value == 0) or \
                (expr1.concrete and expr1._model_concrete.value == 0):
            return claripy.BVV(0, expr.bits)
        return expr0 * expr1
    
    def _ail_handle_Mull(self, expr: BinaryOp):
        # What's this?
        return self._ail_handle_Mul(expr)
    
    def _ail_handle_Mod(self, expr: BinaryOp):
        return self._expr(expr.operands[0]) % self._expr(expr.operands[1])
    
    def _ail_handle_Shr(self, expr: BinaryOp):
        return self._expr(expr.operands[0]) >> self._expr(expr.operands[1])
    
    def _ail_handle_Sar(self, expr: BinaryOp):
        return self._expr(expr.operands[0]) >> self._expr(expr.operands[1])
    
    def _ail_handle_Shl(self, expr: BinaryOp):
        return self._expr(expr.operands[0]) << self._expr(expr.operands[1])
    
    def _ail_handle_And(self, expr: BinaryOp):
        return self._expr(expr.operands[0]) & self._expr(expr.operands[1])
    
    def _ail_handle_Or(self, expr: BinaryOp):
        return self._expr(expr.operands[0]) | self._expr(expr.operands[1])
    
    def _ail_handle_LogicalAnd(self, expr: BinaryOp):
        expr0 = self._expr(expr.operands[0])
        expr1 = self._expr(expr.operands[1])
        if self.state.is_top(expr0) or self.state.is_top(expr1):
            return self.state.top(expr.bits)
        return claripy.If(expr0 == 0, expr0, expr1)
    
    def _ail_handle_LogicalOr(self, expr: BinaryOp):
        expr0 = self._expr(expr.operands[0])
        expr1 = self._expr(expr.operands[1])
        if self.state.is_top(expr0) or self.state.is_top(expr1):
            return self.state.top(expr.bits)
        return claripy.If(expr0 != 0, expr0, expr1)
    
    def _ail_handle_Xor(self, expr: BinaryOp):
        return self._expr(expr.operands[0]) ^ self._expr(expr.operands[1])
    
    def _ail_handle_Concat(self, expr: BinaryOp):
        # What's this?
        self.l.debug(f'Debug: {expr}')
        return self.state.top(expr.bits)
    
    def _ail_handle_StackBaseOffset(self, expr: StackBaseOffset):
        return claripy.BVS(str(expr), expr.bits, explicit_name=True)
    
    def _ail_handle_DirtyExpression(self, expr: DirtyExpression):
        self.l.debug(f'Ignore DirtyExpression: {expr}')
        return self.state.top(expr.bits)
    
    def _ail_handle_Const(self, expr: Const):
        return claripy.BVV(expr.value, expr.bits)