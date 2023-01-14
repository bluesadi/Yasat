import ailment
import claripy
from angr.engines.light.engine import SimEngineLight, SimEngineLightAILMixin
from angr.errors import SimEngineError
from ailment.statement import *
from ailment.expression import *

from ...utils.logger import LoggerMixin
from ...utils.ailment import stmt_to_str

class SimEngineBackwardSlicing(
    SimEngineLightAILMixin,
    SimEngineLight,
    LoggerMixin
):
    
    def __init__(self, analysis):
        super().__init__()
        
        self.analysis = analysis
        
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
        except SimEngineError as e:
            raise e
        return state
    
    def _process_Stmt(self, whitelist=None):
        if whitelist is not None:
            whitelist = set(whitelist)

        for stmt_idx, stmt in reversed(list(enumerate(self.block.statements))):
            self.l.debug(stmt_to_str(stmt, stmt_idx))
            
            if whitelist is not None and stmt_idx not in whitelist:
                continue

            self.stmt_idx = stmt_idx
            self.state.stmt_idx = stmt_idx
            self.ins_addr = stmt.ins_addr
            
            if self.analysis._handled_slicing_criterion:
                self._handle_Stmt(stmt)
            else:
                if stmt.ins_addr != self.analysis.slicing_criterion.caller_addr:
                    # Ignore all statements before handling slicing criterion
                    return
                if isinstance(stmt, Store) and isinstance(stmt.data, Call):
                    call_stmt = stmt.data
                elif isinstance(stmt, Call):
                    call_stmt = stmt
                else:
                    raise ValueError(f'{stmt_to_str(stmt, stmt_idx)} is not a valid caller.')
                if self.analysis.slicing_criterion.arg_idx >= len(call_stmt.args):
                    raise ValueError(f'{self.analysis.slicing_criterion.arg_idx} is not a valid argument index.')
                arg_expr = call_stmt.args[self.analysis.slicing_criterion.arg_idx]
                self.state.add_track(self._expr(arg_expr), call_stmt)
                self.analysis._handled_slicing_criterion = True
                
            self.l.debug(f'State (After processing): {self.state.dbg_repr()}')
                
    
    def _handle_Stmt(self, stmt):
        handler = self._stmt_handlers.get(type(stmt), None)
        if handler is not None:
            handler(stmt)
        else:
            self.l.warning('Unsupported statement type %s.', type(stmt).__name__)
            
    def _expr(self, expr: Expression) -> claripy.ast.BV:
        handler = self._expr_handlers.get(type(expr), None)
        if handler is not None:
            return handler(expr)
        else:
            self.l.warning('Unsupported expression type %s.', type(expr).__name__)
            return self.state.top(expr.bits)
        
    def _ail_handle_Call(self, stmt: Call):
        pass
    
    def _ail_handle_Store(self, stmt: Store):
        dst = claripy.BVS(f'Load[{str(self._expr(stmt.addr))}]', stmt.addr.bits, explicit_name=True)
        src = self._expr(stmt.data)
        if not self.state.is_top(dst):
            self.state.update_tracks(dst, src, stmt)
        
    def _ail_handle_Assignment(self, stmt: Assignment):
        dst = self._expr(stmt.dst)
        src = self._expr(stmt.src)
        if not self.state.is_top(dst):
            self.state.update_tracks(dst, src, stmt)
        
    def _ail_handle_Jump(self, stmt: Jump):
        pass
    
    def _ail_handle_ConditionalJump(self, stmt: ConditionalJump):
        pass
    
    def _ail_handle_Return(self, stmt: Return):
        pass
    
    def _ail_handle_DirtyStatement(self, stmt: DirtyStatement):
        pass
    
    def _ail_handle_CallExpr(self, expr: Call):
        return self.state.top(expr.bits)
    
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
        return claripy.BVS(f'Load[{str(src)}]', expr.bits, explicit_name=True)
    
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
        return self.state.top(expr.bits)
    
    def _ail_handle_Not(self, expr: UnaryOp):
        src = self._expr(expr)
        if self.state.is_top(src):
            return self.state.top(expr.bits)
        return ~src
    
    def _ail_handle_Neg(self, expr: UnaryOp):
        src = self._expr(expr)
        if self.state.is_top(src):
            return self.state.top(expr.bits)
        return -src
    
    def _ail_handle_Add(self, expr: BinaryOp):
        return self._expr(expr.operands[0]) + self._expr(expr.operands[1])
        
    def _ail_handle_Sub(self, expr: BinaryOp):
        return self._expr(expr.operands[0]) - self._expr(expr.operands[1])
    
    def _ail_handle_Div(self, expr: BinaryOp):
        return self._expr(expr.operands[0]) / self._expr(expr.operands[1])
    
    def _ail_handle_DivMod(self, expr: BinaryOp):
        return self._ail_handle_Div(expr)
    
    def _ail_handle_Mul(self, expr: BinaryOp):
        return self._expr(expr.operands[0]) * self._expr(expr.operands[1])
    
    def _ail_handle_Mull(self, expr: BinaryOp):
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
        return self._expr(expr.operands[0]) & self._expr(expr.operands[1])
    
    def _ail_handle_LogicalOr(self, expr: BinaryOp):
        return self._expr(expr.operands[0]) | self._expr(expr.operands[1])
    
    def _ail_handle_Xor(self, expr: BinaryOp):
        return self._expr(expr.operands[0]) ^ self._expr(expr.operands[1])
    
    def _ail_handle_Concat(self, expr: BinaryOp):
        return claripy.Concat(self._expr(expr.operands[0]), self._expr(expr.operands[1]))
    
    def _ail_handle_StackBaseOffset(self, expr: StackBaseOffset):
        return claripy.BVS(str(expr), expr.bits, explicit_name=True)
    
    def _ail_handle_DirtyExpression(self, expr: DirtyExpression):
        pass
    
    def _ail_handle_Const(self, expr: Const):
        return claripy.BVV(expr.value, expr.bits)