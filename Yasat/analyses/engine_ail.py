import ailment
import claripy
from angr.engines.light.engine import SimEngineLight, SimEngineLightAILMixin
from angr.errors import SimEngineError
from ailment.statement import *

from backward_slicing import BackwardSlicing

class SimEngineBackwardSlicing(
    SimEngineLightAILMixin,
    SimEngineLight,
):
    
    analysis: BackwardSlicing
    
    def __init__(self, analysis: BackwardSlicing):
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

        for stmt_idx, stmt in enumerate(self.block.statements[::]):
            if whitelist is not None and stmt_idx not in whitelist:
                continue

            self.stmt_idx = stmt_idx
            self.ins_addr = stmt.ins_addr
            
            if self.analysis._handled_slicing_criterion:
                self._handle_Stmt(stmt)
            else:
                if stmt.ins_addr != self.analysis.slicing_criterion.callsite_addr:
                    # Ignore all statements before handling slicing criterion
                    return
                if isinstance(stmt, Store) and isinstance(stmt.data, Call):
                    call_expr = stmt.data
                elif isinstance(stmt, Call):
                    call_expr = stmt
                else:
                    raise ValueError(f'{hex(self.analysis.slicing_criterion)} is not a valid callsite address.')
                if self.analysis.slicing_criterion.arg_index >= len(call_expr.args):
                    raise ValueError(f'{self.analysis.slicing_criterion.arg_index} is not a valid argument index.')
                arg_expr = call_expr.args[self.analysis.slicing_criterion.arg_index]
                # TODO
                self.analysis._handled_slicing_criterion = True
                
    
    def _handle_Stmt(self, stmt):
        handler = self._stmt_handlers.get(type(stmt), None)
        if handler is not None:
            handler(stmt)
        else:
            self.l.warning('Unsupported statement type %s.', type(stmt).__name__)
            
    def _expr(self, expr):
        handler = self._expr_handlers.get(type(expr), None)
        if handler is not None:
            return handler(expr)
        else:
            self.l.warning('Unsupported expression type %s.', type(expr).__name__)
            return None
        
    def _ail_handle_Call(self, stmt: Call):
        return self._ail_handle_CallExpr(stmt)
    
    def _ail_handle_CallExpr(self, expr: Call):
        return self._expr(expr)