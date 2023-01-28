from typing import Dict, List

import claripy
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from ailment.expression import StackBaseOffset, Register
from angr.sim_variable import SimStackVariable, SimRegisterVariable

class AstEnhancer:
    
    _tops: Dict[int, claripy.ast.BV] = {}
    _load_ops: Dict[int, claripy.ast.BV] = {}
    
    @staticmethod
    def top(bits: int):
        if bits in AstEnhancer._tops:
            return AstEnhancer._tops[bits]
        top = claripy.BVS('TOP', bits, explicit_name=True)
        AstEnhancer._tops[bits] = top
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
    def load(addr: MultiValues, bits:int):
        results = set()
        for addr_v in next(addr.values()):
            if bits in AstEnhancer._load_ops:
                load = AstEnhancer._load_ops[bits]
            else:
                load = claripy.BVS('__load__', bits, explicit_name=True)
                AstEnhancer._load_ops[bits] = load
            results.add(load ** addr_v)
        return MultiValues(offset_to_values={0: results})
    
    def _is_load(ast, concrete=True):
        if isinstance(ast, claripy.ast.BV) and len(ast.args) == 2:
            if isinstance(ast.args[0], claripy.ast.BV) and isinstance(ast.args[1], claripy.ast.BV):
                if ast.args[0].op == 'BVS' and '__load__' in ast.args[0].variables:
                    return not concrete or ast.args[1].concrete
        return False
    
    @staticmethod
    def extract_loads(expr: claripy.ast.BV, concrete=True):
        asts = list(expr.children_asts()) + [expr]
        loads = []
        for ast in asts:
            if AstEnhancer._is_load(ast, concrete=concrete):
                loads.append(ast)
        return loads
    
    def reg_expr_to_name(expr: Register):
        return f'reg_{expr.reg_offset}'
    
    def stack_expr_to_name(expr: StackBaseOffset):
        return f'stack_base{expr.offset:+d}'
    
    def reg_var_to_name(var: SimRegisterVariable):
        return f'reg_{var.reg}'
    
    def stack_var_to_name(var: SimStackVariable):
        return f'stack_base{var.offset:+d}'