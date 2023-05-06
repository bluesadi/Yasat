from typing import Dict, Union, Optional

import claripy
from ailment.expression import StackBaseOffset, Register, Tmp, Const
from angr.sim_variable import SimStackVariable, SimRegisterVariable

from .multi_values import MultiValues


class AstEnhancer:
    _tops: Dict[int, claripy.ast.Base] = {}
    _load_ops: Dict[int, claripy.ast.Base] = {}

    @staticmethod
    def top(bits: int):
        if bits in AstEnhancer._tops:
            return AstEnhancer._tops[bits]
        top = claripy.BVS("TOP", bits, explicit_name=True)
        AstEnhancer._tops[bits] = top
        return top

    @staticmethod
    def is_top(expr: claripy.ast.Base) -> bool:
        assert isinstance(expr, claripy.ast.Base)
        if expr.op == "BVS" and expr.args[0] == "TOP":
            return True
        return "TOP" in expr.variables

    @staticmethod
    def convert(expr: claripy.ast.Base, to_bits: int):
        assert isinstance(expr, claripy.ast.Base)
        if AstEnhancer.is_top(expr):
            return AstEnhancer.top(to_bits)
        elif isinstance(expr, claripy.ast.Bool):
            return claripy.If(expr, claripy.BVV(1, to_bits), claripy.BVV(0, to_bits))
        elif to_bits < expr.size():
            return expr[to_bits - 1 : 0]
        elif to_bits > expr.size():
            return claripy.ZeroExt(to_bits - expr.size(), expr)
        return expr

    @staticmethod
    def multi_convert(expr: MultiValues, to_bits: int):
        return MultiValues({AstEnhancer.convert(v, to_bits) for v in expr})

    @staticmethod
    def load(addr: MultiValues, bits: int):
        values = set()
        for addr_v in addr:
            values.add(AstEnhancer.load_v(addr_v, bits))
        return MultiValues(values)

    @staticmethod
    def load_v(addr_v: claripy.ast.BV, bits: int):
        assert isinstance(addr_v, claripy.ast.BV)
        if addr_v.size() in AstEnhancer._load_ops:
            load = AstEnhancer._load_ops[addr_v.size()]
        else:
            load = claripy.BVS("__load__", addr_v.size(), explicit_name=True)
            AstEnhancer._load_ops[addr_v.size()] = load
        return AstEnhancer.convert(load**addr_v, bits)

    def _is_load(ast, concrete=True):
        if isinstance(ast, claripy.ast.Base) and len(ast.args) == 2:
            if isinstance(ast.args[0], claripy.ast.Base) and isinstance(
                ast.args[1], claripy.ast.Base
            ):
                if ast.args[0].op == "BVS" and "__load__" in ast.args[0].variables:
                    return not concrete or ast.args[1].concrete
        return False

    @staticmethod
    def call(addr_v: claripy.ast.BV):
        assert isinstance(addr_v, claripy.ast.BV)
        call = claripy.BVS("__call__", addr_v.size(), explicit_name=True)
        return call**addr_v

    @staticmethod
    def resolve_call(ast):
        if isinstance(ast, claripy.ast.Base) and len(ast.args) == 2:
            if isinstance(ast.args[0], claripy.ast.Base) and isinstance(
                ast.args[1], claripy.ast.Base
            ):
                if ast.args[0].op == "BVS" and "__call__" in ast.args[0].variables:
                    return AstEnhancer.concrete_value(ast.args[1])
        return None

    @staticmethod
    def extract_loads(expr: claripy.ast.Base, concrete=True):
        asts = list(expr.children_asts()) + [expr]
        loads = []
        for ast in asts:
            if AstEnhancer._is_load(ast, concrete=concrete):
                loads.append(ast)
        return loads

    def stack_base_offset(expr: Union[StackBaseOffset, SimStackVariable]):
        if isinstance(expr, StackBaseOffset) or isinstance(expr, SimStackVariable):
            name = f"statck_base_{expr.offset}"
        else:
            raise TypeError(f"expr's type should be Register or SimRegisterVariable")
        return claripy.BVS(name, expr.bits, explicit_name=True)

    def reg(expr: Union[Register, SimRegisterVariable]):
        if isinstance(expr, Register):
            name = f"reg_{expr.reg_offset}"
        elif isinstance(expr, SimRegisterVariable):
            name = f"reg_{expr.reg}"
        else:
            raise TypeError(f"expr's type should be Register or SimRegisterVariable")
        return claripy.BVS(name, expr.bits, explicit_name=True)

    def tmp(expr: Tmp):
        return claripy.BVS(str(expr), expr.bits, explicit_name=True)

    def const(expr: Const):
        return claripy.BVV(expr.value, expr.bits)

    def concrete_value(base: claripy.ast.Base) -> Optional[int]:
        if base.concrete:
            if isinstance(base, claripy.ast.Bool):
                if base.is_true():
                    return 1
                elif base.is_false():
                    return 0
            elif isinstance(base, claripy.ast.BV):
                return base._model_concrete.value
        return None
