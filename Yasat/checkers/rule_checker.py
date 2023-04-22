from typing import List
import logging

from angr import Analysis
from angr.knowledge_plugins import Function

from ..misc.report import Misuse
from ..knowledge_plugins import Subject
from ..analyses.backward_slicing import BackwardSlicing
from ..analyses.backward_slicing.criteria_selector.argument_selector import ArgumentSelector
from ..utils.print import PrintUtil
from ..utils.format import format_stmt

l = logging.getLogger(__name__)

class RuleChecker(Analysis):
    subject: Subject
    
    def __init__(self, criteria):
        super().__init__()
        self.proj = self.project
        self.subject = self.proj.kb.subject
        self.criteria = criteria

    def check(self) -> List[Misuse]:
        """
        Go find misuses

        :return: A list of misuses we found
        """
        misuses = []
        for func_name, arg_idx in self.criteria:
            misuses.extend(self._check_one(func_name, arg_idx))
        return misuses

    def _check_one(self, func_name, arg_idx) -> List[Misuse]:
        """
        Check against one criterion

        :param func_name: Target function's name
        :param arg_idx: Target argument's index
        :return: A list of misuses we found
        """
        raise NotImplementedError("_check() is not implemented.")


class FunctionCallsChecker(RuleChecker):
    def __init__(self, criteria):
        super().__init__(criteria)

    def _build_misuse_desc(self, func_name, caller_addr):
        return f"Call to {func_name}() at address {hex(caller_addr)}"

    def _check_one(self, func_name, _) -> List[Misuse]:
        results = []
        callee_addr = self.subject.resolve_external_function(func_name)
        callers = self.subject.resolve_callers(callee_addr)
        for caller_insn_addrs in callers.values():
            for caller_insn_addr in caller_insn_addrs:
                results.append(
                    Misuse(self.proj.filename, self._build_misuse_desc(func_name, caller_insn_addr))
                )
        return results

class ConstantValuesChecker(RuleChecker):
    def __init__(self, criteria, arg_name, type, filter=None):
        super().__init__(criteria)
        self.arg_name = arg_name
        self.type = type
        self.filter = filter

    def _build_misuse_desc(self, func_name, arg_name, arg_value, caller_addr):
        if isinstance(arg_value, str):
            arg_value = f'"{arg_value}"'
        elif isinstance(arg_value, Function):
            arg_value = f"{arg_value.name}()"
        return (
            f"Call to {func_name}({arg_name}={arg_value}) at address {hex(caller_addr)}"
        )

    def _check_one(self, func_name, arg_idx) -> List[Misuse]:
        results = []
        callee_addr = self.subject.resolve_external_function(func_name)
        callers = self.subject.resolve_callers(callee_addr)
        for caller_func_addr in callers:
            target_func = self.proj.kb.functions[caller_func_addr]
            bs: BackwardSlicing = self.proj.analyses.BackwardSlicing(
                target_func=target_func, 
                criteria_selectors=[ArgumentSelector(callee_addr, arg_idx)]
            )
            for concrete_result in bs.concrete_results:
                arg_value = None
                if self.type is str:
                    arg_value = concrete_result.string_value
                elif self.type is int:
                    arg_value = concrete_result.int_value
                elif self.type is Function:
                    arg_value = concrete_result.function_value
                    l.debug(f"Found function return value: {arg_value}")
                if arg_value is not None:
                    if self.filter is None or self.filter(arg_value):
                        results.append(
                            Misuse(
                                self.proj.filename,
                                self._build_misuse_desc(
                                    func_name, self.arg_name, arg_value, concrete_result.slice[0].ins_addr
                                ),
                                [PrintUtil.pstr_stmt(stmt) for stmt in concrete_result.slice]
                            )
                        )
                    else:
                        l.info(f"Santilize {arg_value} by {type(self)}")
        return results


class ConstantStringsChecker(ConstantValuesChecker):
    def __init__(self, criteria, arg_name, filter=None):
        super().__init__(criteria, arg_name=arg_name, type=str, filter=filter)

class ConstantIntegersChecker(ConstantValuesChecker):
    def __init__(self, criteria, arg_name, filter=None):
        super().__init__(criteria, arg_name=arg_name, type=int, filter=filter)
        
class ReturnValuesChecker(ConstantValuesChecker):
    def __init__(self, criteria, arg_name, filter=None):
        super().__init__(criteria, arg_name=arg_name, type=Function, filter=filter)