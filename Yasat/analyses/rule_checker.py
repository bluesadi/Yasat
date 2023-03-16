from typing import List

from angr import Analysis

from ..report import MisuseReport
from ..knowledge_plugins import Subject
from .backward_slicing import BackwardSlicing
from .backward_slicing.criteria_selector.argument_selector import ArgumentSelector
from ..utils.print import PrintUtil


class Criterion:
    def __init__(self, lib, arg_idx, func_name):
        self.lib = lib
        self.arg_idx = arg_idx
        self.func_name = func_name


class RuleChecker(Analysis):
    subject: Subject
    
    def __init__(self, name, desc, criteria):
        super().__init__()
        self.proj = self.project
        self.subject = self.proj.kb.subject
        self.name = name
        self.desc = desc
        self.criteria = criteria

    def check(self) -> List[MisuseReport]:
        reports = []
        for criterion in self.criteria:
            reports += self._check_one(criterion)
        return reports

    def _check_one(self, criterion: Criterion) -> List[MisuseReport]:
        raise NotImplementedError("_check() is not implemented.")


class ConstantValuesChecker(RuleChecker):
    def __init__(self, name, desc, criteria, arg_name, type):
        super().__init__(name, desc, criteria)
        self.arg_name = arg_name
        self.type = type

    def _build_misuse_desc(self, criterion, arg_name, arg_value, caller_addr):
        if isinstance(arg_value, str):
            arg_value = f'"{arg_value}"'
        return (
            f"Call to lib{criterion.lib}::{criterion.func_name}({arg_name}={arg_value}) "
            f"at address {hex(caller_addr)}"
        )

    def _check_one(self, criterion: Criterion) -> List[MisuseReport]:
        results = []
        callee_addr = self.subject.resolve_external_function(criterion.func_name, criterion.lib)
        callers = self.subject.resolve_callers(callee_addr)
        for caller_func_addr in callers:
            target_func = self.proj.kb.functions[caller_func_addr]
            bs: BackwardSlicing = self.proj.analyses.BackwardSlicing(
                target_func=target_func, 
                criteria_selectors=[ArgumentSelector(callee_addr, criterion.arg_idx)]
            )
            for concrete_result in bs.concrete_results:
                arg_value = (
                    concrete_result.string_value
                    if self.type is str
                    else concrete_result.int_value
                )
                if arg_value is not None:
                    results.append(
                        MisuseReport(
                            self.proj.filename,
                            self.desc,
                            self._build_misuse_desc(
                                criterion, self.arg_name, arg_value, concrete_result.slice[0].ins_addr
                            ),
                            [PrintUtil.pstr_stmt(stmt) for stmt in concrete_result.slice]
                        )
                    )
        return results


class ConstantStringsChecker(ConstantValuesChecker):
    def __init__(self, name, desc, criteria, arg_name):
        super().__init__(name, desc, criteria, arg_name=arg_name, type=str)
