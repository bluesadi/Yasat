from typing import List
from collections import defaultdict

from angr import Analysis, Project
from angr.knowledge_plugins.cfg.cfg_model import CFGModel

from ..report import MisuseReport
from ..analyses.backward_slicing import BackwardSlicing
from ..analyses.backward_slicing.criteria_selector.argument_selector import (
    ArgumentSelector,
)


class Criterion:
    def __init__(self, lib_from, arg_index, func_name, func_addr):
        self.lib_from = lib_from
        self.arg_index = arg_index
        self.func_name = func_name
        self.func_addr = func_addr


class RuleChecker(Analysis):
    proj: Project

    def __init__(self, name, desc, criteria):
        super().__init__()
        self.proj = self.project
        self.name = name
        self.desc = desc
        self.criteria: list[Criterion] = criteria

    @property
    def cfg(self) -> CFGModel:
        return self.proj.kb.cfgs.get_most_accurate()

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
        if isinstance(arg_value, bytes):
            arg_value = f'\'{arg_value.decode("utf-8")}\''
        return (
            f'Call to "{criterion.lib_from}::{criterion.func_name}({arg_name}={arg_value})" '
            f"at address {hex(caller_addr)}"
        )

    def _resolve_callers(self, callee_addr):
        callers = defaultdict(list)
        if self.cfg is not None:
            predecessors = self.cfg.get_predecessors(self.cfg.get_any_node(callee_addr))
            for predecessor in predecessors:
                block = self.proj.factory.block(predecessor.addr)
                caller_insn_addr = block.instruction_addrs[-1]
                caller_func_addr = self.proj.kb.functions.floor_func(
                    predecessor.addr
                ).addr
                callers[caller_func_addr].append(caller_insn_addr)
        return callers

    def _check_one(self, criterion: Criterion) -> List[MisuseReport]:
        results = []
        callers = self._resolve_callers(criterion.func_addr)
        for caller_func_addr in callers:
            target_func = self.proj.kb.functions[caller_func_addr]
            criterion_selectors = []
            for caller_insn_addr in callers[caller_func_addr]:
                criterion_selectors.append(
                    ArgumentSelector(criterion.func_addr, criterion.arg_index)
                )

            bs: BackwardSlicing = self.proj.analyses.BackwardSlicing(
                target_func, criterion_selectors
            )
            for concrete_result in bs.concrete_results:
                arg_value = (
                    concrete_result.string_value
                    if self.type is str
                    else concrete_result.int_value
                )
                results.append(
                    MisuseReport(
                        self.proj.filename,
                        self.desc,
                        self._build_misuse_desc(
                            criterion, self.arg_name, arg_value, caller_insn_addr
                        ),
                    )
                )
        return results


class ConstantStringsChecker(ConstantValuesChecker):
    def __init__(self, name, desc, criteria, arg_name):
        super().__init__(name, desc, criteria, arg_name=arg_name, type=str)
