from typing import List, Tuple
import os
import logging

import angr
from angr import AngrNoPluginError
from angr.knowledge_plugins.cfg.cfg_model import CFGModel

from .checkers.base import Criterion, RuleChecker

l = logging.getLogger(__name__)


class Binary:
    path: str
    proj: angr.Project
    bound_checkers: List[RuleChecker]
    should_abort: bool
    cfg: CFGModel

    def __init__(self, path):
        """
        Create an instance of Binary

        :param path:            The path of the original binary. If the path does not exist, return None.
        :param checkers_conf:   Checkers configuration loaded from configuration file. If checkers_conf is not None,
                                parse it to a RuleChecker list. If this binary does not import any functions targeted
                                by checkers, return None and skip cfg generation.
        :return:                None or a Binary instance with all properties initialized.
        :rtype:                 Binary
        """
        self.path = path
        self.proj = angr.Project(self.path, load_options={"auto_load_libs": False})
        self.bound_checkers = []
        self.should_abort = False
        self.cfg = None  # We will load the CFG later on

    def resolve_local_function(self, func_name):
        for func_addr in self.proj.kb.functions:
            func = self.proj.kb.functions[func_addr]
            if func.name == func_name:
                return func.addr
        return 0

    def resolve_external_function(self, func_name, lib):
        obj = self.proj.loader.main_object
        symbol = obj.get_symbol(func_name)
        if symbol is not None and symbol.is_import and lib == symbol.resolvedby.name:
            if func_name in obj.plt:
                return obj.plt[func_name]
            return symbol.resolvedby.rebased_addr
        return None

    def resolve_callers(self, func_addr):
        callers = set()
        if self.cfg is not None:
            predecessors = self.cfg.get_predecessors(self.cfg.get_any_node(func_addr))
            for predecessor in predecessors:
                block = self.proj.factory.block(predecessor.addr)
                caller_insn_addr = block.instruction_addrs[-1]
                callers.add(caller_insn_addr)
        return iter(callers)

    def setup_cfg(self):
        self.cfg = self.proj.analyses.CFGFast(
            resolve_indirect_jumps=True,
            force_complete_scan=False,
            normalize=True,
        )

    def bind_checkers(self, checkers: List[Tuple[str, str, List[Criterion]]]):
        for checker_name, desc, criteria in checkers:
            try:
                checker_type = self.proj.analyses.get_plugin(checker_name)
            except AngrNoPluginError:
                l.warning(f"No such checker: {checker_name}")
                continue
            bound_criteria = []
            for criterion in criteria:
                func_addr = self.resolve_external_function(
                    criterion.func_name, criterion.lib
                )
                if func_addr is not None:
                    bound_criteria.append(
                        Criterion(
                            criterion.lib,
                            criterion.arg_idx,
                            criterion.func_name,
                            func_addr,
                        )
                    )
            self.bound_checkers.append(checker_type(desc, bound_criteria))
