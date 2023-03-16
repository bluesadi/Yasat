from typing import List, Tuple, Optional
from collections import defaultdict
import logging
import time

from angr import AngrNoPluginError, Project
from angr.knowledge_plugins.cfg.cfg_model import CFGModel
from angr.analyses.cfg.cfg_fast import CFGFast
from angr.knowledge_plugins.plugin import KnowledgeBasePlugin
from angr.knowledge_base.knowledge_base import KnowledgeBase

l = logging.getLogger(__name__)


class Subject(KnowledgeBasePlugin):
    _proj: Project

    def __init__(self, kb: KnowledgeBase):
        self._proj = kb._project
    
    @property
    def cfg(self) -> CFGModel:
        cfg = self._proj.kb.cfgs.get_most_accurate()
        if cfg is None:
            cfg = self._proj.analyses.CFGFast(
                resolve_indirect_jumps=True,
                force_complete_scan=False,
                normalize=True,
            ).model
        return cfg

    def resolve_local_function(self, func_name):
        for func_addr in self._proj.kb.functions:
            func = self._proj.kb.functions[func_addr]
            if func.name == func_name:
                return func.addr
        return 0

    def resolve_external_function(self, func_name, lib):
        obj = self._proj.loader.main_object
        symbol = obj.get_symbol(func_name)
        if symbol is not None and symbol.is_import and lib == symbol.resolvedby.name:
            if func_name in obj.plt:
                return obj.plt[func_name]
            return symbol.resolvedby.rebased_addr
        return None

    def resolve_callers(self, callee_addr):
        callers = defaultdict(list)
        cfg = self.cfg
        predecessors = cfg.get_predecessors(cfg.get_any_node(callee_addr))
        for predecessor in predecessors:
            block = self._proj.factory.block(predecessor.addr)
            caller_insn_addr = block.instruction_addrs[-1]
            caller_func_addr = self._proj.kb.functions.floor_func(
                predecessor.addr
            ).addr
            callers[caller_func_addr].append(caller_insn_addr)
        return callers
                
KnowledgeBasePlugin.register_default("subject", Subject)
