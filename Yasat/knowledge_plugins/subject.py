from typing import List, Tuple, Optional
from collections import defaultdict
import logging
import time

import angr
from angr import AngrNoPluginError, Project
from angr.knowledge_plugins.cfg.cfg_model import CFGModel
from angr.analyses.cfg.cfg_fast import CFGFast
from angr.knowledge_plugins.plugin import KnowledgeBasePlugin
from angr.knowledge_base.knowledge_base import KnowledgeBase

l = logging.getLogger(__name__)

default_prototypes = {"EVP_EncryptInit_ex": "int(int, int, char*, char*, int, int, char*, char *)"}


class Subject(KnowledgeBasePlugin):
    _proj: Project

    def __init__(self, kb: KnowledgeBase):
        self._proj = kb._project

    @property
    def cfg(self) -> CFGModel:
        """
        Returns the CFG of the current function.

        :return: A CFGModel object representing the CFG.
        """
        cfg = self._proj.kb.cfgs.get_most_accurate()
        if cfg is None:
            cfg = self.build_cfg()
        return cfg

    def build_cfg(self) -> CFGModel:
        cfg = self._proj.analyses.CFGFast(
            resolve_indirect_jumps=True,
            force_complete_scan=False,
            normalize=True,
        ).model
        for func_addr in self._proj.kb.functions:
            func = self._proj.kb.functions[func_addr]
            if func.name in default_prototypes:
                func.prototype = angr.types.parse_type(default_prototypes[func.name])
        return cfg

    def is_local_function(self, func):
        proj = self._proj
        is_extern = False
        if proj.loader.main_object.contains_addr(func.addr):
            is_extern = proj.loader.find_plt_stub_name(func.addr) is not None
        else:
            symbol = proj.loader.find_symbol(func.addr)
            is_extern = symbol is not None and symbol.is_extern
        return not is_extern

    def resolve_local_function(self, func_name):
        """
        Resolve the address of a local function specified by its name.
        """
        for func_addr in self._proj.kb.functions:
            func = self._proj.kb.functions[func_addr]
            if func.name == func_name:
                return func.addr
        return 0

    def resolve_external_function(self, func_name, lib=None):
        """
        Resolve the address of an external function specified by its name and the name of the library it belongs to.

        :param func_name: A string representing the name of the external function.
        :param lib: A string representing the name of the library where the external function is located.
        :return: If the external function is found and belongs to the specified library, return its address. Otherwise,
                 return None.
        """
        obj = self._proj.loader.main_object
        symbol = obj.get_symbol(func_name)
        # if symbol is not None and symbol.is_import and lib == symbol.resolvedby.name:
        if symbol is not None and symbol.is_import:
            if func_name in obj.plt:
                return obj.plt[func_name]
            return symbol.resolvedby.rebased_addr
        return None

    def resolve_callers(self, callee_addr):
        """
        Retrieve all callers of a function specified by callee_addr.

        :param callee_addr: The address of the callee function.
        :return: A dictionary with integer keys and list values, where each key represents a caller function's address and
                 its corresponding value is a list of instruction addresses within that caller function.
        """
        callers = defaultdict(list)
        cfg = self.cfg
        predecessors = cfg.get_predecessors(cfg.get_any_node(callee_addr))
        for predecessor in predecessors:
            block = self._proj.factory.block(predecessor.addr)
            caller_insn_addr = block.instruction_addrs[-1]
            caller_func_addr = self._proj.kb.functions.floor_func(predecessor.addr).addr
            callers[caller_func_addr].append(caller_insn_addr)
        return callers


KnowledgeBasePlugin.register_default("subject", Subject)
