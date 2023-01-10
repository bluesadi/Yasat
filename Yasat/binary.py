from typing import List
import os

import angr
from angr import AngrNoPluginError
from angr.analyses.cfg.cfg_fast import CFGFast

from . import l
from .checkers.base import Criterion, RuleChecker

class Binary:
    
    path: str
    proj: angr.Project
    bound_checkers: List[RuleChecker]
    should_abort: bool
    cfg: CFGFast
    
    def __init__(self, path):
        """
        Do not call this constructor directly
        Please use `Binary.new(path, checkers_conf)` instead
        """
        self.path = path
        self.proj = angr.Project(self.path, load_options={'auto_load_libs': False})
        self.bound_checkers = []
        self.should_abort = False
        self.cfg = None     # We will load the CFG later on
    
    @staticmethod
    def new(path, checkers_conf=None):
        """
        Create an instance of Binary
        
        :param path:            The path of the original binary. If the path does not exist, return None.
        :param checkers_conf:   Checkers configuration loaded from configuration file. If checkers_conf is not None, 
                                parse it to a RuleChecker list. If this binary does not import any functions targeted
                                by checkers, return None and skip cfg generation.
        :return:                None or a Binary instance with all properties initialized.
        :rtype:                 Binary
        """
        if not os.path.exists(path):
            return None
        binary = Binary(path)
        if checkers_conf is not None and len(checkers_conf) > 0:
            if not binary._parse_checkers(checkers_conf):
                return None
        binary.cfg = binary.proj.analyses.CFGFast(resolve_indirect_jumps=True, 
                                                  cross_references=True, 
                                                  force_complete_scan=False, 
                                                  normalize=True, 
                                                  symbols=True)
        return binary
    
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
    
    def _parse_checkers(self, checkers_conf):
        for checker_name in checkers_conf:
            checker_conf = checkers_conf[checker_name]
            if not checker_conf['enable']:
                continue
            try:
                checker_type = self.proj.analyses.get_plugin(checker_name)
            except AngrNoPluginError:
                l.warning(f'No such checker: {checker_name}')
                continue
            desc = checker_conf['desc']
            criteria: list[Criterion] = []
            for func_name in checker_conf['criteria']:
                criterion = checker_conf['criteria'][func_name]
                lib_from = criterion['lib_from']
                arg_index = criterion['arg_index']
                func_addr = self.resolve_external_function(func_name, lib_from)
                if func_addr is not None:
                    criteria.append(Criterion(lib_from, arg_index, func_name, func_addr))
            if len(criteria) > 0:
                self.bound_checkers.append(checker_type(desc, criteria))
        return len(self.bound_checkers) > 0