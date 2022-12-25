from typing import List

import angr
from angr import AngrNoPluginError

from . import l
from .checkers.base import Criterion, RuleChecker
from .report import OverallReport

class Binary:
    
    path: str
    proj: angr.Project
    checkers: List[RuleChecker]
    should_abort: bool
    cfg: angr.analyses.cfg.cfg_fast.CFGFast
    
    def __init__(self, path):
        self.path = path
        self.proj = angr.Project(self.path, load_options={'auto_load_libs': False})
        self.checkers = []
        self.should_abort = False
        self.cfg = None     # We will load binary's CFG later on
        
    def _resolve_external_function(self, func_name, lib):
        obj = self.proj.loader.main_object
        symbol = obj.get_symbol(func_name)
        if symbol is not None and symbol.is_import and lib == symbol.resolvedby.name:
            if func_name in obj.plt:
                return obj.plt[func_name]
            return symbol.resolvedby.rebased_addr
        return None
    
    def _parse_checkers(self, checkers):
        for checker_name in checkers:
            checker_conf = checkers[checker_name]
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
                lib = criterion['lib']
                arg = criterion['arg']
                func_addr = self._resolve_external_function(func_name, lib)
                if func_addr is not None:
                    criteria.append(Criterion(lib, arg, func_name, func_addr))
            if len(criteria) > 0:
                self.checkers.append(checker_type(desc, criteria))
    
    def preprocess(self, tasks):
        self._parse_checkers(tasks)
        if len(self.checkers) == 0:
            return False
        self.cfg = self.proj.analyses.CFGFast(resolve_indirect_jumps=True, 
                                              cross_references=True, 
                                              force_complete_scan=False, 
                                              normalize=True, 
                                              symbols=True)
        return True
    
    def analyze(self, report: OverallReport):
        for checker in self.checkers:
            misuse_reports = checker.check()
            report.report_misuses(checker.name, misuse_reports)