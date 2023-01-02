from typing import List

from angr import Analysis, Project
from angr.knowledge_plugins.cfg.cfg_model import CFGModel

from ..report import MisuseReport
from ..knowledge_plugins.analysis_results_manager import AnalysisResultsManager

class Criterion:
    
    def __init__(self, lib_from, arg_index, func_name, func_addr):
        self.lib_from = lib_from
        self.arg_index = arg_index
        self.func_name = func_name
        self.func_addr = func_addr

class RuleChecker(Analysis):
    
    proj: Project
    analysis_results: AnalysisResultsManager
    
    def __init__(self, name, desc, criteria):
        self.proj = self.project
        self.analysis_results = self.proj.kb.analysis_results
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
        raise NotImplementedError('_check() is not implemented.')
    
class ConstantValuesChecker(RuleChecker):
    
    def __init__(self, name, desc, criteria, arg_name, type):
        super().__init__(name, desc, criteria)
        self.arg_name = arg_name
        self.type = type
       
    def _build_misuse_desc(self, criterion, arg_name, arg_value, caller_addr):
        if isinstance(arg_value, bytes):
            arg_value = f'\'{arg_value.decode("utf-8")}\''
        return f'Call to "{criterion.lib_from}::{criterion.func_name}({arg_name}={arg_value})" '\
            f'at address {hex(caller_addr)}'
        
    def _check_one(self, criterion: Criterion) -> List[MisuseReport]:
        results = []
        predecessors = self.cfg.get_predecessors(self.cfg.get_any_node(criterion.func_addr))
        for predecessor in predecessors:
            block = self.proj.factory.block(predecessor.addr)
            caller_addr = block.instruction_addrs[-1]
            caller_func_addr = self.kb.functions.floor_func(block.addr).addr
            defs = self.analysis_results.get_arg_defs(func_addr=caller_func_addr, 
                                                      insn_addr=caller_addr, 
                                                      index=criterion.arg_index, type=self.type)
            results += [MisuseReport(self.proj.filename, self.desc, 
                                     self._build_misuse_desc(criterion, self.arg_name, 
                                                             def_, caller_addr)) for def_ in defs]
        return results
    
class ConstantStringsChecker(ConstantValuesChecker):
    
    def __init__(self, name, desc, criteria, arg_name):
        super().__init__(name, desc, criteria, arg_name=arg_name, type=bytes)