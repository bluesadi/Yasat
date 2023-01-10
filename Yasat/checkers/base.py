from typing import List

from angr import Analysis, Project
from angr.knowledge_plugins.cfg.cfg_model import CFGModel

from ..report import MisuseReport
from ..knowledge_plugins.argument_definition_manager import ArgumentDefinitionManager

class Criterion:
    
    def __init__(self, lib_from, arg_index, func_name, func_addr):
        self.lib_from = lib_from
        self.arg_index = arg_index
        self.func_name = func_name
        self.func_addr = func_addr

class RuleChecker(Analysis):
    
    proj: Project
    arg_defs: ArgumentDefinitionManager
    
    def __init__(self, name, desc, criteria):
        self.proj = self.project
        self.arg_defs = self.proj.kb.arg_defs
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
        defs = self.arg_defs.get_arg_defs(criterion.func_addr, criterion.arg_index, self.type)
        for caller_func_addr, caller_insn_addr, arg_def in defs:
            results.append(MisuseReport(self.proj.filename, self.desc, 
                                        self._build_misuse_desc(criterion, self.arg_name, arg_def, caller_insn_addr)))
        return results
    
class ConstantStringsChecker(ConstantValuesChecker):
    
    def __init__(self, name, desc, criteria, arg_name):
        super().__init__(name, desc, criteria, arg_name=arg_name, type=bytes)