from tests.common import YasatTestCase

from angr.analyses.decompiler.clinic import Clinic
from ailment.statement import *
from ailment.expression import *

class DevTestCase(YasatTestCase):
    
    def test_sum(self):
        for binary in self.get_test_binaries():
            print(binary.proj)
            func_addr = binary.resolve_local_function('main')
            cfg = binary.proj.analyses.CFGFast(resolve_indirect_jumps=True, 
                                               cross_references=True, 
                                               force_complete_scan=False, 
                                               normalize=True, 
                                               symbols=True)
            target_func = cfg.kb.functions[func_addr]
            clinic: Clinic = binary.proj.analyses.Clinic(target_func)
            
            print(clinic.dbg_repr())
            
            for block in clinic.graph:
                for stmt in block.statements:
                    if isinstance(stmt, Call):
                        for arg in stmt.args:
                            print(type(arg.variable))