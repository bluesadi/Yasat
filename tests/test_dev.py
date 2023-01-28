
from angr.analyses.decompiler.clinic import Clinic
from ailment.statement import *
from ailment.expression import *
from Yasat.binary import Binary
from Yasat.analyses.backward_slicing import BackwardSlicing
from Yasat.analyses.backward_slicing.criteria_selector import ArgumentSelector
from Yasat.analyses.backward_slicing.function_handler import InterproceduralFunctionHandler

from tests.common import YasatTestCase

class DevTestCase(YasatTestCase):
    
    def test_sum(self):
        for binary in self.get_test_binaries():
            print(binary.proj.filename)
            binary: Binary
            func_addr = binary.resolve_local_function('main')
            cfg = binary.proj.analyses.CFGFast(resolve_indirect_jumps=True, 
                                               cross_references=True, 
                                               force_complete_scan=False, 
                                               normalize=True, 
                                               symbols=True)
            foo_func = cfg.kb.functions[binary.resolve_local_function('foo')]
            clinic: Clinic = binary.proj.analyses.Clinic(foo_func)
            target_func = cfg.kb.functions[func_addr]
            clinic: Clinic = binary.proj.analyses.Clinic(target_func)
            criteria_selectors = [ArgumentSelector(binary.resolve_local_function('sink'), 0)]
            # criteria_selectors = [ReturnSelector()]
            bs: BackwardSlicing = binary.proj.analyses.BackwardSlicing(target_func=target_func,
                                                                       criteria_selectors=criteria_selectors)
            for track in bs.concrete_results:
                print(f'Expr: {track.int_expr}')
                print(f'Slice ({hex(id(track.slice))}): {track.slice}')
            break