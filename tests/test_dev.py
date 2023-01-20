
from angr.analyses.decompiler.clinic import Clinic
from ailment.statement import *
from ailment.expression import *
from Yasat.binary import Binary
from Yasat.analyses.backward_slicing import SlicingCriterion, BackwardSlicing
from Yasat.analyses.backward_slicing.criterion_selector.argument_selector import ArgumentSelector

from tests.common import YasatTestCase

class DevTestCase(YasatTestCase):
    
    def test_sum(self):
        for binary in self.get_test_binaries():
            binary: Binary
            func_addr = binary.resolve_local_function('main')
            cfg = binary.proj.analyses.CFGFast(resolve_indirect_jumps=True, 
                                               cross_references=True, 
                                               force_complete_scan=False, 
                                               normalize=True, 
                                               symbols=True)
            target_func = cfg.kb.functions[func_addr]
            clinic: Clinic = binary.proj.analyses.Clinic(target_func)
            criterion_selectors = [ArgumentSelector(binary.resolve_local_function('sink'), 0)]
            bs: BackwardSlicing = binary.proj.analyses.BackwardSlicing(target_func=target_func, 
                                                                       criterion_selectors=criterion_selectors)
            for track in bs.concrete_results:
                print(f'Expr: {track.int_expr}')
                print(f'Slice ({hex(id(track.slice))}): {track.slice}')