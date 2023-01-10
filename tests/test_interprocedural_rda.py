
from Yasat.binary import Binary
from tests.common import YasatTestCase

class InterproceduralRdaTestCase(YasatTestCase):
    
    def test_sum(self):
        pass
        # for binary in self.get_test_binaries():
        #     self.assertIsNotNone(binary)
        #     func_addr = binary.resolve_local_function('sink')
        #     defs = binary.proj.kb.arg_defs.get_arg_defs(func_addr, 0)
        #     print(f'Defs: {defs}')