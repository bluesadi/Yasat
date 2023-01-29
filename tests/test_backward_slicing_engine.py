
from Yasat.binary import Binary
from tests.common import YasatTestCase

class BackwardSlicingEngineTestCase(YasatTestCase):
    
    def test_add(self):
        for binary in self.get_test_binaries():
            self.assertIsNotNone(binary)
            self.assertEqual(self.perform_backward_slicing_on_sinks(binary), [0x9b5bb44 + 0x55ae8a])
            
    def test_sub(self):
        for binary in self.get_test_binaries():
            self.assertIsNotNone(binary)
            self.assertEqual(self.perform_backward_slicing_on_sinks(binary), [0x45146a6b - 0x90e090ec + 0xffffffff + 1])
            
    def test_div(self):
        for binary in self.get_test_binaries():
            self.assertIsNotNone(binary)
            self.assertEqual(self.perform_backward_slicing_on_sinks(binary), [0xe636039d // 0xd5c489a1])