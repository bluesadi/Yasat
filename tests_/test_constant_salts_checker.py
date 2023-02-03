from tests_.common import YasatTestCase

class ConstantSaltsCheckerTestCase(YasatTestCase):
    
    def test_crypt_arm(self):
        self.Yasat_test_on_firmware('crypt_arm.bin')