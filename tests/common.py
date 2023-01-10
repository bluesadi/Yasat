import unittest
import sys
import os

from Yasat.binary import Binary

ARCH_LIST = ['arm', 'mips']

class YasatTestCase(unittest.TestCase):
    
    module: str=''
    
    def get_test_binaries(self):
        caller_filename = sys._getframe(1).f_code.co_filename
        caller_funcname = sys._getframe(1).f_code.co_name
        module = os.path.basename(caller_filename).split('.')[0]
        sub_test_case = caller_funcname[5:]

        binaries = []
        for arch in ARCH_LIST:
            binaries.append(Binary.new(f'tests/{module}/bin/{arch}/{sub_test_case}'))
        return binaries