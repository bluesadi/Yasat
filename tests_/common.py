import unittest
import yaml

from Yasat.binary import Binary
from Yasat import Config
from Yasat.main import Main
from Yasat.analyses.backward_slicing.criteria_selector import ArgumentSelector

ARCH_LIST = ['arm', 'mips']

class YasatTestCase(unittest.TestCase):
    
    def __init__(self, methodName: str = ...) -> None:
        super().__init__(methodName)
        assert(methodName.startswith('test_'))
        assert(len(self.__module__.split('.')) == 2)
        self.method_name = methodName[5:]
        self.module_name = self.__module__.split('.')[1]
        
    def get_test_binaries(self):
        binaries = []
        for arch in ARCH_LIST:
            binaries.append(Binary.new(f'tests/{self.module_name}/bin/{arch}/{self.method_name}'))
        return binaries
    
    def perform_backward_slicing_on_sinks(self, binary, cast_to_str=False):
        target_func_addr = binary.resolve_local_function('main')
        target_func = binary.proj.kb.functions[target_func_addr]
        bs = binary.proj.analyses.BackwardSlicing(target_func,
                                                  [ArgumentSelector(binary.resolve_local_function('sink'), 0)])
        if cast_to_str:
            return [result.string_expr for result in bs.concrete_results]
        return [result.int_expr for result in bs.concrete_results]
    
    def Yasat_test_on_firmware(self, firmware_name):
        with open('config.yml', "r") as fd:
            yaml_config = yaml.safe_load(fd)
        yaml_config['input_path'] = f'tests/{self.module_name}/input/{firmware_name}'
        yaml_config['tmp_dir'] = f'tests/{self.module_name}/tmp/'
        yaml_config['report_dir'] = f'tests/{self.module_name}/report/'
        yaml_config['log_dir'] = f'tests/{self.module_name}/log/'
        
        config = Config(yaml_config)
        
        Main(config).start()