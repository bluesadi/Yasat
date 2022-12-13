from time import time
import os
import traceback

from func_timeout import func_timeout
from func_timeout.exceptions import FunctionTimedOut

from Yasat.config import Config
from .utils.extractor import Extractor
from . import l

class Analysis:
    
    config: Config
    
    def __init__(self, config):
        self.config = config
        self.stage1_time = -1
        self.stage2_time = -1
    
    def start(self):
        # Stage 1: Load valid input file. Valid file types include:
        # - Firmware (zip archive), e.g., Archer AX10(US)_V1.20_220117.zip)
        # - Firmware (binary), e.g., freshtomato-K26USB-NVRAM32K_RT-MIPSR2-2022.5-AIO.trx
        # - Executable file, e.g., hostapd, libcurl.so.4
        # Save the extracted files to `tmp` directory
        # Get a list of binaries to be analyzed
        l.info('*** Stage 1 - Extract target binaries from firmware ***')
        start = time()
        binaries = Extractor().extract(self.config.input_path, self.config.tmp_dir)
        
        end = time()
        self.stage1_time = end - start
        
        l.info(f'[*] {len(binaries)} binaries will be analyzed soon')
        l.info(f'*** Stage 1 Finished - Costs {self.stage1_time} seconds ***')
        
        l.info('*** Stage 2 - Prepare for cryptographic API misuse detection ***')
        start = time()
        
        def prepare_with_timeout(binary, timeout):
            try:
                l.info(f'Start prepare {binary.path}')
                return func_timeout(timeout, binary.prepare, args=(self.config.tasks,))
            except FunctionTimedOut as e:
                l.warn(f'Preparation for binary {binary.path} ' + 
                          f'timed out after {e.timedOutAfter} seconds')
            except BaseException as e:
                l.warn(f'Error occured while preparing for {binary.path}: {e}\n{traceback.print_exc()}')
            return False
        
        binaries = list(filter(lambda binary : prepare_with_timeout(
            binary, timeout=self.config.preparation_timeout), binaries))
        
        end = time()
        self.stage2_time = end - start
        
        l.info(f'[*] Successfully prepared {len(binaries)} binaries for further analysis')
        l.info(f'*** Stage 2 Finished - Costs {self.stage2_time} seconds ***')
        
        for binary in binaries:
            print(binary)