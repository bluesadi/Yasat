from time import time

from Yasat.config import Config
from .utils.extractor import Extractor
from .utils.common import call_with_timeout
from . import l, timer

class Main:
    
    config: Config
    
    def __init__(self, config):
        self.config = config
        self.stage1_time = -1
        self.stage2_time = -1
    
    def start(self):
        timer.start()
        # Stage 1: Load valid input file. Valid file types include:
        # - Firmware (zip archive), e.g., Archer AX10(US)_V1.20_220117.zip)
        # - Firmware (binary), e.g., freshtomato-K26USB-NVRAM32K_RT-MIPSR2-2022.5-AIO.trx
        # - Executable file, e.g., hostapd, libcurl.so.4
        # Save the extracted files to `tmp` directory
        # Get a list of binaries to be analyzed
        l.info('*** Stage 1 - Extract target binaries from firmware ***')
        binaries = Extractor().extract(self.config.input_path, self.config.tmp_dir)
        
        self.stage1_time = timer.interval
        
        l.info(f'[-] {len(binaries)} binaries will be analyzed soon')
        l.info(f'*** Stage 1 Finished - Cost {self.stage1_time} seconds ***')
        
        l.info('*** Stage 2 - Preprocess target binaries ***')
        
        binaries_tmp = []
        for i, binary in enumerate(binaries):
            l.info(f'[-] Preprocess {binary.path} ({i + 1}/{len(binaries)})')
            should_keep = call_with_timeout(binary.preprocess, args=(self.config.tasks,),
                                            timeout=self.config.preparation_timeout)
            if should_keep:
                binaries_tmp.append(binary)
        binaries = binaries_tmp
        
        self.stage2_time = timer.interval
        
        l.info(f'[*] Successfully prepared {len(binaries)} binaries for further analysis')
        l.info(f'*** Stage 2 Finished - Costs {self.stage2_time} seconds ***')
        
        for binary in binaries:
            print(binary)