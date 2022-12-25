from typing import List
import os

from .config import Config
from .utils.extractor import Extractor
from .utils.common import call_with_timeout
from . import l, timer
from .report import OverallReport

class Main:
    
    config: Config
    report: OverallReport
    
    def __init__(self, config):
        self.config = config
        self.report = OverallReport(config.input_path)
        
        self.stage1_time = -1
        self.stage1_progress = None
        
        self.stage2_time = -1
        self.stage2_progress = None
        
        self.stage3_time = -1
        self.stage3_progress = None
    
    def start(self):
        # Timer start - used to record how much time each stage costs
        timer.start()
        
        '''
        Stage 1:
        - Try to decompress the given file (if the given file is an achieve file, e.g., zip).
        - Try to extract ELF executables from the given file (if the given file is a firmware image)
          or the decompressed files.
        - Do nothing if the given file is already an ELF executable.
        - Save all the ELF executable(s) from to `config.tmp_dir` for subsequent procedures.
        '''
        l.info('*** Stage 1 - Extract ELF binaries***')
        binaries = Extractor().extract(self.config.input_path, self.config.tmp_dir)
        
        self.stage1_time = timer.interval
        
        l.info(f'[-] {len(binaries)} binaries will be analyzed soon')
        l.info(f'*** Stage 1 Finished - Cost {self.stage1_time} seconds ***')
        
        '''
        Stage 2:
        - For each binary in `binaries` list, check whether it imports any of cryptographic APIs
          specified in `config.checkers`. If not, discard it.
        - Then generate a CFG for each of the reset.
        - If the whole process of a binary costs more than `config.preprocess_timeout`, also 
          discard it because the binary might be too large to finish analyzing in acceptable time.
        '''
        l.info('*** Stage 2 - Preprocess target binaries ***')
        
        binaries_tmp = []
        for i, binary in enumerate(binaries):
            self.stage2_progress = f'{i + 1}/{len(binaries)}'
            l.info(f'[-] Preprocess {binary.path} ({self.stage2_progress})')
            should_keep = call_with_timeout(binary.preprocess, args=(self.config.checkers,),
                                            timeout=self.config.preprocess_timeout)
            if should_keep:
                binaries_tmp.append(binary)
        binaries = binaries_tmp
        
        self.stage2_time = timer.interval
        
        l.info(f'[*] {len(binaries)} binaries will be checked against a set of rules soon')
        l.info(f'*** Stage 2 Finished - Costs {self.stage2_time} seconds ***')
        
        for i, binary in enumerate(binaries):
            self.stage3_progress = f'{i + 1}/{len(binaries)}'
            binary.analyze(self.report)
            
        self.stage3_time = timer.interval
        
        l.info(f'Total cost: {timer.total} seconds')
        
        report_path = os.path.join(self.config.report_dir,
                                   os.path.basename(self.config.input_path)) + '.log'
        self.report.save(report_path)
        l.info(f'Overall report has been save to {report_path}')