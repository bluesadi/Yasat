import os
import time
from typing import List

from .config import Config
from .utils.extractor import Extractor
from .utils.common import call_with_timeout
from . import l
from .report import OverallReport
from .binary import Binary

class Main:
    
    config: Config
    report: OverallReport
    
    def __init__(self, config):
        self.config = config
        self.report = OverallReport(config.input_path)
        self.stage_id = 0
        self.stage_desc = 'Not started yet'
        self.stage_start = 0
        self.stage_progress = [0, 0]
    
    def _start_stage(self, stage_desc):
        self.stage_id += 1
        self.stage_desc = stage_desc
        l.info(f'*** Stage {self.stage_id} - {stage_desc} ***')
        self.stage_start = time.time()
        
    def _init_stage_progress(self, total):
        self.stage_progress = [0, total]
    
    def _progress_stage(self):
        self.stage_progress[0] += 1
        l.info(f'[-] Stage is progressing ({"/".join(map(str, self.stage_progress))})')
        
    def _end_stage(self):
        stage_cost = time.time() - self.stage_start
        self.report.report_time_cost(self.stage_desc, stage_cost)
        l.info(f'*** Stage {self.stage_id} Finished - Cost {stage_cost:.1f} seconds ***')
        
    def start(self):
        '''
        Stage 1:
        - Try to decompress the given file (if the given file is an achieve file, e.g., zip).
        - Try to extract ELF executables from the given file (if the given file is a firmware image)
          or the decompressed files.
        - Do nothing if the given file is already an ELF executable.
        - Save all the ELF executable(s) from to `config.tmp_dir` for subsequent procedures.
        '''
        self._start_stage('Extract ELF binaries')
        
        binary_paths = Extractor().extract(self.config.input_path, self.config.tmp_dir)
        
        l.info(f'[-] {len(binary_paths)} binaries will be analyzed soon')
        self._end_stage()
        
        '''
        Stage 2:
        - For each binary_path in `binary_paths` list, check whether the binary of this path imports any of 
          cryptographic APIs specified in `config.checkers`. If not, discard it.
        - Then create a Binary instance for each of the rest.
        - If the whole process of creating a binary costs more than `config.preprocess_timeout` seconds, also discard it
          because the binary might be too large to finish analyzing within acceptable time.
        - Instantiating a Binary could be rather slow. That's basically because the CFG generation process takes 
          a lot of time.
        '''
        self._start_stage('Preprocess target binaries')
        self._init_stage_progress(len(binaries))
        
        binaries: List[Binary] = []
        for binary_path in binary_paths:
            binary = call_with_timeout(Binary.new, args=(binary_path, self.config.checkers),
                                       timeout=self.config.preprocess_timeout)
            if isinstance(binary, Binary):
                binaries.append(binary)
            self._progress_stage()
        binaries = binaries
        
        l.info(f'[-] {len(binaries)} binaries will be checked against a set of rules soon')
        self._end_stage()
        
        self._start_stage('Analyze target binaries')
        self._init_stage_progress(len(binaries))
        
        for binary in binaries:
            for checker in binary.bound_checkers:
                misuse_reports = checker.check()
                self.report.report_misuses(checker.name, misuse_reports)
            self._progress_stage()
            
        self._end_stage()
        
        report_path = os.path.join(self.config.report_dir,
                                   os.path.basename(self.config.input_path)) + '.log'
        self.report.save(report_path)
        
        l.info(f'Overall report has been save to {report_path}')