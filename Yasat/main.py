import os
import time

from .config import Config
from .utils.extractor import Extractor
from .utils.common import call_with_timeout
from . import l
from .report import OverallReport

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
        
        binaries = Extractor().extract(self.config.input_path, self.config.tmp_dir)
        
        l.info(f'[-] {len(binaries)} binaries will be analyzed soon')
        self._end_stage()
        
        '''
        Stage 2:
        - For each binary in `binaries` list, check whether it imports any of cryptographic APIs
          specified in `config.checkers`. If not, discard it.
        - Then generate a CFG for each of the reset.
        - If the whole process of a binary costs more than `config.preprocess_timeout`, also 
          discard it because the binary might be too large to finish analyzing in acceptable time.
        '''
        self._start_stage('Preprocess target binaries')
        self._init_stage_progress(len(binaries))
        
        binaries_tmp = []
        for i, binary in enumerate(binaries):
            should_keep = call_with_timeout(binary.preprocess, args=(self.config.checkers,),
                                            timeout=self.config.preprocess_timeout)
            if should_keep:
                binaries_tmp.append(binary)
            self._progress_stage()
        binaries = binaries_tmp
        
        l.info(f'[-] {len(binaries)} binaries will be checked against a set of rules soon')
        self._end_stage()
        
        self._start_stage('Analyze target binaries')
        self._init_stage_progress(len(binaries))
        
        for i, binary in enumerate(binaries):
            binary.analyze(self.report)
            self._progress_stage()
            
        self._end_stage()
        
        report_path = os.path.join(self.config.report_dir,
                                   os.path.basename(self.config.input_path)) + '.log'
        self.report.save(report_path)
        
        l.info(f'Overall report has been save to {report_path}')