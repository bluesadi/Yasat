import os
import time
from typing import List, Tuple, Set
import subprocess
import traceback
import logging

import angr
from angr import AngrNoPluginError
from angr.angrdb import AngrDB

from .config import Config
from .utils import Extractor, TimeoutUtil, PrintUtil
from .report import OverallReport
from .knowledge_plugins import Subject
from .analyses.rule_checker import Criterion

l = logging.getLogger(__name__)

class Main:
    config: Config
    report: OverallReport

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.report = OverallReport(self.config.input_path)
        self._time_records = {}

    def _start_timer(self, tag):
        self._time_records[tag] = time.perf_counter()
        
    def _end_timer(self, tag):
        return int(time.perf_counter() - self._time_records[tag])

    def start(self):
        try:
            # return TimeoutUtil.call_with_timeout(self._start, args=(), timeout=self.config.timeout)
            return self._start()
        except:
            l.error(traceback.format_exc())
        return self.report

    def _start(self):
        self._start_timer("total")
        """
        Step 1: Parse checkers configuration
        - `parsed_target_apis`: A set of names of all target APIs
        - `parsed_checkers`: A list of tuples consisting of checker's name, description and analyzing criteria
        """
        parsed_target_apis: Set[str] = set()
        parsed_checkers: List[str, str, List[Criterion]] = []
        for checker_name in self.config.checkers:
            checker_conf = self.config.checkers[checker_name]
            if not checker_conf["enable"]:
                continue
            desc = checker_conf["desc"]
            criteria: list[Criterion] = []
            for func_name in checker_conf["criteria"]:
                criterion = checker_conf["criteria"][func_name]
                lib = criterion["lib"]
                arg_idx = criterion["arg_idx"]
                criteria.append(Criterion(lib, arg_idx, func_name))
                parsed_target_apis.add(func_name)
            parsed_checkers.append((checker_name, desc, criteria))
        l.info(f"Parsed {len(parsed_checkers)} checkers from configuration")
        
        """
        Step 2: Extract ELF binaries
        - Try to decompress the given file (if the given file is an achieve file, e.g., zip).
        - Try to extract ELF executables from the given file (if the given file is a firmware image) or the decompressed
          files.
        - Do nothing if the given file is already an ELF executable.
        - Save all the ELF executable(s) from to `config.tmp_dir` for subsequent procedures.
        """
        paths = Extractor().extract(self.config.input_path, self.config.tmp_dir)
        l.info(f"Extracted {len(paths)} ELF binaries")

        """
        Step 3: Load and check extracted binaries
        - For each path in `paths` list, check whether the ELF binary at this path imports any of the cryptographic APIs
          specified in `config.checkers`. If not, discard it.
        - Then create a Binary instance for each of the rest.
        - If the whole process of creating a binary costs more than `config.preprocess_timeout` seconds, also discard it
          because the binary might be too large to finish analyzing within acceptable time.
        - Instantiating a Binary could be rather slow. That's basically because the CFG generation process takes 
          a lot of time.
        """
        for path in paths:
            # Quickly check if target APIs are possibly imported by nm command
            syms = subprocess.check_output(["nm", "-D", path]).decode().split("\n")
            selected = False
            for sym in syms:
                if len(sym.split()) >= 2:
                    type, funcname = sym.split()[-2:]
                    if type == "U" and funcname in parsed_target_apis:
                        selected = True
            l.info(f"{'Analyzing' if selected else 'Discarded'} {path}")
            # If the ELF at `path` is likely to import any target APIs
            if selected:
                def analyze():
                    # Load project from .adb file if applicable
                    db_path = os.path.join(self.config.db_dir, os.path.basename(path) + ".adb")
                    if os.path.exists(db_path):
                        proj = AngrDB().load(db_path)
                        l.info(f"[-] Loaded angr project from {db_path}")
                    else:
                        proj = angr.Project(path, load_options={"auto_load_libs": False})
                    for checker_name, desc, criteria in parsed_checkers:
                        try:
                            checker_type = proj.analyses.get_plugin(checker_name)
                        except AngrNoPluginError:
                            l.error(f"No such checker: {checker_name}")
                            continue
                        checker = checker_type(desc, criteria)
                        self._start_timer("check")
                        misuses = checker.check()
                        l.info(f"[-] Found {len(misuses)} misuses by {checker_name} in {self._end_timer('check')} seconds")
                        self.report.report_misuses(checker_name, misuses)
                    AngrDB(proj).dump(db_path)
                self._start_timer("analyze")
                TimeoutUtil.call_with_timeout(analyze, args=(), timeout=self.config.analyzing_timeout)
                l.info(f"Finished analyzing {path} in {self._end_timer('analyze')} seconds")
            
        """
        Step 4: Save overall report of misuses to `report path` and mark this task as finished
        """   
        time_cost = self._end_timer("total")
        l.info(f"Total time cost: {time_cost} seconds")
        
        report_path = (
            os.path.join(
                self.config.report_dir, os.path.basename(self.config.input_path)
            )
            + ".log"
        )
        
        if self.report.num_misuses > 0:
            self.report.save(report_path)
            l.info(f"Overall report has been saved to {report_path}")
        else:
            l.info(f"No misuses are found in {self.config.input_path}")

        self.report.report_time_cost(time_cost)
        self.report.finished = True
        
        return self.report
