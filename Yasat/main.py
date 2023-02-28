import os
import time
from typing import List, Tuple
import logging
import subprocess
import traceback

from .config import Config
from .utils import Extractor, TimeoutUtil, PrintUtil
from .report import OverallReport
from .binary import Binary
from .checkers.base import Criterion
from .logging import get_logger, init_logger

l = get_logger(__name__)


class Main:
    config: Config
    report: OverallReport

    _parsed_checkers: List[Tuple[str, str, List[Criterion]]]
    _parsed_target_apis = set()

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.report = OverallReport(config.input_path)
        self._stage_id = 0
        self._stage_desc = "Not started yet"
        self._stage_start = 0
        self._parsed_checkers = []

    def _parse_checkers(self):
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
                self._parsed_target_apis.add(func_name)
            self._parsed_checkers.append((checker_name, desc, criteria))

    def _start_stage(self, stage_desc):
        self._stage_id += 1
        self._stage_desc = stage_desc
        l.info(PrintUtil.fill80(f"Stage {self._stage_id} - {stage_desc}"))
        self._stage_start = time.process_time()

    def _end_stage(self):
        stage_cost = time.process_time() - self._stage_start
        self.report.report_time_cost(self._stage_desc, stage_cost)
        l.info(
            PrintUtil.fill80(
                f"Stage {self._stage_id} Finished - Cost {stage_cost:.1f} seconds"
            )
        )

    def start(self):
        try:
            return self._start()
        except:
            l.error(traceback.format_exc())
        return self.report

    def _start(self):
        """
        Initialize logger
        """
        init_logger(self.config)
        """
        Stage 1:
        - Try to decompress the given file (if the given file is an achieve file, e.g., zip).
        - Try to extract ELF executables from the given file (if the given file is a firmware image)
          or the decompressed files.
        - Do nothing if the given file is already an ELF executable.
        - Save all the ELF executable(s) from to `config.tmp_dir` for subsequent procedures.
        """
        self._start_stage(f"Extract ELF binaries from {self.config.input_path}")

        binary_paths = Extractor().extract(self.config.input_path, self.config.tmp_dir)

        l.info(f"[-] Extracted {len(binary_paths)} ELF binaries")
        self._end_stage()

        """
        Stage 2:
        - For each binary_path in `binary_paths` list, check whether the binary of this path imports any of 
          cryptographic APIs specified in `config.checkers`. If not, discard it.
        - Then create a Binary instance for each of the rest.
        - If the whole process of creating a binary costs more than `config.preprocess_timeout` seconds, also discard it
          because the binary might be too large to finish analyzing within acceptable time.
        - Instantiating a Binary could be rather slow. That's basically because the CFG generation process takes 
          a lot of time.
        """
        self._start_stage("Preprocess target binaries")

        self._parse_checkers()
        l.info(f"[-] Parsed {len(self._parsed_checkers)} checkers from configuration")

        def preprocess_binary():
            binary = Binary(path)
            binary.bind_checkers(self._parsed_checkers)
            if len(binary.bound_checkers) > 0:
                binary.setup_cfg()
                binaries.append(binary)
                return True
            return False

        binaries: List[Binary] = []
        for path in binary_paths:
            """
            Quickly check if target APIs are possibly imported by nm command
            """
            try:
                a = time.process_time()
                syms = subprocess.check_output(["nm", "-D", path]).decode().split("\n")
                selected = False
                for sym in syms:
                    if len(sym.split()) >= 2:
                        type, funcname = sym.split()[-2:]
                        if type == "U" and funcname in self._parsed_target_apis:
                            selected = TimeoutUtil.call_with_timeout(
                                preprocess_binary,
                                args=(),
                                timeout=self.config.preprocess_timeout,
                            )
                            break
                b = time.process_time()
                l.info(
                    f"[-] {'Selected' if selected else 'Discarded'} {path} in {b-a:.1f} seconds"
                )
            except:
                l.error(f"Error occured when preprocessing {path}")
                l.error(traceback.format_exc())

        l.info(
            f"[-] {len(binaries)} binaries will be checked against a set of rules soon"
        )
        self._end_stage()

        self._start_stage("Analyze target binaries")

        def analyze_binary(binary):
            for checker in binary.bound_checkers:
                misuse_reports = checker.check()
                self.report.report_misuses(checker.name, misuse_reports)

        for binary in binaries:
            l.info(f"[-] Start analizing {binary.path}")
            TimeoutUtil.call_with_timeout(
                analyze_binary, args=(binary,), timeout=self.config.analyze_timeout
            )

        self._end_stage()

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

        self.report.completed = True
        return self.report
