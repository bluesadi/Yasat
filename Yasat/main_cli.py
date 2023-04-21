import argparse
import os
import multiprocessing as mp
import logging
import signal
import sys
import time
import psutil
import struct

import yaml
from angr.misc.loggers import CuteFormatter
import angr
from angr import AngrNoPluginError
from angr.angrdb import AngrDB

from .utils.files import Files
from .misc.loggers import MpFileHandler, LevelFilterer
from .misc.extractor import Extractor
from .misc.report import Report
from .misc.concurrency import *
from .utils import format_exception
from .checkers import default_checkers

l = logging.getLogger(__name__)
    
class ExtractionWorker(Worker):
    
    def __init__(self, src, dst):
        super().__init__(name=os.path.basename(src))
        self.src = src
        self.dst = dst
    
    def run(self):
        src, dst = self.src, self.dst
        # First check if cache file is available
        cache_file = os.path.join(dst, os.path.basename(src) + ".cache")
        if os.path.isfile(cache_file):
            l.info(f"Lol! Found cache file {cache_file}!!!")
            with open(cache_file, "r") as fd:
                return fd.read().splitlines()
        else:
            l.info(f"Extracting ELF files from {src}")
            elf_files = Extractor().extract(src, dst)
            with open(cache_file, "w") as fd:
                fd.write("\n".join(elf_files))
            return elf_files
       
class AnalysisWorker(Worker):
    
    def __init__(self, filename, adb_path=None):
        super().__init__(name=os.path.basename(filename))
        self.filename = filename
        self.report = Report()
        self._target_apis = set()
        self._adb_path = adb_path
        for _, criteria in default_checkers.items():
            for func_name, _ in criteria:
                self._target_apis.add(func_name)
        
    def run(self):
        # Load project from .adb file if exists
        Files.mkdirs(os.path.dirname(self._adb_path))
        if self._adb_path is not None and os.path.exists(self._adb_path):
            proj = AngrDB().load(self._adb_path)
        else:
            proj = angr.Project(self.filename, load_options={"auto_load_libs": False})
        if any(proj.kb.subject.resolve_external_function(target_api) is not None 
                for target_api in self._target_apis):
            for checker_cls, criteria in default_checkers.items():
                name = checker_cls.__name__
                try:
                    checker = proj.analyses.get_plugin(name)
                except AngrNoPluginError:
                    l.error(f"No such checker: {name}")
                    continue
                checker = checker(criteria)
                misuses = checker.check()
                self.report.report_misuses(name, misuses)
            if not os.path.exists(self._adb_path):
                AngrDB(proj).dump(self._adb_path)
        
def main_cli():    
    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c", "--config", help="configuration file path", default="config.yml"
    )
    parser.add_argument(
        "-p",
        "--processes",
        help="the maximum number of processes used for analyzing input files",
        type=int,
        default=mp.cpu_count() // 2,
    )
    args = parser.parse_args()
    
    processes = args.processes
    
    # Load configuration
    with open(args.config, "r") as fd:
        config = yaml.safe_load(fd)
    input_path = config["input_path"]
    tmp_dir = config["tmp_dir"]
    out_dir = os.path.abspath(config["out_dir"])
    extraction_timeout = config["extraction_timeout"]
    analysis_timeout = config["analysis_timeout"]
    
    Files.mkdirs(tmp_dir)
    Files.clear(out_dir)
        
    # Set up loggers
    # logging.root.handlers.clear()
    root = logging.getLogger("Yasat")
    root.setLevel(logging.DEBUG)
    root.addHandler(MpFileHandler())
    for level in (logging.INFO, logging.WARNING, logging.ERROR, logging.DEBUG):
        log_path = Files.join(out_dir, logging.getLevelName(level).lower() + ".log")
        handler = logging.FileHandler(filename=log_path, mode="w")
        handler.addFilter(LevelFilterer(levelno=level))
        handler.setFormatter(CuteFormatter(should_color=False))
        root.addHandler(handler)
    sys.stderr = open(Files.join(out_dir, "stderr.log"), "w")
        
    try:
        report = Report()
        start_time = time.perf_counter()
        ###############################################################
        #   First step: Extract ELF files (subjects) from firmware    #
        ###############################################################
        def on_extraction_done(worker: ExtractionWorker):
            elf_files = []
            if worker.status == TIMEOUT:
                cache_file = os.path.join(worker.dst, os.path.basename(worker.src) + ".cache")
                open(cache_file, "w").close()
                report.extraction_timeout += 1
            elif worker.status == FAILURE or len(worker.result) == 0:
                report.extraction_failure += 1
                l.warning(f"Failed to extract ELF files from {worker.src}")
            else:
                report.extraction_success += 1
                elf_files = worker.result
            progress = (f"[{report.extraction_success + report.extraction_failure}/"
                        f"{num_input_files} ({report.extraction_success} success, "
                        f"{report.extraction_failure} failure, "
                        f"{report.extraction_timeout} timeout)] ")
            # We say it failure when no ELF files are extracted
            l.info(f"{progress}Extracted {len(elf_files)} ELF files from {worker.src}")
            subjects.extend(elf_files)
            
        pool = PoolWrapper(processes)
        pool.set_callback(on_extraction_done)
        input_files = []
        # The path is a file or directory?
        if os.path.isfile(input_path):
            input_files.append(input_path)
        elif os.path.isdir(input_path):
            for dirpath, _, filenames in os.walk(input_path):
                for filename in filenames:
                    input_files.append(Files.join(dirpath, filename))
        num_input_files = len(input_files)
        subjects = []
        for input_file in input_files:
            relpath = os.path.dirname(os.path.relpath(input_file, input_path))
            dst = Files.join(tmp_dir, relpath)
            Files.mkdirs(dst)
            pool.apply_async(ExtractionWorker(input_file, dst))
        pool.close()
        pool.wait(extraction_timeout)
        pool.terminate()
        num_subjects = len(subjects)
        l.info(f"Successfully extracted {num_subjects} ELF files!")
        
        ##########################################################################################
        #   Second step: Filter out redundant ELF files with the same architectures and names    #
        ##########################################################################################
        def read_elf_machine(filepath):
            ELFCLASS32 = 1
            ELFCLASS64 = 2
            ELFMAG = b'\x7fELF'
            with open(filepath, 'rb') as f:
                elf_header = f.read(20)
            if len(elf_header) < 20 or not elf_header.startswith(ELFMAG):
                return None
            elf_class = struct.unpack('B', elf_header[4:5])[0]
            e_machine, = struct.unpack('H', elf_header[18:18+2])
            if elf_class not in [ELFCLASS32, ELFCLASS64] or e_machine > 100:
                return None
            return e_machine
                
        _subjects = []
        discarded = 0
        collected = set()
        excluded = ["openssl", "libssl", "libcrypto"]
        for i, subject in enumerate(subjects):
            l.info(f"[{i + 1}/{num_subjects} {discarded} discarded] Filtering subjects")
            t = (read_elf_machine(subject), os.path.basename(subject))
            if t[0] is None or t in collected or os.path.basename(subject).split(".")[0] in excluded:
                discarded += 1
                continue
            collected.add(t)
            _subjects.append(subject)
        subjects = _subjects
        num_subjects = len(subjects)
        l.info(f"Got {num_subjects} unique ELF files!")
        
        ######################################
        #   Final step: Analyze ELF files    #
        ######################################
                
        def on_analysis_done(worker: AnalysisWorker):
            if worker.status == TIMEOUT:
                report.analysis_timeout += 1
            elif worker.status == FAILURE:
                report.analysis_failure += 1
            else:
                report.analysis_success += 1
            progress = (f"[{report.analysis_total}/ {num_subjects} "
                        f"({report.analysis_success} success, "
                        f"{report.analysis_failure} failure, "
                        f"{report.analysis_timeout} timeout)] ")
            l.info(f"{progress}Discovered {worker.report.num_misuses} misuses in {worker.filename}"
                   f"\n{worker.report.summary}")
            if worker.report.num_misuses > 0:
                report.merge(worker.report)
                report.time = int(time.perf_counter() - start_time)
                report.save(Files.join(out_dir, "report.log"))
            
        pool = PoolWrapper(processes, maxtasksperchild=100)
        pool.set_callback(on_analysis_done)
        
        for filename in subjects:
            pool.apply_async(AnalysisWorker(filename=filename, adb_path=filename + ".adb"))
        pool.close()
        pool.wait(analysis_timeout)
        pool.terminate()
                
        l.info("All done!!!")    
        l.info("\n" + report.summary)                
        
    except BaseException as e:
        l.error(format_exception(e))