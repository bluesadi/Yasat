import argparse
import os
import multiprocessing as mp
import logging
import signal
import sys
import time
from elftools.elf.elffile import ELFFile

import yaml
from angr.misc.loggers import CuteFormatter

from .task import Task, FAILURE, SUCCESS, TIMEOUT
from .utils.files import Files
from .misc.loggers import MpFileHandler, LevelFilterer
from .misc.global_state import GlobalState
from .misc.extractor import Extractor
from .utils import format_exception

l = logging.getLogger(__name__)

def _get_elf_arch(filename):
    try:
        with open(filename, 'rb') as fd:
            return ELFFile(fd)['e_machine']
    except:
        l.error(f"Failed to parse {filename} as an ELF file")
    return None
    
def _extraction_worker(src, dst):
    """
    Extract ELF files from firmware

    :param src: Firmware path
    :param dst: Output directory
    :return: Extracted file paths and original firmware path
    """
    # First check if cache file is available
    cache_file = os.path.join(dst, os.path.basename(src) + ".cache")
    if os.path.isfile(cache_file):
        l.info(f"Lol! Extraction cache file {cache_file} is available!!!")
        with open(cache_file, "r") as fd:
            return fd.read().splitlines(), src
    else:
        l.info(f"Extracting from {src}")
        try:
            elf_paths = Extractor().extract(src, dst)
            with open(cache_file, "w") as fd:
                fd.write("\n".join(elf_paths))
            return elf_paths, src
        except BaseException as e:
            l.error(f"Error occured when extracting from {src}")
            l.error(format_exception(e))
    return [], src

def _analysis_worker(task: Task, global_state: GlobalState):
    l.info(f"Analyzing {task.filename}")
    try:
        task.start(global_state)
    except BaseException as e:
        l.error(f"Analyzing {task.filename} failed with exception")
        l.error(format_exception(e))
        task.status = FAILURE
    return task

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
    
    # Load configuration
    with open(args.config, "r") as fd:
        config = yaml.safe_load(fd)
    input_path = config["input_path"]
    tmp_dir = config["tmp_dir"]
    out_dir = os.path.abspath(config["out_dir"])
    timeout = config["timeout"]
    
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
        pool = mp.Pool(args.processes)
        global_state = GlobalState()
        report = global_state.report
        start_time = time.perf_counter()
        
        def _collect_subjects():
            """
            First step. Extract ELF files (subjects) from firmware

            :return: Extracted file paths
            """
            firmware_paths = []
            # The path is a file or directory?
            if os.path.isfile(input_path):
                firmware_paths.append(input_path)
            elif os.path.isdir(input_path):
                for dirpath, _, filenames in os.walk(input_path):
                    for filename in filenames:
                        firmware_paths.append(Files.join(dirpath, filename))
            subjects = []
            def on_extraction_done(args):
                elf_paths, firmware_path = args
                progress = lambda : (f"[{report.extraction_success + report.extraction_failure}/"
                                     f"{len(firmware_paths)} "
                                     f"({report.extraction_success} success, "
                                     f"{report.extraction_failure} failure)] ")
                # We say it failure when no ELF files are extracted
                if len(elf_paths) == 0:
                    report.extraction_failure += 1
                    l.warning(f"{progress()}Failed to extract ELF files from {firmware_path}")
                else:
                    report.extraction_success += 1
                    l.info(f"{progress()}Extracted {len(elf_paths)} ELF files from {firmware_path}")
                subjects.extend(elf_paths)
                    
            results = []
            for firmware_path in firmware_paths:
                results.append(pool.apply_async(_extraction_worker, args=(firmware_path, tmp_dir), 
                                                callback=on_extraction_done))
            for result in results:
                result.wait()
                
            l.info(f"Extraction completed")
            return subjects
                
        subjects = _collect_subjects()
        num_subjects = len(subjects)
        
        # Discard redundant subjects with the same architectures and filenames
        collected = set()
        _subjects = []
        discarded = 0
        for i, filename in enumerate(subjects):
            l.info(f"[{i + 1}/{num_subjects} {discarded} discarded] "
                   "Filtering out redundant subjects")
            t = (_get_elf_arch(filename), os.path.basename(filename))
            if t[0] is None or t in collected:
                discarded += 1
                continue
            collected.add(t)
            _subjects.append(filename)
        subjects = _subjects
        num_subjects = len(subjects)
        
        def _analyze_subjects():
            
            def on_analysis_done(task: Task):
                # if task.status != TIMEOUT:
                #     l.debug(f"Analyzing {task.filename} completed in "
                #             f"{int(time.perf_counter() - task.start_time)} seconds")
                if task.status == TIMEOUT:
                    report.analysis_timeout += 1
                    try:
                        os.kill(task.pid, signal.SIGKILL)
                    except OSError as e:
                        l.error(e)
                elif task.status == SUCCESS:
                    report.analysis_success += 1
                elif task.status == FAILURE:
                    report.analysis_failure += 1
                else:
                    l.error("This should never happen!")
                progress = (f"[{report.analysis_total}/ {num_subjects} "
                            f"({report.analysis_success} success, "
                            f"{report.analysis_failure} failure, "
                            f"{report.analysis_timeout} timeout)] ")
                l.info(f"{progress}Discovered {task.report.num_misuses} misuses in {task.filename}"
                       f"\n{task.report.summary}")
                if task.report.num_misuses > 0:
                    report.merge(task.report)
                    report.time = int(time.perf_counter() - start_time)
                    report.save(Files.join(out_dir, "report.log"))
                del global_state.running_tasks[task.pid]
            
            for filename in subjects:
                task = Task(filename=filename, adb_path=filename + ".adb")
                pool.apply_async(_analysis_worker, args=(task, global_state), 
                                 callback=on_analysis_done)
                
            while True:
                if report.analysis_total == num_subjects:
                    break
                with global_state.lock:
                    for task in list(global_state.running_tasks.values()):
                        if int(time.perf_counter() - task.start_time) > timeout:
                            task.status = TIMEOUT
                            # l.debug(f"Analyzing {task.filename} timed out")
                            on_analysis_done(task)
                num_running = len(global_state.running_tasks.items())
                l.info(f"There are {num_running} tasks running now "
                       f"({report.analysis_success} success, {report.analysis_failure} failure, "
                       f"{report.analysis_timeout} timeout, "
                       f"{num_subjects - report.analysis_total - num_running} pending)")
                time.sleep(1)
                
        _analyze_subjects()
        
        l.info("All done!!!")    
        l.info("\n" + report.summary)                
        
    except BaseException as e:
        l.error(format_exception(e))