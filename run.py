import argparse
import pathlib
import shutil
import os
from multiprocessing import Pool, cpu_count
import multiprocessing as mp
import traceback
import logging
import pathlib

import yaml

from Yasat.main import Main
from Yasat import Config
from Yasat.report import OverallReport

l = logging.getLogger("Yasat.entry")

def init_logger():
    
    class LevelFilterer(logging.Filterer):
    
        def __init__(self, levelno):
            super().__init__()
            self.levelno = levelno
        
        def filter(self, record: logging.LogRecord) -> bool:
            return record.levelno == self.levelno
        
    for filename in ("__run__.log", "__error__.log", "__warning__.log", "__report__.log"):
        pathlib.Path(filename).unlink(missing_ok=True)
        
    handler = logging.FileHandler(filename="__run__.log")
    handler.setLevel(logging.DEBUG)
    l.addHandler(handler)
    l.setLevel(logging.DEBUG)
    
    root = logging.getLogger("Yasat")
    err_handler = logging.FileHandler(filename="__error__.log")
    err_handler.setLevel(logging.ERROR)
    root.addHandler(err_handler)
    
    warning_handler = logging.FileHandler(filename="__warning__.log")
    warning_handler.setLevel(logging.WARNING)
    warning_handler.addFilter(LevelFilterer(logging.WARNING))
    root.addHandler(warning_handler)
    
    root.setLevel(logging.DEBUG)

if __name__ == "__main__":
    init_logger()

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c", "--config", help="configuration file path", default="config.yml"
    )
    parser.add_argument(
        "-p",
        "--processes",
        help="the maximum number of processes used for analyzing input files",
        type=int,
        default=cpu_count() // 2,
    )
    args = parser.parse_args()

    with open(args.config, "r") as fd:
        yaml_config = yaml.safe_load(fd)

    config = Config(yaml_config)

    for path in [config.tmp_dir, config.report_dir, config.log_dir]:
        shutil.rmtree(path, ignore_errors=True)
        pathlib.Path(path).mkdir(parents=True, exist_ok=True)

    def run_with_config(config: Config):
        return Main(config).start()

    # When the input path is a file, simply run on it
    if os.path.isfile(config.input_path):
        run_with_config(config)
    # When the input path is a dir, recursively traverse and run on all files in it
    elif os.path.isdir(config.input_path):
        config_list = []
        for dirpath, dirnames, filenames in os.walk(config.input_path):
            rel_path = os.path.relpath(dirpath, config.input_path)
            for filename in filenames:
                # Reset config to avoid path conflict
                new_config = Config(yaml_config)
                new_config.input_path = os.path.normpath(
                    os.path.join(dirpath, filename)
                )
                new_config.log_dir = os.path.normpath(
                    os.path.join(config.log_dir, rel_path)
                )
                new_config.tmp_dir = os.path.normpath(
                    os.path.join(os.path.join(config.tmp_dir, rel_path), filename)
                )
                new_config.report_dir = os.path.normpath(
                    os.path.join(config.report_dir, rel_path)
                )
                new_config.db_dir = os.path.normpath(
                    os.path.join(os.path.join(config.db_dir, rel_path), filename)
                )
                for path in [
                    new_config.tmp_dir,
                    new_config.report_dir,
                    new_config.log_dir,
                    new_config.db_dir
                ]:
                    shutil.rmtree(path, ignore_errors=True)
                    pathlib.Path(path).mkdir(parents=True, exist_ok=True)
                config_list.append(new_config)
        if args.processes <= 1:
            for config in config_list:
                run_with_config(config)
        else:
            pool = Pool(args.processes)
            try:
                merged_report = OverallReport(config.input_path)
                num_finished = 0
                num_failed = 0
                num_timeout = 0
                num_total = len(config_list)
                
                def callback(report: OverallReport):
                    try:
                        global merged_report
                        global num_finished
                        global num_failed
                        global num_timeout
                        global num_total
                        if report is None:
                            num_timeout += 1
                        elif report.finished:
                            num_finished += 1
                            if report.num_misuses > 0:
                                merged_report = merged_report.merge(report)
                                merged_report.save("__report__.log")
                        else:
                            num_failed += 1
                        l.info(f"Progressing... ({num_finished + num_failed + num_timeout}/{num_total}, {num_finished} finished, {num_failed} failed, {num_timeout} timeouted)")
                    except:
                        l.error(traceback.format_exc())

                results = []
                for config in config_list:
                    result = pool.apply_async(
                        run_with_config, (config,), callback=callback
                    )
                    results.append(result)
                pool.close()
                for result in results:
                    try:
                        result.get(20 * 60)
                    except mp.TimeoutError:
                        l.warning("Timeout after 20 minutes")
                        callback(None)
            except KeyboardInterrupt:
                pool.terminate()
