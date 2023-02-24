import argparse
import pathlib
import shutil
import os
from multiprocessing import Pool, cpu_count
import traceback
import logging
import pathlib

l = logging.getLogger('run_dev')

import yaml

from Yasat.main import Main
from Yasat import Config
from Yasat.report import OverallReport
from Yasat.utils import TimeoutUtil

def init_logger():
    for path in ('run_dev.log', 'error.log'):
        pathlib.Path(path).unlink()
        
    handler = logging.FileHandler('run_dev.log')
    handler.setLevel(logging.DEBUG)
    l.addHandler(handler)
    
    root = logging.getLogger('Yasat')
    handler = logging.FileHandler('error.log')
    handler.setLevel(logging.ERROR)
    root.addHandler(handler)

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
                for path in [
                    new_config.tmp_dir,
                    new_config.report_dir,
                    new_config.log_dir,
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

                def callback(report: OverallReport):
                    try:
                        if report.completed:
                            global merged_report
                            merged_report = merged_report.merge(report)
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
                    result.wait()
                merged_report.save(os.path.join(config.report_dir, "report.log"))
            except KeyboardInterrupt:
                pool.terminate()
