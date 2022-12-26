import argparse
import copy
import pathlib
import shutil
import os

import yaml

from Yasat.main import Main
from Yasat import Config
from Yasat import init_logger
from Yasat import l
from Yasat.utils.common import pstr

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', 
                        help='load configuration from this path',
                        default='config.yml')
    args = parser.parse_args()
    
    with open(args.config, "r") as fd:
        try:
            yaml_config = yaml.safe_load(fd)
        except yaml.YAMLError:
            print(f'Failed to load configuration from {args.config}')
            
    config = Config(yaml_config)
    
    for path in [config.tmp_dir, config.report_dir, config.log_dir]:
        shutil.rmtree(path, ignore_errors=True)
        pathlib.Path(path).mkdir(parents=True, exist_ok=True)
    
    def run_with_config(config: Config):
        init_logger(config)
        l.info(f'Start task(s) with configuration from {args.config}:\n{pstr(config._yaml_config)}')
        Main(config).start()
        
    # When the input path is a file, simply run on it
    if os.path.isfile(config.input_path):
        run_with_config(config)
    # When the input path is a dir, recursively traverse and run on all files in it
    elif os.path.isdir(config.input_path):
        config_list = []
        for dirpath, dirnames, filenames in os.walk(config.input_path):
            relative_path = dirpath.replace(config.input_path, '', 1)
            for filename in filenames:
                # Reset config to avoid conflict
                config_copy = Config(copy.deepcopy(yaml_config))
                config_copy.input_path = os.path.join(dirpath, filename)
                config_copy.log_dir = os.path.join(config_copy.log_dir, relative_path)
                config_copy.tmp_dir = os.path.join(config_copy.tmp_dir, relative_path)
                config_copy.report_dir = os.path.join(config_copy.report_dir, relative_path)
                for path in [config_copy.tmp_dir, config_copy.report_dir, config_copy.log_dir]:
                    shutil.rmtree(path, ignore_errors=True)
                    pathlib.Path(path).mkdir(parents=True, exist_ok=True)
                config_list.append(config_copy)
        for config in config_list:
            run_with_config(config) 
    