import argparse
import pathlib
import shutil

import yaml

from Yasat.task import Task
from Yasat import Config
from Yasat import init_logger
from Yasat import l

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
    
    init_logger(config)
    
    l.info(f'Start task(s) with configuration from {args.config}:\n{config}')
    
    Task(config).run()
    