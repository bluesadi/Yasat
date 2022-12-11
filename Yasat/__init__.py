from inspect import isfunction
import logging
import os

from .config import Config

l = logging.getLogger('Yasat')
l.setLevel(logging.DEBUG)

def init_logger(config: Config):
    handler = logging.FileHandler(filename=os.path.join(
        config.log_dir, os.path.basename(config.input_path) + '.log'))
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(
        logging.Formatter(fmt='[%(asctime)s] %(message)s', datefmt='%H:%M:%S'))
    l.addHandler(handler)
