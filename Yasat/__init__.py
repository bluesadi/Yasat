import logging
import os

from .config import Config
from .knowledge_plugins import argument_definition_manager
from .checkers import base

logging.getLogger('angr').propagate = False
logging.getLogger('cle').propagate = False
logging.getLogger('pyvex').propagate = False

l = logging.getLogger('Yasat')
l.setLevel(logging.DEBUG)

def init_logger(config: Config):
    handler = logging.FileHandler(filename=os.path.join(
        config.log_dir, os.path.basename(config.input_path) + '.log'))
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(
        logging.Formatter(fmt='[%(levelname)s][%(asctime)s] %(message)s', datefmt='%H:%M:%S'))
    l.addHandler(handler)
