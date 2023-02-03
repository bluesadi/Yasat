import logging
import os

from .config import Config
# from . import knowledge_plugins
from .checkers import constant_keys, constant_salts
from .analyses import backward_slicing
from .knowledge_plugins import clinic_manager
from .binary import Binary

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
