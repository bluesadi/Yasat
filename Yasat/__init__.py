import os
import logging

from .config import Config
from .binary import Binary
from . import knowledge_plugins, checkers, analyses

logging.getLogger("angr").propagate = False
logging.getLogger("cle").propagate = False
logging.getLogger("pyvex").propagate = False


def init_logger(config: Config):
    root_logger = logging.getLogger("Yasat")
    handler = logging.FileHandler(
        filename=os.path.join(
            config.log_dir, os.path.basename(config.input_path) + ".log"
        )
    )
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(
        logging.Formatter(
            fmt="[%(levelname)s][%(asctime)s] %(message)s", datefmt="%H:%M:%S"
        )
    )
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.DEBUG if config.debug_mode else logging.INFO)
