import logging
import os

logging.getLogger("angr").propagate = False
logging.getLogger("cle").propagate = False
logging.getLogger("pyvex").propagate = False

def get_logger(name: str):
    return logging.getLogger(name.replace("Yasat", f"Yasat.task-{os.getpid()}", 1))

def init_logger(config):
    root = logging.getLogger(f"Yasat.task-{os.getpid()}")
    root.handlers.clear()
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
    root.addHandler(handler)
    
    root.setLevel(logging.DEBUG if config.debug_mode else logging.INFO)