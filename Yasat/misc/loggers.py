import logging

from angr.misc.loggers import CuteFormatter

class LevelFilterer(logging.Filterer):
    def __init__(self, levelno):
        super().__init__()
        self.levelno = levelno

    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno == self.levelno

class MpFileHandler(logging.Handler):
    """
    Custom FileHandler for multiprocessing loggers
    """
    
    _output_files = {}
    
    def __init__(self):
        super().__init__()
        self.setFormatter(CuteFormatter(should_color=False))
        
    @staticmethod
    def set_output_file(pid, fd):
        MpFileHandler._output_files[pid] = fd
        
    def emit(self, record: logging.LogRecord):
        pid = record.process
        if pid in MpFileHandler._output_files:
            fd = MpFileHandler._output_files[pid]
            fd.write(self.format(record))
