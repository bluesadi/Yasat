from inspect import isfunction
import logging
import os

l = logging.getLogger('Yasat')
l.setLevel(logging.DEBUG)

class LevelFilter(logging.Filter):
    
    def __init__(self, cond):
        self.cond = cond
    
    def filter(self, record):
        if isfunction(self.cond):
            return self.cond(record)
        return record.levelno == self.cond

def init_loggers():
    info_handler = logging.FileHandler(
        filename=os.path.join(config.log_dir, os.path.basename(config.input_path) + '.log'))
    info_handler.setLevel(logging.INFO)
    info_handler.setFormatter(
        logging.Formatter(fmt='[%(asctime)s] %(message)s', datefmt='%H:%M:%S'))
    info_handler.addFilter(LevelFilter(lambda record : record.levelno >= logging.INFO))
    
    debug_handler = logging.FileHandler(
        filename=os.path.join(config.log_dir, os.path.basename(config.input_path) + '_debug.log'))
    debug_handler.setLevel(logging.DEBUG)
    debug_handler.setFormatter(
        logging.Formatter(fmt='[%(asctime)s] - %(pathname)s:%(lineno)d -> %(message)s', 
                          datefmt='%H:%M:%S'))
    debug_handler.addFilter(LevelFilter(logging.DEBUG))
    
    l.addHandler(info_handler)
    l.addHandler(debug_handler)

class Config:
    
    tmp_dir: str
    input_path: str
    report_dir: str
    log_dir: str
    
config = Config()

class KnowledgeBase:
    
    def __init__(self):
        self.sym_links = {}
        
kb = KnowledgeBase()