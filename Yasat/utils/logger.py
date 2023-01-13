import logging

class LoggerMixin:
    
    def __init__(self):
        self.l = logging.getLogger(self.__module__ + "." + self.__class__.__name__)
        
default_logger = logging.getLogger('Yasat')