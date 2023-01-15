import logging

class LoggerMixin:
    
    def __init__(self):
        self.l = logging.getLogger(self.__module__ + "." + self.__class__.__name__)
        
class LoggerMetaclass(type):
    
    def __new__(cls, name, bases, attrs):
        attrs['l'] = logging.getLogger(cls.__module__ + "." + cls.__name__)
        return type.__new__(cls, name, bases, attrs)
    
default_logger = logging.getLogger('Yasat')