import json
from typing import Callable
import traceback
import logging

from func_timeout import func_timeout
from func_timeout.exceptions import FunctionTimedOut

from .logger import default_logger

def pstr(obj):
    try:
        return str(json.dumps(obj, indent=2))
    except BaseException:
        print(json.dumps(obj, indent=2))
        return str(obj)
    
def call_with_timeout(func: Callable, args, timeout):
    l = default_logger
    try:
        return func_timeout(timeout, func, args=args)
    except FunctionTimedOut as e:
        l.warn(f'Error occured when executing function {func.__name__}: ' + 
                    f'timed out after {e.timedOutAfter} seconds')
    except BaseException as e:
        l.warn(f'Error occured when executing function {func.__name__}: {e}\n{traceback.print_exc()}')
    return False

def get_logger(obj):
    logger = logging.getLogger(obj.__module__ + "." + obj.__class__.__name__)
    return logger