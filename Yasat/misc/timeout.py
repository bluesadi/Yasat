from typing import Callable
import logging
import threading
import multiprocessing as mp

l = logging.getLogger(__name__)

class CallWithTimeout:
    
    def __init__(self, func: Callable, args, timeout):
        self.result = None
        self.timeout = False
        self._exception = None
        
        self._call_with_timeout(func, args, timeout)
    
    def _call_with_timeout(self, func, args, timeout):
        def wrapper():
            try:
                self.result = func(*args)
            except Exception as e:
                self._exception = e
            
        worker = threading.Thread(target=wrapper, daemon=True)
        # worker = mp.Process(target=wrapper, daemon=True)
        worker.start()
        worker.join(timeout=timeout)
        
        if worker.is_alive():
            self.timeout = True
            
        if self._exception is not None:
            raise self._exception