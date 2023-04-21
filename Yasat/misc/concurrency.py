import multiprocessing as mp
from typing import Dict
import time
import os
import logging
import signal
import psutil

from ..utils.format import format_exception

l = logging.getLogger(__name__)

class GlobalState:
    
    running_workers: Dict[int, "Worker"]
    
    def __init__(self):
        manager = mp.Manager()
        self.running_workers = manager.dict()
        self.lock = manager.Lock()

RUNNING = "RUNNING"
SUCCESS = "SUCCESS"
FAILURE = "FAILURE"
TIMEOUT = "TIMEOUT"

class Worker:
    _global_state: GlobalState
    
    def __init__(self, name):
        super().__init__()
        self.name = name
        self.status = None
        self.pid = 0
        self.result = None
        
        self._global_state = None
        self._start_time = 0
        
    @property
    def running_time(self):
        return int(time.perf_counter() - self._start_time)
    
    def start(self):
        self.pid = os.getpid()
        self._start_time = time.perf_counter()
        self.status == RUNNING
        with self._global_state.lock:
            self._global_state.running_workers[self.pid] = self
        try:
            self.result = self.run()
            self.status = SUCCESS
        except BaseException as e:
            self.status = FAILURE
            l.error(f"Error occured in {self.name}")
            l.error(format_exception(e))
        with self._global_state.lock:
            del self._global_state.running_workers[self.pid]
        return self

    def run(self):
        raise NotImplementedError("run() is not implemented.")
    
def _func_wrapper(worker):
    return worker.start()
    
class PoolWrapper:
    
    def __init__(self, processes, maxtasksperchild=None):
        self._pool = mp.Pool(processes, maxtasksperchild=maxtasksperchild)
        self.global_state = GlobalState()
        self._pending_workers = 0
        
        def default_callback(_):
            self._pending_workers -= 1
        self._callback = default_callback
       
    def set_callback(self, callback):
        def wrapper(worker):
            self._pending_workers -= 1
            callback(worker)
        self._callback = wrapper
        
    def apply_async(self, worker: Worker):
        worker._global_state = self.global_state
        self._pending_workers += 1
        self._pool.apply_async(_func_wrapper, args=(worker,), callback=self._callback)
        
    def wait(self, timeout=0):
        while True:
            self.global_state.lock.acquire()
            try:
                num_running_workers = len(self.global_state.running_workers)
                if num_running_workers == 0 and self._pending_workers == 0:
                    break
                l.info(f"There are {num_running_workers} tasks running now "
                    f"({self._pending_workers - num_running_workers} pending)")
                l.info(f"|{'pid'.center(8)}|{'name'.center(40)}|{'running time'.center(15)}|"
                    f"{'memory'.center(10)}|")
                for worker in self.global_state.running_workers.values():
                    try:
                        pid = str(worker.pid)
                        name = worker.name
                        running_time = str(worker.running_time) + " seconds"
                        memory = str(psutil.Process(worker.pid).memory_info().rss // 1024 // 1024)
                        memory += " MB"
                        l.info(f"|{pid.center(8)}|{name.center(40)}|{running_time.center(15)}|"
                            f"{memory.center(10)}|")
                        if timeout > 0 and worker.running_time > timeout:
                            l.warning(f"Timeout in {worker.name}")
                            worker.status = TIMEOUT
                            self._callback(worker)
                            del self.global_state.running_workers[worker.pid]
                            os.kill(worker.pid, signal.SIGKILL)
                    except (OSError, psutil.NoSuchProcess) as e:
                        l.error(f"Failed to kill {worker.pid}")
                        l.error(format_exception(e))
            except BaseException as e:
                l.error(format_exception(e))
            finally:
                self.global_state.lock.release()
            time.sleep(1)
            
    def close(self):
        self._pool.close()
        
    def terminate(self):
        self._pool.terminate()