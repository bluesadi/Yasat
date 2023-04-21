from typing import Dict, Any
import multiprocessing as mp

from .report import Report
from ..task import Task

class GlobalState:
    
    running_tasks: Dict[int, Task]
    shared: Dict[Any, Any]
    
    def __init__(self):
        manager = mp.Manager()
        self.running_tasks = manager.dict()
        self.shared = manager.dict()
        self.report = Report()
        self.lock = manager.Lock()
        self.shared_lock = manager.Lock()