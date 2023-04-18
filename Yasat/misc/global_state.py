from typing import Dict
import multiprocessing as mp

from .report import Report
from ..task import Task

class GlobalState:
    
    running_tasks: Dict[int, Task]
    
    def __init__(self):
        manager = mp.Manager()
        self.running_tasks = manager.dict()
        self.report = Report()
        self.lock = manager.Lock()