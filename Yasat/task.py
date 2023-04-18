import os
import time
from typing import Set
import logging

import angr
from angr import AngrNoPluginError
from angr.angrdb import AngrDB

from .checkers import default_checkers
from .utils.files import Files
from .misc.report import Report

l = logging.getLogger(__name__)

READY = "READY"
SUCCESS = "SUCCESS"
FAILURE = "FAILURE"
TIMEOUT = "TIMEOUT"
        
class Task:
    
    filename: str
    _adb_path: str
    _target_apis: Set[str]
    
    def __init__(self, filename, adb_path=None):
        super().__init__()
        self.filename = filename
        self.status = READY
        self.report = Report()
        self.pid = 0
        
        self._adb_path = adb_path
        
        self._target_apis = set()
        for _, criteria in default_checkers.items():
            for func_name, _ in criteria:
                self._target_apis.add(func_name)
                
        self.start_time = 0

    def start(self, global_state):
        self.pid = os.getpid()
        self.start_time = time.perf_counter()
        with global_state.lock:
            global_state.running_tasks[self.pid] = self
        
        # Load project from .adb file if exists
        Files.mkdirs(os.path.dirname(self._adb_path))
        if self._adb_path is not None and os.path.exists(self._adb_path):
            l.info(f"Load angr project from {self._adb_path}")
            proj = AngrDB().load(self._adb_path)
        else:
            proj = angr.Project(self.filename, load_options={"auto_load_libs": False})
        if any(proj.kb.subject.resolve_external_function(target_api) is not None 
                for target_api in self._target_apis):
            for checker_cls, criteria in default_checkers.items():
                name = checker_cls.__name__
                try:
                    checker = proj.analyses.get_plugin(name)
                except AngrNoPluginError:
                    l.error(f"No such checker: {name}")
                    continue
                checker = checker(criteria)
                misuses = checker.check()
                self.report.report_misuses(name, misuses)
                with global_state.lock:
                    global_state.running_tasks[self.pid] = self
            if not os.path.exists(self._adb_path):
                AngrDB(proj).dump(self._adb_path)
            
        self.status = SUCCESS