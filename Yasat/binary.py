from collections import defaultdict

import angr
import ailment

from . import l
from .utils.common import pstr

class Binary():
    
    def __init__(self, path):
        self.path = path
        self.proj = angr.Project(self.path, load_options={'auto_load_libs': False})
        self.tasks = defaultdict(list)
        self.should_abort = False
        self.cfg = None     # binary's cfg will be loaded later
        
    def _resolve_external_function(self, func_name, lib):
        obj = self.proj.loader.main_object
        symbol = obj.get_symbol(func_name)
        if symbol is not None and symbol.is_import and lib == symbol.resolvedby.name:
            if func_name in obj.plt:
                return obj.plt[func_name]
            return symbol.resolvedby.rebased_addr
        return None
    
    def _parse_tasks(self, tasks):
        for task_id in tasks:
            task = tasks[task_id]
            if not task['enable']:
                continue
            for func_name in task['criteria']:
                criterion = task['criteria'][func_name]
                lib = criterion['lib']
                arg = criterion['arg']
                func_addr = self._resolve_external_function(func_name, lib)
                if func_addr is not None:
                    self.tasks[task_id].append({
                        'func_name': func_name,
                        'func_addr': func_addr,
                        'arg': arg
                    })
    
    def preprocess(self, tasks):
        self._parse_tasks(tasks)
        if len(self.tasks) == 0:
            return False
        self.cfg = self.proj.analyses.CFGFast()
        preds = self.cfg.get_any_node(self.tasks['check_constant_keys'][0]['func_addr']).predecessors
        for node in preds:
            ail_block = ailment.IRSBConverter.convert(
                node.block.vex, ailment.manager.Manager(arch=self.proj.arch))
            print(ail_block)
            node = self.cfg.get_any_node(0x400544)
            ail_block = ailment.IRSBConverter.convert(
                node.block.vex, ailment.manager.Manager(arch=self.proj.arch))
            print(node.block.vex)
            print(ail_block)
        return True