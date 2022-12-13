from collections import defaultdict

import angr
import ailment

class Binary():
    
    def __init__(self, path):
        self.path = path
        self.proj = angr.Project(self.path, load_options={'auto_load_libs': False})
        self.tasks = defaultdict(list)
        self.should_abort = False
        self.cfg = None     # binary's cfg will be loaded later
    
    def _parse_tasks(self, tasks):
        for task_id in tasks:
            task = tasks[task_id]
            if not task['enable']:
                continue
            for func_name in task['criteria']:
                criterion = task['criteria'][func_name]
                lib = criterion['lib']
                arg = criterion['arg']
                symbol = self.proj.loader.main_object.get_symbol(func_name)
                if symbol is not None and symbol.is_import and lib == symbol.resolvedby.name:
                    self.tasks[task_id].append({
                        'func_name': func_name,
                        'func_addr': symbol.resolvedby.rebased_addr,
                        'arg': arg
                    })
    
    def prepare(self, tasks):
        self._parse_tasks(tasks)
        if len(self.tasks) == 0:
            return False
        self.cfg = self.proj.analyses.CFGFast()
        preds = self.cfg.get_any_node(self.tasks['check_constant_keys'][0]['func_addr']).predecessors
        for node in preds:
            ail_block = ailment.IRSBConverter.convert(
                node.block.vex, ailment.manager.Manager(arch=self.proj.arch))
            print(dir(ail_block))
            for stmt in ail_block.statements:
                if isinstance(stmt, ailment.statement.Call):
                    print(stmt.calling_convention)
        return True