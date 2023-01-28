from angr.knowledge_plugins.plugin import KnowledgeBasePlugin
from angr.knowledge_base.knowledge_base import KnowledgeBase
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER
from angr.analyses.reaching_definitions.dep_graph import DepGraph

class ArgumentDefinitionManager(KnowledgeBasePlugin):
    
    def __init__(self, kb: KnowledgeBase):
        self.kb = kb
        self.proj = kb._project
        self.cfg = kb.cfgs.get_most_accurate()
    
    def get_arg_defs(self, func_addr, arg_index, type=int):
        results = []
        predecessors = self.cfg.get_predecessors(self.cfg.get_any_node(func_addr))
        for predecessor in predecessors:
            block = self.proj.factory.block(predecessor.addr)
            caller_insn_addr = block.instruction_addrs[-1]
            caller_func_addr = self.kb.functions.floor_func(block.addr).addr
            defs = self.get_arg_defs_by_insn(caller_func_addr=caller_func_addr,
                                             caller_insn_addr=caller_insn_addr, 
                                             arg_index=arg_index, result_type=type)
            defs = [(caller_func_addr, caller_insn_addr, arg_def) for arg_def in defs]
            results += defs
        return results
                        
    def get_arg_defs_by_insn(self, caller_func_addr, caller_insn_addr, arg_index, result_type=int):
        proj = self.kb._project
        arch = proj.arch
        regs = list(arch.argument_registers)
        regs.sort()
        if arg_index < len(regs):
            if not self.kb.defs.has_model(caller_func_addr):
                target_func = self.kb.functions[caller_func_addr]
                model = proj.analyses.ReachingDefinitions(subject=target_func, 
                                                    func_graph=target_func.graph,
                                                    cc=target_func.calling_convention,
                                                    observe_all=True,
                                                    dep_graph=DepGraph(),
                                                    call_stack=[],
                                                    function_handler=InterproceduralFunctionHandler()
                                                    ).model
                proj.kb.defs.model_by_funcaddr[caller_func_addr] = model
            model = self.kb.defs.get_model(caller_func_addr)
            reg_defs = model.observed_results[('insn', caller_insn_addr, OP_BEFORE)].register_definitions
            values = reg_defs.load(regs[arg_index], arch.bytes).values()
            defs = []
            state = proj.factory.entry_state()
            solver = state.solver
            for value in values:
                for def_ in value:
                    if def_.concrete:
                        constant = solver.eval(def_, cast_to=int)
                        if result_type == bytes:
                            constant = state.mem[constant].string.concrete
                        defs.append(constant)
            return defs
        else:
            return []

KnowledgeBasePlugin.register_default('arg_defs', ArgumentDefinitionManager)