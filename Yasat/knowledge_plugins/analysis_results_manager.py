from angr.knowledge_plugins.plugin import KnowledgeBasePlugin
from angr.knowledge_base.knowledge_base import KnowledgeBase
import angr.analyses.reaching_definitions.dep_graph as dep_graph
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE

class AnalysisResultsManager(KnowledgeBasePlugin):
    
    def __init__(self, kb: KnowledgeBase):
        self.kb = kb
        
    def get_arg_defs(self, func_addr, insn_addr, index, type=int):
        proj = self.kb._project
        arch = proj.arch
        regs = list(arch.argument_registers)
        regs.sort()
        if index < len(regs):
            model = self.kb.defs.get_model(func_addr)
            if model is None:
                target_func = self.kb.functions[func_addr]
                proj.analyses.ReachingDefinitions(subject=target_func, 
                                                  func_graph=target_func.graph,
                                                  cc = target_func.calling_convention,
                                                  observe_all=True,
                                                  dep_graph = dep_graph.DepGraph())
                model = self.kb.defs.get_model(func_addr)
                
            reg_defs = model.observed_results[('insn', insn_addr, OP_BEFORE)].register_definitions
            values = reg_defs.load(regs[index], arch.bytes).values()
            defs = []
            state = proj.factory.entry_state()
            solver = state.solver
            for value in values:
                for def_ in value:
                    if def_.concrete:
                        constant = solver.eval(def_, cast_to=int)
                        if type == bytes:
                            constant = state.mem[constant].string.concrete
                        defs.append(constant)
            return defs
        else:
            return []

KnowledgeBasePlugin.register_default('analysis_results', AnalysisResultsManager)