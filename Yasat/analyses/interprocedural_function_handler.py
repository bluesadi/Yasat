from typing import Optional, List, Set, Tuple

from angr.analyses.reaching_definitions.function_handler import FunctionHandler
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.analyses.reaching_definitions.reaching_definitions import ReachingDefinitionsAnalysis
from angr.code_location import CodeLocation
from angr.knowledge_plugins.key_definitions.constants import OP_AFTER

class InterproceduralFunctionHandler(FunctionHandler):
    
    def hook(self, analysis: ReachingDefinitionsAnalysis):
        self.analysis = analysis
        self.proj = analysis.project
        return super().hook(analysis)
    
    def print_values(self, state: ReachingDefinitionsState, reg):
        reg_offset = self.proj.arch.registers.get(reg, None)[0]
        print(state.register_definitions)
        values = state.register_definitions.load(reg_offset, size=self.proj.arch.bytes).values()
        print(f'DEBUG: {list(values)}')
    
    def handle_local_function(self,
                              init_state: ReachingDefinitionsState,
                              func_addr: int, call_stack: Optional[List],
                              maximum_local_call_depth: int,
                              visited_blocks: Set[int],
                              dep_graph: DepGraph,
                              src_ins_addr: Optional[int] = None,
                              codeloc: Optional[CodeLocation] = None
                              ) -> Tuple[bool, ReachingDefinitionsState, Set[int], DepGraph]:
        target_func = self.proj.kb.functions[func_addr]
        ret_states = {}
        ret_addrs = [ret_site.addr for ret_site in target_func.ret_sites]
        init_state_copy = init_state.copy()
        init_state_copy.tmp_definitions.clear()
        init_state_copy.tmp_uses.clear()
        def observe_callback(ob_type, addr, state, op_type, stmt=None, block=None):
            if ob_type == 'node' and op_type == OP_AFTER and addr in ret_addrs:
                ret_states[addr] = state
                return True
            return False
        rd = self.proj.analyses.ReachingDefinitions(subject=target_func, 
                                               func_graph=target_func.graph,
                                            #    init_state=init_state_copy,
                                               cc=target_func.calling_convention,
                                               observe_callback=observe_callback,
                                               dep_graph=dep_graph,
                                               call_stack=call_stack,
                                            #    function_handler=InterproceduralFunctionHandler()
                                               )
        ret_states = list(ret_states.values())
        if len(ret_states) > 0:
            ret_state = ret_states[0]
            ret_state.merge(*ret_states[1:])
            self.print_values(init_state, 'sp')
            self.print_values(ret_state, 'r7')
            init_state.live_definitions = ret_state.live_definitions
            return True, init_state, visited_blocks, dep_graph
        return False, init_state, visited_blocks, dep_graph