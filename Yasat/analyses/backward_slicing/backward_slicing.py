from typing import Dict, Set, List, Any, Tuple
from collections import defaultdict

from networkx import DiGraph
from angr.analyses.analysis import Analysis
from angr.analyses.decompiler.clinic import Clinic
from ailment import Block
from ailment.expression import Expression
from angr.knowledge_plugins.functions import Function
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from angr.sim_variable import SimVariable

from .slicing_state import SlicingState, SlicingTrack
from .engine_ail import SimEngineBackwardSlicing
from .criteria_selector import CriteriaSelector
from .function_handler import InterproceduralFunctionHandler, FunctionHandler

class SlicingCriterion:
    
    def __init__(self, caller_addr: int, arg_idx: int):
        self.caller_addr = caller_addr
        self.arg_idx = arg_idx
        

class BackwardSlicing(Analysis):
    
    target_func: Function
    criteria_selectors: List[CriteriaSelector]
    preset_arguments: List[Tuple[SimVariable, MultiValues]]
    function_handler: FunctionHandler
    graph: DiGraph
    concrete_results: Set[SlicingTrack]
    
    _max_iterations: int
    _max_call_depth: int
    _entry_block: Block
    _should_abort: bool
    _blocks_by_addr: Dict[int, Block]
    _output_states_by_addr: Dict[int, SlicingState]
    _engine: SimEngineBackwardSlicing
    _node_iterations: Dict[int, int]
    
    def __init__(self, 
                 target_func,
                 criteria_selectors,
                 preset_arguments=[],
                 function_handler=InterproceduralFunctionHandler(),
                 max_iterations=5,
                 max_call_depth=2) -> None:
        super().__init__()
        self.target_func = target_func
        self.criteria_selectors = criteria_selectors
        self.preset_arguments = preset_arguments
        self.function_handler = function_handler
        
        if criteria_selectors is None or len(criteria_selectors) == 0:
            raise ValueError('You should set up at least 1 criteria selector.')
        
        # Bind this analysis to slicing citeria selectors
        for selector in criteria_selectors:
            selector.hook(self)
        
        self._max_iterations = max_iterations
        self._max_call_depth = max_call_depth
        
        # Get or generate CFG
        cfg = self.project.kb.cfgs.get_most_accurate()
        if cfg is None:
            cfg = self.project.analyses.CFGFast(resolve_indirect_jumps=True, 
                                                force_complete_scan=False, 
                                                normalize=True)
        
        # That's for recovering prototypes of callees in this function, in order to achieve a higher accuracy
        # e.g., sometimes Clinic analysis cannot correctly deduce callees' stack arguments
        for addr in self.project.kb.callgraph[target_func.addr]:
            if target_func.name == 'div':
                print('div')
            self.project.kb.clinic_manager.get_clinic(addr)
            if target_func.name == 'div':
                print('div end')
            
        # Generate the AIL CFG for the target function
        clinic: Clinic = self.project.kb.clinic_manager.get_clinic(target_func)
            
        self.preset_arguments = list(zip(clinic.arg_list, preset_arguments))
        
        self.graph = clinic.graph.copy()
        
        self._blocks_by_addr = dict()
        self._output_states_by_addr = dict()
        
        # Initialize address-block mappings and output states
        for block in self.graph:
            self._blocks_by_addr[block.addr] = block
            self._output_states_by_addr[block.addr] = self._initial_state(block)
        
        self._engine = SimEngineBackwardSlicing(self)
        self._node_iterations = defaultdict(int)
        self.concrete_results = set()
        self._analyze()
        
    def _initial_state(self, block: Block):
        return SlicingState(analysis=self,
                            block=block)
    
    def _meet_successors(self, block: Block):
        output_states_of_succs = [self._output_states_by_addr[succ.addr] for succ in self.graph.successors(block)]
        if len(output_states_of_succs) == 1:
            state = output_states_of_succs[0]
        elif len(output_states_of_succs) > 1:
            state = output_states_of_succs[0].merge(*output_states_of_succs[1:])
        else:
            state = self._initial_state(block)
        state.block = block
        state.addr = block.addr
        return state
    
    def _analyze(self):
        
        working_queue = sorted(self._blocks_by_addr.keys(), reverse=True)
        pending_queue = set(self._blocks_by_addr.keys())
        last_states = {}
        while working_queue:
            block = self._blocks_by_addr[working_queue.pop(0)]
            pending_queue.discard(block.addr)
            # Current block's out-state (input state) is merged from the sucessors' in-states (output states).
            state = self._meet_successors(block)
            
            # We set a limitation of iterations to avoid stucking in infinite loop
            self._node_iterations[block.addr] += 1
            
            last_states[block.addr] = state
            if self._node_iterations[block.addr] > self._max_iterations:
                continue
            state = self._run_on_node(state)
            last_states[block.addr] = state
            
            old_state = self._output_states_by_addr[block.addr]
            # Update output state
            self._output_states_by_addr[block.addr] = state
            
            if old_state.num_tracks != state.num_tracks or old_state.num_concrete_tracks != state.num_concrete_tracks:
                # Since we only add new track to state.tracks or move track from state.tracks to state.concrete_tracks,
                # if state has changed, either state.tracks or state.concrete_tracks must have changed as well.
                # When state has changed, revisit all it's predecessors.
                
                revisit_iter = filter(lambda pred : pred.addr not in pending_queue,
                                      self.graph.predecessors(block))
                working_queue += list(block.addr for block in revisit_iter)
                pending_queue |= set(block.addr for block in revisit_iter)
        
        # Collect concrete results from the last state of each block
        for state in last_states.values():
            self.concrete_results |= state.concrete_results
        
    def _run_on_node(self, state: SlicingState) -> SlicingState:
        return self._engine.process(state.copy(), block=state.block)
    
from angr import AnalysesHub
AnalysesHub.register_default('BackwardSlicing', BackwardSlicing)