from typing import Dict, Set, Tuple
from collections import defaultdict

from networkx import DiGraph
from angr.analyses.analysis import Analysis
from ailment import Block

from .backward_slicing_state import BackwardSlicingState, SlicingTrack
from .engine_ail import SimEngineBackwardSlicing

class SlicingCriterion:
    
    def __init__(self, callsite_addr: int, arg_index: int):
        self.callsite_addr = callsite_addr
        self.arg_index = arg_index
        

class BackwardSlicing(Analysis):
    
    slicing_criterion: SlicingCriterion
    graph: DiGraph
    concrete_results: Set[SlicingTrack]
    
    _max_iterations: int
    _entry_block: Block
    _callsite_stmt_idx: int
    _should_abort: bool
    _blocks_by_addr: Dict[int, Block]
    _output_states_by_addr: Dict[int, BackwardSlicingState]
    _engine: SimEngineBackwardSlicing
    _handled_slicing_criterion: bool
    _node_iterations: Dict[int, int]
    
    def __init__(self, 
                 slicing_criterion,
                 max_iterations=3) -> None:
        super().__init__()
        self.slicing_criterion = slicing_criterion
        self._max_iterations = max_iterations
        
        cfg = self.project.kb.cfgs.get_most_accurate()
        if cfg is None:
            raise RuntimeError('CFG should be generated first before backward slicing')
        
        target_func = self.project.kb.functions.floor_func(slicing_criterion.callsite_addr)
        if target_func is None:
            raise ValueError(f'slicing_criterion.callsite_addr ({hex(slicing_criterion.callsite_addr)}) is not a valid address.')
        
        clinic = self.project.analyses.Clinic(target_func)
        self.graph = clinic.graph
        
        self._blocks_by_addr = dict()
        self._output_states_by_addr = dict()
        for block in self.graph:
            for stmt in block.statements:
                if stmt.ins_addr == slicing_criterion.callsite_addr:
                    self._entry_block = block
                    self._callsite_stmt_idx = stmt.idx
            self._blocks_by_addr[block.addr] = block
            self._output_states_by_addr[block.addr] = self._initial_state(block)
            
        if self._entry_block is None:
            raise ValueError(f'Can\'t find callsite at address {hex(slicing_criterion.callsite_addr)}.')
        
        self._engine = SimEngineBackwardSlicing(self)
        self._handled_slicing_criterion = False
        self._node_iterations = defaultdict(int)
        self.concrete_results = set()
        
        self._analyze()
        
    def _initial_state(self, block: Block):
        return BackwardSlicingState(analysis=self,
                                    block=block)
    
    def meet_successors(self, block: Block):
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
        all_blocks = list(self.graph.nodes)
        all_blocks.sort(key=lambda block: block.addr)
        working_queue = list(all_blocks)
        pending_queue = set(all_blocks)
        ended_states = []
        
        while working_queue:
            block = working_queue.pop()
            pending_queue.discard(block)
            # Current block's out-state (input state) is merged from the sucessors' in-states (output states)
            state = self.meet_successors(block)
            
            if state.ended:
                self._output_states_by_addr[block.addr] = state
                continue
            
            state, changed = self._run_on_node(state)
            
            self._output_states_by_addr[block.addr] = state
            if state.ended and state.has_concrete_results:
                ended_states.append(state)
                
            if state.changed:
                revisit_iter = filter(lambda pred : pred not in pending_queue, self.graph.predecessors(block))
                working_queue += list(revisit_iter)
                pending_queue |= set(revisit_iter)
                
        for ended_state in ended_states:
            self.concrete_results |= ended_state.concrete_results
            
    def _run_on_node(self, state: BackwardSlicingState) -> Tuple[BackwardSlicingState, bool]:
        state_copy = state.copy()
        state_copy.changed = False
        self._node_iterations[state_copy.addr] += 1
        if self._node_iterations <= self._max_iterations:
            return self._engine.process(state_copy, block = state.block)
        return state_copy, False
    
from angr import AnalysesHub
AnalysesHub.register_default('BackwardSlicing', BackwardSlicing)