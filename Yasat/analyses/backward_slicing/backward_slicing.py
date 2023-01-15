from typing import Dict, Set, Tuple
from collections import defaultdict

from networkx import DiGraph
from angr.analyses.analysis import Analysis
from angr.analyses.decompiler.clinic import Clinic
from ailment import Block

from .slicing_state import SlicingState, SlicingTrack
from .engine_ail import SimEngineBackwardSlicing

class SlicingCriterion:
    
    def __init__(self, caller_addr: int, arg_idx: int):
        self.caller_addr = caller_addr
        self.arg_idx = arg_idx
        

class BackwardSlicing(Analysis):
    
    slicing_criterion: SlicingCriterion
    graph: DiGraph
    concrete_results: Set[SlicingTrack]
    
    _max_iterations: int
    _entry_block: Block
    _should_abort: bool
    _blocks_by_addr: Dict[int, Block]
    _output_states_by_addr: Dict[int, SlicingState]
    _engine: SimEngineBackwardSlicing
    _handled_slicing_criterion: bool
    _node_iterations: Dict[int, int]
    
    def __init__(self, 
                 slicing_criterion,
                 max_iterations=5) -> None:
        super().__init__()
        self.slicing_criterion = slicing_criterion
        self._max_iterations = max_iterations
        
        # Get or generate CFG
        cfg = self.project.kb.cfgs.get_most_accurate()
        if cfg is None:
            cfg = self.project.analyses.CFGFast(resolve_indirect_jumps=True, 
                                                force_complete_scan=False, 
                                                normalize=True)
        
        # Find the target function
        target_func = self.project.kb.functions.floor_func(slicing_criterion.caller_addr)
        if target_func is None:
            raise ValueError(f'Cannot find the corresponding function that contains address ' \
                             f'{hex(slicing_criterion.caller_addr)}.')
        
        # Generate the AIL CFG for the target function
        clinic: Clinic = self.project.analyses.Clinic(target_func)
        self.graph = clinic.graph.copy()
        
        self._blocks_by_addr = dict()
        self._output_states_by_addr = dict()
        
        # Find the entry block
        for block in self.graph:
            for stmt in block.statements:
                if stmt.ins_addr == slicing_criterion.caller_addr:
                    self._entry_block = block
            
        if self._entry_block is None:
            raise ValueError(f'Cannot find caller statement at address {hex(slicing_criterion.caller_addr)}.')
        
        # Remove all blocks that are unreachable from the entry block.
        # Because we don't want to waste time on those unrelated blocks.
        reachable_blocks = set()
        queue = {self._entry_block}
        while queue:
            block = queue.pop()
            if block in reachable_blocks:
                continue
            reachable_blocks.add(block)
            queue |= set(self.graph.predecessors(block))
        unreachable_blocks = set(self.graph.nodes) - reachable_blocks
        for unreachable_block in unreachable_blocks:
            self.graph.remove_node(unreachable_block)
        
        # Initialize address-block mappings and output states
        for block in self.graph:
            self._blocks_by_addr[block.addr] = block
            self._output_states_by_addr[block.addr] = self._initial_state(block)
        
        self._engine = SimEngineBackwardSlicing(self)
        self._handled_slicing_criterion = False
        self._node_iterations = defaultdict(int)
        self.concrete_results = set()
        
        self._analyze()
        
    def _initial_state(self, block: Block):
        return SlicingState(analysis=self,
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
        working_queue = [self._entry_block.addr]
        pending_queue = {self._entry_block.addr}
        last_states = {}
        
        while working_queue:
            block = self._blocks_by_addr[working_queue.pop(0)]
            pending_queue.discard(block.addr)
            # Current block's out-state (input state) is merged from the sucessors' in-states (output states).
            state = self.meet_successors(block)
            
            # We set a limitation of iterations to avoid stucking in infinite loop
            self._node_iterations[block.addr] += 1
            
            last_states[block.addr] = state
            if self._node_iterations[block.addr] > self._max_iterations:
                continue
            
            if block.addr != self._entry_block.addr and state.num_tracks == 0:
                continue
            
            state = self._run_on_node(state)
            last_states[block.addr] = state
            
            old_state = self._output_states_by_addr[block.addr]
            # Update output state
            self._output_states_by_addr[block.addr] = state
            
            # Update results when new concrete tracks are found
            
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