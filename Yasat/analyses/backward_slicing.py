from typing import Dict, Tuple

from networkx import DiGraph
from angr.analyses.analysis import Analysis
from angr.analyses.decompiler.clinic import Clinic
from ailment import Block
from ailment.statement import Call, Statement

from .backward_slicing_state import BackwardSlicingState
from .engine_ail import SimEngineBackwardSlicing

class SlicingCriterion:
    
    def __init__(self, callsite_addr: int, arg_index: int):
        self.callsite_addr = callsite_addr
        self.arg_index = arg_index

class BackwardSlicing(Analysis):
    
    slicing_criterion: SlicingCriterion
    graph: DiGraph
    
    _entry_block: Block
    _callsite_stmt_idx: int
    _should_abort: bool
    _blocks_by_addr: Dict[int, Block]
    _in_states_by_addr: Dict[int, BackwardSlicingState]
    _out_states_by_addr: Dict[int, BackwardSlicingState]
    _engine: SimEngineBackwardSlicing
    _handled_slicing_criterion: bool
    
    def __init__(self, slicing_criterion: SlicingCriterion) -> None:
        super().__init__()
        self.slicing_criterion = slicing_criterion
        cfg = self.project.kb.cfgs.get_most_accurate()
        if cfg is None:
            raise RuntimeError('CFG should be generated first before backward slicing')
        
        target_func = self.project.kb.functions.floor_func(slicing_criterion.callsite_addr)
        if target_func is None:
            raise ValueError(f'slicing_criterion.callsite_addr ({hex(slicing_criterion.callsite_addr)}) is not a valid address.')
        
        clinic = self.project.analyses.Clinic(target_func)
        self.graph = clinic.graph
        
        self._blocks_by_addr = dict()
        for block in self.graph:
            for stmt in block.statements:
                if stmt.ins_addr == slicing_criterion.callsite_addr:
                    self._entry_block = block
                    self._callsite_stmt_idx = stmt.idx
            self._blocks_by_addr[block.addr] = block
            self._in_states_by_addr[block.addr] = self._init_in_state(block)
            
        if self._entry_block is None:
            raise ValueError(f'Can\'t find callsite at address {hex(slicing_criterion.callsite_addr)}.')
        
        self._analyze()
        
    def _init_in_state(self, block: Block):
        return BackwardSlicingState(block=block
                                    )  
    
    def _init_out_state(self, block: Block):
        return BackwardSlicingState(block=block
                                    )
        
    def _analyze(self):
        working_queue = [self._entry_block]
        pending_queue = set()
        while working_queue:
            block = working_queue.pop()
            pending_queue.discard(block)
            in_states_of_succs = [self._out_states_by_addr[succ.addr] for succ in self.cfg.successors(block)]
            out_state = in_states_of_succs[0].merge(*in_states_of_succs[1:])
            in_state = self._run_on_node(out_state)
            # Have we reached fixed-point?
            if in_state != self._in_states_by_addr[block.addr]: 
                self._in_states_by_addr[block.addr] = in_state
                revisit_iter = filter(lambda pred : pred not in pending_queue, self.cfg.predecessors(block))
                working_queue += list(revisit_iter)
                pending_queue |= set(revisit_iter)
            
    def _run_on_node(self, state: BackwardSlicingState) -> BackwardSlicingState:
        return self._engine.process(state)