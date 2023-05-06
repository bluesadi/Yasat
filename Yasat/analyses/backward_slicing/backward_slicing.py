from typing import Dict, Set, List, Tuple
from collections import defaultdict
import logging

from networkx import DiGraph
from angr.analyses.analysis import Analysis
from angr.analyses.decompiler.clinic import Clinic
from ailment import Block
from ailment.statement import ConditionalJump
from ailment.expression import Const
from angr.knowledge_plugins.functions import Function
from angr.sim_variable import SimVariable

from .slicing_state import SlicingState, SlicingTrack
from .engine_ail import SimEngineBackwardSlicing
from .criteria_selector import CriteriaSelector, ConditionSelector
from .function_handler import InterproceduralFunctionHandler, FunctionHandler
from ..multi_values import MultiValues

l = logging.getLogger(__name__)


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
    concrete_results: List[SlicingTrack]

    _max_iterations: int
    _max_call_depth: int
    _entry_block: Block
    _should_abort: bool
    _blocks_by_addr: Dict[int, Block]
    _output_states_by_addr: Dict[int, SlicingState]
    _engine: SimEngineBackwardSlicing
    _node_iterations: Dict[int, int]

    def __init__(
        self,
        target_func,
        criteria_selectors,
        preset_arguments: List[MultiValues] = [],
        function_handler=InterproceduralFunctionHandler(),
        max_iterations=5,
        max_call_depth=2,
        remove_unreachable_blocks=True,
        call_stack=None,
    ) -> None:
        super().__init__()

        if call_stack is None:
            call_stack = [target_func.addr]

        self.target_func = target_func
        self.criteria_selectors = criteria_selectors
        self.preset_arguments = preset_arguments
        self.function_handler = function_handler
        self.concrete_results = []

        self._max_iterations = max_iterations
        self._max_call_depth = max_call_depth
        self._call_stack = call_stack
        self._node_iterations = defaultdict(int)
        self._sim_state = self.project.factory.entry_state()
        self._engine = SimEngineBackwardSlicing(self)
        self._blocks_by_addr = dict()
        self._output_states_by_addr = dict()

        if criteria_selectors is None or len(criteria_selectors) == 0:
            raise ValueError("You should set up at least 1 criteria selector.")

        # Bind to slicing citeria selectors
        for selector in criteria_selectors:
            selector.hook(self)

        # Bind to function handler
        if function_handler is not None:
            function_handler.hook(self)

        # Get CFG
        cfg = self.project.kb.cfgs.get_most_accurate()
        if cfg is None:
            cfg = self.project.analyses.CFGFast(
                resolve_indirect_jumps=True, force_complete_scan=False, normalize=True
            )

        # That's for recovering prototypes of callees in this function, in order to achieve a higher
        # accuracy
        # Sometimes Clinic analysis cannot correctly deduce callees' stack arguments
        # for addr in self.project.kb.callgraph[target_func.addr]:
        #     if addr in self.project.kb.functions:
        #         called_func = self.project.kb.functions[addr]
        #         if self.kb.subject.is_local_function(called_func):
        #             if not called_func.normalized:
        #                 called_func.normalize()
        #             self.project.kb.clinic_manager.get_clinic(called_func)
        #     else:
        #         l.warning(f'Cannot find function at {hex(addr)}')

        # Generate AIL CFG for target function
        clinic: Clinic = self.project.kb.clinic_manager.get_clinic(target_func)
        if clinic is not None:
            self.preset_arguments = (
                list(zip(clinic.arg_list, preset_arguments)) if clinic.arg_list else []
            )

            self.graph = clinic.graph.copy()

            # Initialize address-block mappings and output states
            for block in self.graph:
                self._blocks_by_addr[block.addr] = block
                self._output_states_by_addr[block.addr] = self._initial_state(block)

            # Sometimes a called function with preset arguments may contain some unreachable
            # branches.
            # We remove them to make analysis more precise and efficient.
            if remove_unreachable_blocks and preset_arguments:
                # self._remove_unreachable_blocks()
                pass

            self._analyze()

    def _remove_unreachable_blocks(self):
        graph = self.graph.copy()
        preset_arguments = [mv for _, mv in self.preset_arguments]
        bs = self.project.analyses.BackwardSlicing(
            target_func=self.target_func,
            criteria_selectors=[ConditionSelector()],
            function_handler=None,
            max_iterations=1,
            preset_arguments=preset_arguments,
            remove_unreachable_blocks=False,
        )
        constant_conds = {}
        for result in bs.concrete_results:
            constant_conds[result.slice[-1].ins_addr] = result.bool_value
        entry_block = None
        for block in graph:
            if graph.in_degree(block) == 0:
                entry_block = block
                break
        queue = [entry_block]
        reachable_blocks = set()
        while queue:
            block = queue.pop(0)
            if block.addr in reachable_blocks:
                continue
            reachable_blocks.add(block.addr)
            stmt = block.statements[-1]
            if isinstance(stmt, ConditionalJump):
                if stmt.ins_addr in constant_conds:
                    cond_v = constant_conds[stmt.ins_addr]
                    if cond_v and isinstance(stmt.true_target, Const):
                        succ = self._blocks_by_addr[stmt.true_target.value]
                        queue.append(succ)
                    elif not cond_v and isinstance(stmt.false_target, Const):
                        succ = self._blocks_by_addr[stmt.false_target.value]
                        queue.append(succ)
            else:
                queue += list(graph.successors(block))
        for block in graph:
            if block.addr not in reachable_blocks:
                self.graph.remove_node(block)
                if block.addr in self._blocks_by_addr:
                    del self._blocks_by_addr[block.addr]

    def _initial_state(self, block: Block):
        return SlicingState(analysis=self, block=block)

    def _meet_successors(self, block: Block):
        output_states_of_succs = [
            self._output_states_by_addr[succ.addr] for succ in self.graph.successors(block)
        ]
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
        boundary_state = None
        while working_queue:
            block = self._blocks_by_addr[working_queue.pop(0)]
            pending_queue.discard(block.addr)
            # Current block's out-state (input state) is merged from the sucessors' in-states (output states).
            state = self._meet_successors(block)

            # We set a limitation of iterations to avoid stucking in infinite loop
            self._node_iterations[block.addr] += 1

            if block.addr == self.target_func.addr:
                boundary_state = state
            if self._node_iterations[block.addr] > self._max_iterations:
                continue

            state = self._run_on_node(state)
            if block.addr == self.target_func.addr:
                boundary_state = state

            old_state = self._output_states_by_addr[block.addr]
            # Update output state
            self._output_states_by_addr[block.addr] = state

            if (
                old_state.num_tracks != state.num_tracks
                or old_state.num_concrete_tracks != state.num_concrete_tracks
            ):
                # Since we only add new track to state.tracks or move track from state.tracks to state.concrete_tracks,
                # if state has changed, either state.tracks or state.concrete_tracks must have changed as well.
                # When state has changed, revisit all it's predecessors.

                revisit_iter = filter(
                    lambda pred: pred.addr not in pending_queue,
                    self.graph.predecessors(block),
                )
                working_queue += list(block.addr for block in revisit_iter)
                pending_queue |= set(block.addr for block in revisit_iter)

        # Collect concrete results from the boundary state
        self.concrete_results = sorted(
            boundary_state.concrete_results, key=lambda track: track.slice[0].ins_addr
        )

    def _run_on_node(self, state: SlicingState) -> SlicingState:
        return self._engine.process(state.copy(), block=state.block)


from angr import AnalysesHub

AnalysesHub.register_default("BackwardSlicing", BackwardSlicing)
