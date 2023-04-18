from typing import Dict, Union
import logging
import traceback

from angr.knowledge_plugins.plugin import KnowledgeBasePlugin
from angr.knowledge_base.knowledge_base import KnowledgeBase
from angr.analyses.decompiler.clinic import Clinic
from angr.knowledge_plugins.functions.function import Function
from angr.analyses.decompiler.optimization_passes import get_default_optimization_passes
from angr.analyses.decompiler.optimization_passes.eager_returns import EagerReturnsSimplifier

l = logging.getLogger(__name__)


class ClinicManager(KnowledgeBasePlugin):
    _cached: Dict[int, Clinic]

    def __init__(self, kb: KnowledgeBase) -> None:
        self._kb = kb
        self._proj = kb._project
        self._cfg = kb.cfgs.get_most_accurate()
        self._cached = {}

    def get_clinic(self, func: Union[int, Function]) -> Clinic:
        """
        Get Clinic instance from cache. If cache the required Clinic does not exists in cache, create one and cache it.

        :param func: Function's address or Function instance.
        """
        optimization_passes = get_default_optimization_passes(self._proj.arch, 
                                                              self._proj.simos.name)
        # We should avoid duplicate return blocks.
        # If this optimization is enabled, some blocks with the same addresses may have different 
        # AIL instructions.
        # See: https://github.com/angr/angr/issues/3784
        if EagerReturnsSimplifier in optimization_passes:
            optimization_passes.remove(EagerReturnsSimplifier)
        if isinstance(func, int):
            func = self._kb.functions[func]
        if func.addr in self._cached:
            return self._cached[func.addr]
        try:
            clinic = self._proj.analyses.Clinic(
                func, 
                cfg=self._kb.cfgs.get_most_accurate(),
                optimization_passes=optimization_passes
            )
        except Exception as e:
            l.warning(f"Failed to build AIL graph for {func.name} (1/2)")
            l.warning(''.join(traceback.format_exception(type(e), e, e.__traceback__)))
            try:
                clinic = self._proj.analyses.Clinic(func,
                                                    optimization_passes=optimization_passes)
            except Exception as e:
                l.warning(f"Failed to build AIL graph for {func.name} (2/2)")
                l.warning(''.join(traceback.format_exception(type(e), e, e.__traceback__)))
                return None
        self._cached[func.addr] = clinic
        return clinic


KnowledgeBasePlugin.register_default("clinic_manager", ClinicManager)
