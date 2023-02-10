from typing import Dict, Union
import logging

from angr.knowledge_plugins.plugin import KnowledgeBasePlugin
from angr.knowledge_base.knowledge_base import KnowledgeBase
from angr.analyses.decompiler.clinic import Clinic
from angr.knowledge_plugins.functions.function import Function

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

        :param func:    Function's address or Function instance.
        """
        if isinstance(func, int):
            func = self._kb.functions[func]
        if func.addr in self._cached:
            return self._cached[func.addr]
        try:
            clinic = self._proj.analyses.Clinic(
                func, cfg=self._kb.cfgs.get_most_accurate()
            )
        except:
            clinic = self._proj.analyses.Clinic(func)
        self._cached[func.addr] = clinic
        return clinic


KnowledgeBasePlugin.register_default("clinic_manager", ClinicManager)
