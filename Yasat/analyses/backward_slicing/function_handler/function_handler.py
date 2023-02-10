from typing import Tuple, List

from angr.knowledge_plugins.functions.function import Function

from ..multi_values import MultiValues


class FunctionHandler:
    def __init__(self):
        super().__init__()
        self.analysis = None

    def hook(self, anaylsis):
        self.analysis = anaylsis

    def handle(self, func: Function, args: List[MultiValues]) -> MultiValues:
        proj = func.project
        is_extern = False
        if proj.loader.main_object.contains_addr(func.addr):
            is_extern = proj.loader.find_plt_stub_name(func.addr) is not None
        else:
            symbol = proj.loader.find_symbol(func.addr)
            is_extern = symbol is not None and symbol.is_extern
        if is_extern:
            return self.handle_extern_function(func, args)
        else:
            return self.handle_local_function(func, args)

    def handle_local_function(
        self, func: Function, args: List[Tuple[MultiValues, MultiValues]]
    ) -> MultiValues:
        return None

    def handle_extern_function(
        self, func: Function, args: List[Tuple[MultiValues, MultiValues]]
    ) -> MultiValues:
        return None
