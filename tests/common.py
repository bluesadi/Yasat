import os

from Yasat import Binary
from Yasat.analyses.backward_slicing.criteria_selector import ArgumentSelector

def run_backward_slicing_on_binary(path, cast_to=int):
    assert os.path.isfile(path)
    assert cast_to in [int, str]
    binary = Binary.new(path)
    main_addr = binary.resolve_local_function('main')
    main = binary.proj.kb.functions[main_addr]
    sink_addr = binary.resolve_local_function('sink')
    bs = binary.proj.analyses.BackwardSlicing(target_func=main,
                                              criteria_selectors=[ArgumentSelector(sink_addr, 0)])
    if cast_to == str:
        return [result.string_value for result in bs.concrete_results]
    return [result.int_value for result in bs.concrete_results]