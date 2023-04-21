import os

import angr
from Yasat.knowledge_plugins import Subject
from Yasat.analyses.backward_slicing.criteria_selector import ArgumentSelector


def run_backward_slicing_on_binary(path, sink_func="sink", arg_idx=0, cast_to=int):
    assert os.path.isfile(path)
    assert cast_to in [int, str]
    subject: Subject = angr.Project(path, load_options={"auto_load_libs": False}).kb.subject
    subject.cfg
    main_addr = subject.resolve_local_function("main")
    main = subject._proj.kb.functions[main_addr]
    sink_addr = subject.resolve_local_function(sink_func)
    bs = subject._proj.analyses.BackwardSlicing(
        target_func=main, criteria_selectors=[ArgumentSelector(sink_addr, arg_idx)]
    )
    if cast_to == str:
        return [result.string_value for result in bs.concrete_results]
    return [result.int_value for result in bs.concrete_results]
