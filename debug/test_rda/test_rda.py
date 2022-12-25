import angr
import angr.analyses.reaching_definitions.dep_graph as dep_graph
import claripy

proj = angr.Project('test_rda_arm', load_options={'auto_load_libs': False})
cfg = proj.analyses.CFGFast(resolve_indirect_jumps=True, 
                        cross_references=True, 
                        force_complete_scan=False, 
                        normalize=True, 
                        symbols=True)
target_func = cfg.kb.functions[0x400642 + 1]

point = ("insn", 0x400672 + 1, 0)

rd = proj.analyses.ReachingDefinitions(subject=target_func, 
                                       func_graph=target_func.graph,
                                       cc=target_func.calling_convention,
                                       observe_all=True,
                                       dep_graph=dep_graph.DepGraph())

solver = claripy.Solver()
r0_offset = proj.arch.registers.get('r0', None)[0]
reg_defs = rd.observed_results[point].register_definitions
bv = reg_defs.load(r0_offset, size=proj.arch.bytes)
print(list(bv.values()))