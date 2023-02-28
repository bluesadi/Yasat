from collections import defaultdict
from typing import Dict, List
import logging


class MisuseReport:
    binary_path: str
    rule_desc: str
    misuse_desc: str
    stmts: List[str]

    def __init__(self, binary_path, rule_desc, misuse_desc, stmts):
        self.binary_path = binary_path
        self.rule_desc = rule_desc
        self.misuse_desc = misuse_desc
        self.stmts = stmts

    def __repr__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        repr = (
            f"[-] Binary path: {self.binary_path}\n"
            f"[-] Rule descrption: {self.rule_desc}\n"
            f"[-] Misuse description: {self.misuse_desc}\n"
            f"[-] Statements:"
        )
        for stmt in self.stmts:
            repr += f"\n{stmt}"
        return repr


class OverallReport:
    _input_path: str
    _misuse_reports: Dict[str, List[MisuseReport]]
    finished: bool

    def __init__(self, input_path):
        self._input_path = input_path
        self._misuse_reports = defaultdict(list)
        self._time_costs = []
        self.finished = False

    def __repr__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        report = "*** Summary ***\n" f"Input path: {self._input_path}\n"
        for i, desc_cost in enumerate(self._time_costs):
            report += f"Stage {i + 1} ({desc_cost[0]}) time cost: {desc_cost[1]:.1f} seconds\n"
        report += (
            f"Total time cost: {sum(map(lambda ele : ele[1], self._time_costs)):.1f} seconds"
            "\n\n"
            "*** Misuses Found (Grouped by Checkers) ***\n"
        )
        for checker_id in self._misuse_reports:
            report += f"# {checker_id}\n"
            for i, misuse_report in enumerate(self._misuse_reports[checker_id]):
                report += f"## Misuse {i + 1}/{len(self._misuse_reports[checker_id])}\n"
                report += f"{misuse_report}\n\n"
        return report

    def report_time_cost(self, stage_desc, time_cost):
        self._time_costs.append((stage_desc, time_cost))
        return time_cost

    def report_misuses(self, checker_name: str, misuse_reports: List[MisuseReport]):
        self._misuse_reports[checker_name] += misuse_reports

    @property
    def num_misuses(self):
        return sum(len(self._misuse_reports[checker_name]) for checker_name in self._misuse_reports)

    def save(self, path):
        with open(path, "w") as fd:
            fd.write(self.__str__())
            fd.flush()

    def merge(self, another: "OverallReport"):
        report = OverallReport(self._input_path)
        misuse_reports = self._misuse_reports.copy()
        for key in another._misuse_reports:
            misuse_reports[key] += another._misuse_reports[key]
        report._misuse_reports = misuse_reports
        return report
