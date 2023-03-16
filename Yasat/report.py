from collections import defaultdict
from typing import Dict, List, Tuple


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
    _time_cost: int
    finished: bool

    def __init__(self, input_path):
        self._input_path = input_path
        self._misuse_reports = defaultdict(list)
        self._time_cost = 0
        self.finished = False

    def __repr__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        report = (
            "*** Summary ***\n"
            f"Input path: {self._input_path}\n"
            f"Total time cost: {self._time_cost} seconds\n"
            "\n"
            "*** Misuses Found (Grouped by Checkers) ***\n"
        )
        for checker_name in self._misuse_reports:
            report += f"# {checker_name}\n"
            for i, misuse_report in enumerate(self._misuse_reports[checker_name]):
                report += f"## Misuse {i + 1}/{len(self._misuse_reports[checker_name])}\n"
                report += f"{misuse_report}\n\n"
        return report

    def report_time_cost(self, time_cost):
        self._time_cost = int(time_cost)

    def report_misuses(self, checker_name: str, misuse_reports: List[MisuseReport]):
        self._misuse_reports[checker_name] += misuse_reports

    @property
    def num_misuses(self):
        return sum(len(self._misuse_reports[checker_name]) for checker_name in self._misuse_reports)

    """
    Save this report to `path`
    
    :param path:    Self explanatory.
    """
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
