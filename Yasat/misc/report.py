from collections import defaultdict
from typing import Dict, List

class Misuse:
    filename: str
    desc: str
    stmts: List[str]

    def __init__(self, filename, desc, stmts=[]):
        self.filename = filename
        self.desc = desc
        self.stmts = stmts

    def __repr__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        repr = (
            f"[-] Filename: {self.filename}\n"
            f"[-] Description: {self.desc}\n"
            f"[-] Correctness: UN\n"
            f"[-] Statements:"
        )
        for stmt in self.stmts:
            repr += f"\n{stmt}"
        return repr

class Report:
    _misuses: Dict[str, List[Misuse]]
    time: int

    def __init__(self):
        self.time = 0
        self.extraction_success = 0
        self.extraction_failure = 0
        self.extraction_timeout = 0
        
        self.analysis_success = 0
        self.analysis_failure = 0
        self.analysis_timeout = 0
        
        self._width = 50
        self._misuses = defaultdict(list)

    @property
    def extraction_total(self):
        return self.extraction_success + self.extraction_failure + self.extraction_timeout

    @property
    def analysis_total(self):
        return self.analysis_success + self.analysis_failure + self.analysis_timeout

    def __repr__(self) -> str:
        return self.__str__()

    @property
    def summary(self):
        summary = (
            f"{'#' * self._width}\n"
            f"#{'Summary'.center(self._width - 2)}#\n"
            f"{'#' * self._width}\n"
            f"Time: {self.time} seconds\n"
        )
        if self.extraction_total != 0:
            summary += (
                f"Extraction success rate: "
                f"{int(self.extraction_success / self.extraction_total * 100)}% "
                f"({self.extraction_success} success, {self.extraction_failure} failure, "
                f"{self.extraction_timeout})\n"
            )
        if self.analysis_total != 0:
            summary += (
                f"Analysis success rate: "
                f"{int(self.analysis_success / self.analysis_total * 100)}% "
                f"({self.analysis_success} success, {self.analysis_failure} failure, "
                f"{self.analysis_timeout} timeout)\n"
            )
        summary += f"Misuses number: {self.num_misuses}\n"
        for checker in self._misuses:
            summary += f"- {checker}: {len(self._misuses[checker])}\n"
        return summary
    
    @property
    def details(self):
        details = (
            f"{'#' * self._width}\n"
            f"#{'Potential Misuses'.center(self._width - 2)}#\n"
            f"{'#' * self._width}\n"
        )
        for checker_name in self._misuses:
            details += f"*** {checker_name} ***\n"
            for i, misuse_report in enumerate(self._misuses[checker_name]):
                details += (
                    f"Misuses #{i + 1}\n"
                    f"{misuse_report}\n\n"
                )
        return details
    
    def __str__(self) -> str:
        return self.summary

    def report_misuses(self, checker_name: str, misuse_reports: List[Misuse]):
        self._misuses[checker_name].extend(misuse_reports)

    @property
    def num_misuses(self):
        return sum(len(self._misuses[checker_name]) for checker_name in self._misuses)

    def merge(self, another: "Report"):
        for key in another._misuses:
            self.report_misuses(key, another._misuses[key])
            
    def save(self, path):
        with open(path, "w") as fd:
            fd.write(self.summary + "\n" + self.details)