from collections import defaultdict
import os
from typing import Dict, List

class MisuseReport:
    
    binary_path: str
    rule_desc: str
    misuse_desc: str
    
    def __init__(self, binary_path, rule_desc, misuse_desc):
        self.binary_path = binary_path
        self.rule_desc = rule_desc
        self.misuse_desc = misuse_desc
        
    def __repr__(self) -> str:
        return self.__str__()
    
    def __str__(self) -> str:
        return f'[-] Binary path: {self.binary_path}\n'\
            f'[-] Rule descrption: {self.rule_desc}\n'\
            f'[-] Misuse description: {self.misuse_desc}'
    
class OverallReport:
    
    _firmware_path: str
    _misuse_reports: Dict[str, List[MisuseReport]]
    
    def __init__(self, firmware_path):
        self._firmware_path = firmware_path
        self._misuse_reports = defaultdict(list)
        
    def __repr__(self) -> str:
        return self.__str__()    
        
    def __str__(self) -> str:
        report = '*** Summary ***\n'\
            f'Firmware path: {self._firmware_path}\n'\
            '\n'\
            '*** Misuses Found (Grouped by Checkers) ***\n'
        for checker_id in self._misuse_reports:
            report += f'# {checker_id}\n'
            for i, misuse_report in enumerate(self._misuse_reports[checker_id]):
                report += f'## Misuse {i + 1}/{len(self._misuse_reports[checker_id])}\n'
                report += f'{misuse_report}\n\n'
        return report
    
    def report_misuses(self, checker_name: str, misuse_reports: List[MisuseReport]):
        self._misuse_reports[checker_name] += misuse_reports
        
    def save(self, path):
        with open(path, 'w+') as fd:
            fd.write(self.__str__())