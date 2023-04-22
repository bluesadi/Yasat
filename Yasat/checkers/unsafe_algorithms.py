from .rule_checker import FunctionCallsChecker


class UnsafeAlgorithmsChecker(FunctionCallsChecker):
    def __init__(self, criteria):
        super().__init__(criteria)


from angr import AnalysesHub

AnalysesHub.register_default("UnsafeAlgorithmsChecker", UnsafeAlgorithmsChecker)