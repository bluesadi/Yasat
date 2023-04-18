from ..analyses.rule_checker import ConstantStringsChecker


class ConstantSaltsChecker(ConstantStringsChecker):
    def __init__(self, criteria):
        super().__init__(criteria, arg_name="salt")


from angr import AnalysesHub

AnalysesHub.register_default("ConstantSaltsChecker", ConstantSaltsChecker)
