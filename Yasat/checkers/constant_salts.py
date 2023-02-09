from .base import ConstantStringsChecker


class ConstantSaltsChecker(ConstantStringsChecker):
    def __init__(self, desc, criteria):
        super().__init__("ConstantSaltsChecker", desc, criteria, arg_name="salt")


from angr import AnalysesHub

AnalysesHub.register_default("ConstantSaltsChecker", ConstantSaltsChecker)
