from ..analyses.rule_checker import ConstantStringsChecker


class ConstantKeysChecker(ConstantStringsChecker):
    def __init__(self, desc, criteria):
        super().__init__("ConstantKeysChecker", desc, criteria, arg_name="key")


from angr import AnalysesHub

AnalysesHub.register_default("ConstantKeysChecker", ConstantKeysChecker)
