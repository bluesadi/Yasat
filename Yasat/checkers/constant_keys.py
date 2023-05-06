from .rule_checker import ConstantStringsChecker


class ConstantKeysChecker(ConstantStringsChecker):
    def __init__(self, criteria):
        super().__init__(criteria, arg_name="key", filter=lambda value: len(value) > 0)


from angr import AnalysesHub

AnalysesHub.register_default("ConstantKeysChecker", ConstantKeysChecker)
