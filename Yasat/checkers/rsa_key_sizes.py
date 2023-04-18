from ..analyses.rule_checker import ConstantIntegersChecker


class RSAKeySizesChecker(ConstantIntegersChecker):
    def __init__(self, criteria):
        super().__init__(criteria, arg_name="bits", filter=lambda value : value < 1024)


from angr import AnalysesHub

AnalysesHub.register_default("RSAKeySizesChecker", RSAKeySizesChecker)
