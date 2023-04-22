from .rule_checker import ConstantIntegersChecker


class RSAKeySizesChecker(ConstantIntegersChecker):
    def __init__(self, criteria):
        super().__init__(criteria, arg_name="bits", filter=lambda value : value < 2048)


from angr import AnalysesHub

AnalysesHub.register_default("RSAKeySizesChecker", RSAKeySizesChecker)
