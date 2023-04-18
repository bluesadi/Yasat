from ..analyses.rule_checker import ConstantIntegersChecker


class PBEIterationsChecker(ConstantIntegersChecker):
    def __init__(self, criteria):
        super().__init__(criteria, arg_name="iterations", filter=lambda value : value < 1000)


from angr import AnalysesHub

AnalysesHub.register_default("PBEIterationsChecker", PBEIterationsChecker)
