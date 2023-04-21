from ..analyses.rule_checker import ReturnValuesChecker


class ECBEncryptionChecker(ReturnValuesChecker):
    def __init__(self, criteria):
        super().__init__(criteria, arg_name="type", filter=lambda value : value.name in [
            "EVP_aes_128_ecb", "EVP_aes_192_ecb", "EVP_aes_256_ecb"
        ])


from angr import AnalysesHub

AnalysesHub.register_default("ECBEncryptionChecker", ECBEncryptionChecker)