from .rule_checker import ReturnValuesChecker


class UnsafeEVPAlogirthmsChecker(ReturnValuesChecker):
    def __init__(self, criteria):
        super().__init__(criteria, arg_name="type", filter=lambda value : value.name in [
            "EVP_aes_128_ecb", "EVP_aes_192_ecb", "EVP_aes_256_ecb", "EVP_des_ecb", "EVP_des_cbc", 
            "EVP_des_ecb", "EVP_des_cfb", "EVP_des_cfb1", "EVP_des_cfb8", "EVP_des_cfb64", 
            "EVP_des_ofb", "EVP_des_ede", "EVP_des_ede_cbc", "EVP_des_ede_cfb", "EVP_des_ede_cfb64", 
            "EVP_des_ede_ecb", "EVP_des_ede_ofb", "EVP_des_ede3", "EVP_des_ede3_cbc", 
            "EVP_des_ede3_cfb", "EVP_des_ede3_cfb1", "EVP_des_ede3_cfb8", "EVP_des_ede3_cfb64", 
            "EVP_des_ede3_ecb", "EVP_des_ede3_ofb", "EVP_des_ede3_wrap", "EVP_md5", "EVP_md2", 
            "EVP_md4", "EVP_sha1"
        ])


from angr import AnalysesHub

AnalysesHub.register_default("UnsafeEVPAlogirthmsChecker", UnsafeEVPAlogirthmsChecker)